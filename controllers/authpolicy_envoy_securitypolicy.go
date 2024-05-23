package controllers

import (
	"context"
	"fmt"
	"reflect"

	egapi "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/go-logr/logr"
	api "github.com/kuadrant/kuadrant-operator/api/v1beta2"
	"github.com/kuadrant/kuadrant-operator/pkg/common"
	"github.com/kuadrant/kuadrant-operator/pkg/library/kuadrant"
	"github.com/kuadrant/kuadrant-operator/pkg/library/reconcilers"
	"github.com/kuadrant/kuadrant-operator/pkg/library/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayapiv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func (r *AuthPolicyReconciler) reconcileEnvoySecurityPolicies(ctx context.Context, ap *api.AuthPolicy, targetNetworkObject client.Object, gwDiffObj *reconcilers.GatewayDiffs) error {
	if err := r.deleteEnvoySecurityPolicies(ctx, ap, gwDiffObj); err != nil {
		return err
	}
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return err
	}
	// Create EnvoySecurityPolicy for each gateway directly or indirectly referred by the policy (existing and new)
	for _, gw := range append(gwDiffObj.GatewaysWithValidPolicyRef, gwDiffObj.GatewaysMissingPolicyRef...) {
		esp, err := r.envoySecurityPolicy(ctx, ap, targetNetworkObject, gw)
		if err != nil {
			return err
		}
		if err := r.ReconcileResource(ctx, &egapi.SecurityPolicy{}, esp, alwaysUpdateEnvoySecurityPolicy); err != nil && !apierrors.IsAlreadyExists(err) {
			logger.Error(err, "failed to reconcile EnvoySecurityPolicy resource")
			return err
		}
		rg, err := r.securityPolicyReferenceGrant(ctx, esp, ap, gw)
		if err != nil {
			return err
		}
		if err := r.ReconcileResource(ctx, &gatewayapiv1beta1.ReferenceGrant{}, rg, modifyAuthReferenceGrant); err != nil && !apierrors.IsAlreadyExists(err) {
			logger.Error(err, "failed to reconcile gatewayapi ReferenceGrant resource")
			return err
		}
	}
	return nil
}

// deleteEnvoySecurityPolicies deletes envoy SecurityPolicies and associated ReferenceGrants previously created for gateways no longer targeted by the policy (directly or indirectly)
func (r *AuthPolicyReconciler) deleteEnvoySecurityPolicies(ctx context.Context, ap *api.AuthPolicy, gwDiffObj *reconcilers.GatewayDiffs) error {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return err
	}
	for _, gw := range gwDiffObj.GatewaysWithInvalidPolicyRef {
		listOptions := &client.ListOptions{LabelSelector: labels.SelectorFromSet(istioAuthorizationPolicyLabels(client.ObjectKeyFromObject(gw.Gateway), client.ObjectKeyFromObject(ap)))}
		espList := &egapi.SecurityPolicyList{}
		if err := r.Client().List(ctx, espList, listOptions); err != nil {
			return err
		}
		for _, esp := range espList.Items {
			// it's OK to just go ahead and delete because we only create one ESP per target network object,
			// and a network object can be targeted by no more than one AuthPolicy
			espObj := &esp
			if err := r.DeleteResource(ctx, espObj); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to delete envoySecurityPolicy")
				return err
			}
		}
		rgList := &gatewayapiv1beta1.ReferenceGrantList{}
		if err := r.Client().List(ctx, rgList, listOptions); err != nil {
			return err
		}
		for _, rg := range rgList.Items {
			rgObj := &rg
			if err := r.DeleteResource(ctx, rgObj); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to delete envoySecurityPolicy")
				return err
			}
		}
	}
	return nil
}

func (r *AuthPolicyReconciler) envoySecurityPolicy(ctx context.Context, ap *api.AuthPolicy, targetNetworkObject client.Object, gw kuadrant.GatewayWrapper) (*egapi.SecurityPolicy, error) {
	logger, _ := logr.FromContext(ctx)
	logger = logger.WithName("envoySecurityPolicy")

	gateway := gw.Gateway

	var kuadrantNamespace string
	kuadrantNamespace, isSet := kuadrant.GetKuadrantNamespaceFromPolicy(ap)
	if !isSet {
		var err error
		kuadrantNamespace, err = kuadrant.GetKuadrantNamespaceFromPolicyTargetRef(ctx, r.Client(), ap)
		if err != nil {
			logger.Error(err, "failed to get kuadrant namespace")
			return nil, err
		}
	}

	esp := &egapi.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      istioAuthorizationPolicyName(gateway.Name, ap.GetTargetRef()),
			Namespace: targetNetworkObject.GetNamespace(),
			Labels:    istioAuthorizationPolicyLabels(client.ObjectKeyFromObject(gateway), client.ObjectKeyFromObject(ap)),
		},
		Spec: egapi.SecurityPolicySpec{
			TargetRef: gatewayapiv1alpha2.PolicyTargetReferenceWithSectionName{
				PolicyTargetReference: ap.GetTargetRef(),
				SectionName:           nil,
			},
			ExtAuth: &egapi.ExtAuth{
				GRPC: &egapi.GRPCExtAuthService{
					BackendRef: gatewayapiv1.BackendObjectReference{
						Name:      gatewayapiv1.ObjectName("authorino-authorino-authorization"),
						Namespace: ptr.To(gatewayapiv1.Namespace(kuadrantNamespace)),
						Port:      ptr.To(gatewayapiv1.PortNumber(50051)),
					},
				},
			},
		},
	}

	switch targetNetworkObject.(type) {
	case *gatewayapiv1.Gateway:
		// fake a single httproute with all rules from all httproutes accepted by the gateway,
		// that do not have an authpolicy of its own, so we can generate wasm rules for those cases
		rules := make([]gatewayapiv1.HTTPRouteRule, 0)
		routes := r.TargetRefReconciler.FetchAcceptedGatewayHTTPRoutes(ctx, ap.TargetKey())
		for idx := range routes {
			route := routes[idx]
			// skip routes that have an authpolicy of its own
			if route.GetAnnotations()[common.AuthPolicyBackRefAnnotation] != "" {
				continue
			}
			rules = append(rules, route.Spec.Rules...)
		}
		if len(rules) == 0 {
			logger.V(1).Info("no httproutes attached to the targeted gateway, skipping envoy securitypolicy for the gateway authpolicy")
			utils.TagObjectToDelete(esp)
			return esp, nil
		}
	case *gatewayapiv1.HTTPRoute:
		// Check that the gateway is not targetted by an AP, if so do not create
		if gateway.GetAnnotations()[common.AuthPolicyBackRefAnnotation] != "" {
			logger.V(1).Info("gateway for route has authpolicy, skipping envoy securitypolicy for the route authpolicy")
			utils.TagObjectToDelete(esp)
			return esp, nil
		}
	}
	return esp, nil
}

// Creates a reference grant permitting access to the authorino service from the security group namespace
// This is required for both xRoutes as well as Gateways, however this may not be required for gateways in future - see https://github.com/envoyproxy/gateway/issues/3450
func (r *AuthPolicyReconciler) securityPolicyReferenceGrant(ctx context.Context, esp *egapi.SecurityPolicy, ap *api.AuthPolicy, gw kuadrant.GatewayWrapper) (*gatewayapiv1beta1.ReferenceGrant, error) {
	logger, _ := logr.FromContext(ctx)
	logger = logger.WithName("securityPolicyReferenceGrant")

	gateway := gw.Gateway
	espTargetNamespace := string(*esp.Spec.ExtAuth.GRPC.BackendRef.Namespace)
	rg := &gatewayapiv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kuadrant-authorization-rg",
			Namespace: espTargetNamespace,
			Labels:    istioAuthorizationPolicyLabels(client.ObjectKeyFromObject(gateway), client.ObjectKeyFromObject(ap)),
		},
		Spec: gatewayapiv1beta1.ReferenceGrantSpec{
			From: []gatewayapiv1beta1.ReferenceGrantFrom{
				{
					Group:     egapi.GroupName,          // must be envoy-gateway group name
					Kind:      egapi.KindSecurityPolicy, // must be kind SecurityPolicy
					Namespace: gatewayapiv1.Namespace(esp.Namespace),
				},
			},
			To: []gatewayapiv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Service",
					Name:  ptr.To(esp.Spec.ExtAuth.GRPC.BackendRef.Name),
				},
			},
		},
	}
	if esp.Namespace == espTargetNamespace {
		logger.V(1).Info("security policy is in target namespace for authorino service, skipping ReferenceGrant")
		utils.TagObjectToDelete(rg)
		return rg, nil
	}
	return rg, nil
}

func alwaysUpdateEnvoySecurityPolicy(existingObj, desiredObj client.Object) (bool, error) {
	existing, ok := existingObj.(*egapi.SecurityPolicy)
	if !ok {
		return false, fmt.Errorf("%T is not an *egapi.SecurityPolicy", existingObj)
	}
	desired, ok := desiredObj.(*egapi.SecurityPolicy)
	if !ok {
		return false, fmt.Errorf("%T is not an *egapi.SecurityPolicy", desiredObj)
	}

	var update bool

	if !reflect.DeepEqual(existing.Spec.ExtAuth, desired.Spec.ExtAuth) {
		update = true
		existing.Spec.ExtAuth = desired.Spec.ExtAuth
	}

	if !reflect.DeepEqual(existing.Spec.TargetRef, desired.Spec.TargetRef) {
		update = true
		existing.Spec.TargetRef = desired.Spec.TargetRef
	}

	if !reflect.DeepEqual(existing.Annotations, desired.Annotations) {
		update = true
		existing.Annotations = desired.Annotations
	}

	return update, nil
}

func modifyAuthReferenceGrant(existingObj, desiredObj client.Object) (bool, error) {
	existing, ok := existingObj.(*gatewayapiv1beta1.ReferenceGrant)
	if !ok {
		return false, fmt.Errorf("%T is not an *gatewayapiv1beta1.ReferenceGrant", existingObj)
	}
	desired, ok := desiredObj.(*gatewayapiv1beta1.ReferenceGrant)
	if !ok {
		return false, fmt.Errorf("%T is not an *gatewayapiv1beta1.ReferenceGrant", desiredObj)
	}

	var update bool
	for _, from := range desired.Spec.From {
		if !containsReferenceGrantFrom(existing.Spec.From, from) {
			update = true
			existing.Spec.From = append(existing.Spec.From, from)
		}
	}

	if !reflect.DeepEqual(existing.Spec.To, desired.Spec.To) {
		update = true
		existing.Spec.To = desired.Spec.To
	}

	if !reflect.DeepEqual(existing.Annotations, desired.Annotations) {
		update = true
		existing.Annotations = desired.Annotations
	}

	return update, nil
}

func containsReferenceGrantFrom(existing []gatewayapiv1beta1.ReferenceGrantFrom, new gatewayapiv1beta1.ReferenceGrantFrom) bool {
	for _, from := range existing {
		if reflect.DeepEqual(from, new) {
			return true
		}
	}
	return false
}
