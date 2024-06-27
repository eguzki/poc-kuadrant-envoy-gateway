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

const (
	kuadrantReferenceGrantName = "kuadrant-authorization-rg"
)

func (r *AuthPolicyReconciler) reconcileEnvoySecurityPolicies(ctx context.Context, ap *api.AuthPolicy, targetNetworkObject client.Object, gwDiffObj *reconcilers.GatewayDiffs) error {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return err
	}
	// Create EnvoySecurityPolicy for the authpolicy targetting the route or the gateway
	esp, err := r.envoySecurityPolicy(ctx, ap, targetNetworkObject, gwDiffObj)
	if err != nil {
		return err
	}
	if err := r.ReconcileResource(ctx, &egapi.SecurityPolicy{}, esp, alwaysUpdateEnvoySecurityPolicy); err != nil && !apierrors.IsAlreadyExists(err) {
		logger.Error(err, "failed to reconcile EnvoySecurityPolicy resource")
		return err
	}

	// Create ReferenceGrants for all security policies
	rg, err := r.securityPolicyReferenceGrant(ctx, ap)
	if err != nil {
		return err
	}
	if err := r.ReconcileResource(ctx, &gatewayapiv1beta1.ReferenceGrant{}, rg, alwaysUpdateAuthReferenceGrant); err != nil && !apierrors.IsAlreadyExists(err) {
		logger.Error(err, "failed to reconcile gatewayapi ReferenceGrant resource")
		return err
	}
	return nil
}

func (r *AuthPolicyReconciler) envoySecurityPolicy(ctx context.Context, ap *api.AuthPolicy, targetNetworkObject client.Object, gwDiffObj *reconcilers.GatewayDiffs) (*egapi.SecurityPolicy, error) {
	logger, _ := logr.FromContext(ctx)
	logger = logger.WithName("envoySecurityPolicy")

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
			Name:      fmt.Sprintf("on-%s", targetNetworkObject.GetName()),
			Namespace: targetNetworkObject.GetNamespace(),
			Labels:    envoySecurityPolicyLabels(client.ObjectKeyFromObject(ap), kuadrantNamespace),
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

	if ap.DeletionTimestamp != nil {
		logger.V(1).Info("auth policy marked for deletion, deleting envoy securitypolicy")
		utils.TagObjectToDelete(esp)
		return esp, nil
	}

	switch targetNetworkObject.(type) {
	case *gatewayapiv1.Gateway:
		// Check there is at least one httproute attached to the gateway
		routes := r.TargetRefReconciler.FetchAcceptedGatewayHTTPRoutes(ctx, ap.TargetKey())
		if len(routes) == 0 {
			logger.V(1).Info("no httproutes attached to the targeted gateway, skipping envoy securitypolicy for the gateway authpolicy")
			utils.TagObjectToDelete(esp)
			return esp, nil
		}
	case *gatewayapiv1.HTTPRoute:
		// Check whether all parent gateways are targetted by an AP, if so tag for deletion
		if allGatewaysTargetedByAP(gwDiffObj.GatewaysWithValidPolicyRef) {
			logger.V(1).Info("gateway for route has authpolicy, skipping envoy securitypolicy for the route authpolicy")
			utils.TagObjectToDelete(esp)
			return esp, nil
		}
	}
	return esp, nil
}

// Creates a reference grant permitting access to the authorino service from the security group namespace
// This is required for both xRoutes as well as Gateways, however this may not be required for gateways in future - see https://github.com/envoyproxy/gateway/issues/3450
func (r *AuthPolicyReconciler) securityPolicyReferenceGrant(ctx context.Context, ap *api.AuthPolicy) (*gatewayapiv1beta1.ReferenceGrant, error) {
	logger, _ := logr.FromContext(ctx)
	logger = logger.WithName("securityPolicyReferenceGrant")

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

	rg := &gatewayapiv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kuadrantReferenceGrantName,
			Namespace: kuadrantNamespace,
		},
		Spec: gatewayapiv1beta1.ReferenceGrantSpec{
			To: []gatewayapiv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Service",
					Name:  ptr.To(gatewayapiv1.ObjectName("authorino-authorino-authorization")),
				},
			},
		},
	}

	espNamespaces := make(map[string]struct{})
	listOptions := &client.ListOptions{LabelSelector: labels.SelectorFromSet(map[string]string{kuadrant.KuadrantNamespaceAnnotation: kuadrantNamespace})}
	espList := &egapi.SecurityPolicyList{}
	if err := r.Client().List(ctx, espList, listOptions); err != nil {
		return nil, err
	}

	for _, esp := range espList.Items {
		// only append namespaces that differ from the kuadrant namespace and are not marked for deletion
		// if the authpolicy is pending deletion for the namespace of the security policy then do not append
		if esp.DeletionTimestamp == nil && esp.Namespace != kuadrantNamespace && (ap.DeletionTimestamp == nil || ap.Namespace != esp.Namespace) {
			espNamespaces[esp.Namespace] = struct{}{}
		}
	}

	if len(espNamespaces) == 0 {
		logger.V(1).Info("no security policies exist outside of the kuadrant namespace, skipping ReferenceGrant")
		utils.TagObjectToDelete(rg)
		return rg, nil
	}

	refGrantFrom := []gatewayapiv1beta1.ReferenceGrantFrom{}
	for namespace := range espNamespaces {
		refGrantFrom = append(refGrantFrom, referenceGrantFromNamespace(gatewayapiv1.Namespace(namespace)))
	}
	rg.Spec.From = refGrantFrom

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

func alwaysUpdateAuthReferenceGrant(existingObj, desiredObj client.Object) (bool, error) {
	existing, ok := existingObj.(*gatewayapiv1beta1.ReferenceGrant)
	if !ok {
		return false, fmt.Errorf("%T is not an *gatewayapiv1beta1.ReferenceGrant", existingObj)
	}
	desired, ok := desiredObj.(*gatewayapiv1beta1.ReferenceGrant)
	if !ok {
		return false, fmt.Errorf("%T is not an *gatewayapiv1beta1.ReferenceGrant", desiredObj)
	}

	var update bool
	if !reflect.DeepEqual(existing.Spec.From, desired.Spec.From) {
		update = true
		existing.Spec.From = desired.Spec.From
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

func referenceGrantFromNamespace(namespace gatewayapiv1.Namespace) gatewayapiv1beta1.ReferenceGrantFrom {
	return gatewayapiv1beta1.ReferenceGrantFrom{
		Group:     egapi.GroupName,          // must be envoy-gateway group name
		Kind:      egapi.KindSecurityPolicy, // must be kind SecurityPolicy
		Namespace: namespace,
	}
}

func envoySecurityPolicyLabels(apKey client.ObjectKey, kuadrantNamespace string) map[string]string {
	return map[string]string{
		kuadrant.KuadrantNamespaceAnnotation:                            kuadrantNamespace,
		common.AuthPolicyBackRefAnnotation:                              apKey.Name,
		fmt.Sprintf("%s-namespace", common.AuthPolicyBackRefAnnotation): apKey.Namespace,
	}
}

func allGatewaysTargetedByAP(gateways []kuadrant.GatewayWrapper) bool {
	for _, gw := range gateways {
		gateway := gw
		if gateway.GetAnnotations()[common.AuthPolicyBackRefAnnotation] == "" {
			return false
		}
	}
	return true
}
