package controllers

import (
	"context"
	"fmt"

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
		rg, err := r.gatewayReferenceGrant(ctx, esp, ap, gw)
		if err != nil {
			return err
		}
		if err := r.ReconcileResource(ctx, &egapi.SecurityPolicy{}, esp, alwaysUpdateEnvoySecurityPolicy); err != nil && !apierrors.IsAlreadyExists(err) {
			logger.Error(err, "failed to reconcile EnvoySecurityPolicy resource")
			return err
		}
		if err := r.ReconcileResource(ctx, &gatewayapiv1beta1.ReferenceGrant{}, rg, alwaysUpdateGatewayReferenceGrant); err != nil && !apierrors.IsAlreadyExists(err) {
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

	targetRef := gatewayapiv1alpha2.PolicyTargetReferenceWithSectionName{
		PolicyTargetReference: gatewayapiv1alpha2.PolicyTargetReference{
			Group: gatewayapiv1.GroupName,
			Kind:  gatewayapiv1.Kind("Gateway"),
			Name:  gatewayapiv1.ObjectName(gateway.Name),
		},
	}

	esp := &egapi.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      istioAuthorizationPolicyName(gateway.Name, ap.GetTargetRef()),
			Namespace: gateway.Namespace,
			Labels:    istioAuthorizationPolicyLabels(client.ObjectKeyFromObject(gateway), client.ObjectKeyFromObject(ap)),
		},
		Spec: egapi.SecurityPolicySpec{
			TargetRef: targetRef,
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
	}

	return esp, nil
}

func (r *AuthPolicyReconciler) gatewayReferenceGrant(ctx context.Context, esp *egapi.SecurityPolicy, ap *api.AuthPolicy, gw kuadrant.GatewayWrapper) (*gatewayapiv1beta1.ReferenceGrant, error) {
	logger, _ := logr.FromContext(ctx)
	logger = logger.WithName("gatewayReferenceGrant")

	gateway := gw.Gateway
	espTargetNamespace := string(*esp.Spec.ExtAuth.GRPC.BackendRef.Namespace)

	rg := &gatewayapiv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-rg", esp.Name),
			Namespace: espTargetNamespace,
			Labels:    istioAuthorizationPolicyLabels(client.ObjectKeyFromObject(gateway), client.ObjectKeyFromObject(ap)),
		},
		Spec: gatewayapiv1beta1.ReferenceGrantSpec{
			From: []gatewayapiv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayapiv1.GroupName,
					Kind:      "HTTPRoute", // must be HTTPRoute to be tracked by envoy-gateway
					Namespace: gatewayapiv1.Namespace(esp.Namespace),
				},
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

	if gateway.Namespace == espTargetNamespace {
		logger.V(1).Info("gateway is in target namespace for authorino service, skipping ReferenceGrant for the envoy SecurityPolicy")
		utils.TagObjectToDelete(rg)
		return rg, nil
	}

	return rg, nil
}
