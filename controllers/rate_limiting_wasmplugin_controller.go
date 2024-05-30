/*
Copyright 2021 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"

	"github.com/go-logr/logr"
	istioextensionsv1alpha1 "istio.io/api/extensions/v1alpha1"
	istioclientgoextensionv1alpha1 "istio.io/client-go/pkg/apis/extensions/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/env"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	kuadrantv1beta2 "github.com/kuadrant/kuadrant-operator/api/v1beta2"
	kuadrantistioutils "github.com/kuadrant/kuadrant-operator/pkg/istio"
	"github.com/kuadrant/kuadrant-operator/pkg/library/mappers"
	"github.com/kuadrant/kuadrant-operator/pkg/library/reconcilers"
	"github.com/kuadrant/kuadrant-operator/pkg/library/utils"
	"github.com/kuadrant/kuadrant-operator/pkg/rlptools/wasm"
)

var (
	WASMFilterImageURL = env.GetString("RELATED_IMAGE_WASMSHIM", "oci://quay.io/kuadrant/wasm-shim:latest")
)

// RateLimitingWASMPluginReconciler reconciles a WASMPlugin object for rate limiting
type RateLimitingWASMPluginReconciler struct {
	*reconcilers.BaseReconciler
}

//+kubebuilder:rbac:groups=extensions.istio.io,resources=wasmplugins,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=kuadrant.io,resources=ratelimitpolicies,verbs=get;list;watch;update;patch

// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *RateLimitingWASMPluginReconciler) Reconcile(eventCtx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger().WithValues("Gateway", req.NamespacedName)
	logger.Info("Reconciling rate limiting WASMPlugin")
	ctx := logr.NewContext(eventCtx, logger)

	gw := &gatewayapiv1.Gateway{}
	if err := r.Client().Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("no gateway found")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get gateway")
		return ctrl.Result{}, err
	}

	if logger.V(1).Enabled() {
		jsonData, err := json.MarshalIndent(gw, "", "  ")
		if err != nil {
			return ctrl.Result{}, err
		}
		logger.V(1).Info(string(jsonData))
	}

	desired, err := r.desiredRateLimitingWASMPlugin(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.ReconcileResource(ctx, &istioclientgoextensionv1alpha1.WasmPlugin{}, desired, kuadrantistioutils.WASMPluginMutator)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Rate limiting WASMPlugin reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *RateLimitingWASMPluginReconciler) desiredRateLimitingWASMPlugin(ctx context.Context, gw *gatewayapiv1.Gateway) (*istioclientgoextensionv1alpha1.WasmPlugin, error) {
	baseLogger, err := logr.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	wasmPlugin := &istioclientgoextensionv1alpha1.WasmPlugin{
		TypeMeta: metav1.TypeMeta{
			Kind:       "WasmPlugin",
			APIVersion: "extensions.istio.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      kuadrantistioutils.WASMPluginName(gw),
			Namespace: gw.Namespace,
		},
		Spec: istioextensionsv1alpha1.WasmPlugin{
			Selector:     kuadrantistioutils.WorkloadSelectorFromGateway(ctx, r.Client(), gw),
			Url:          WASMFilterImageURL,
			PluginConfig: nil,
			// Insert plugin before Istio stats filters and after Istio authorization filters.
			Phase: istioextensionsv1alpha1.PluginPhase_STATS,
		},
	}

	logger := baseLogger.WithValues("wasmplugin", client.ObjectKeyFromObject(wasmPlugin))

	pluginConfig, err := wasm.ConfigFromGateway(ctx, r.Client(), gw)
	if err != nil {
		return nil, err
	}

	if pluginConfig == nil || len(pluginConfig.RateLimitPolicies) == 0 {
		logger.V(1).Info("pluginConfig is empty. Wasmplugin will be deleted if it exists")
		utils.TagObjectToDelete(wasmPlugin)
		return wasmPlugin, nil
	}

	pluginConfigStruct, err := kuadrantistioutils.WasmConfigToStruct(pluginConfig)
	if err != nil {
		return nil, err
	}

	wasmPlugin.Spec.PluginConfig = pluginConfigStruct

	// controller reference
	if err := r.SetOwnerReference(gw, wasmPlugin); err != nil {
		return nil, err
	}

	return wasmPlugin, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RateLimitingWASMPluginReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ok, err := kuadrantistioutils.IsIstioWASMPluginInstalled(mgr.GetRESTMapper())
	if err != nil {
		return err
	}
	if !ok {
		r.Logger().Info("Istio WasmPlugin controller disabled. Istio was not found")
		return nil
	}

	httpRouteToParentGatewaysEventMapper := mappers.NewHTTPRouteToParentGatewaysEventMapper(
		mappers.WithLogger(r.Logger().WithName("httpRouteToParentGatewaysEventMapper")),
	)

	rlpToParentGatewaysEventMapper := mappers.NewPolicyToParentGatewaysEventMapper(
		mappers.WithLogger(r.Logger().WithName("ratelimitpolicyToParentGatewaysEventMapper")),
		mappers.WithClient(r.Client()),
	)

	return ctrl.NewControllerManagedBy(mgr).
		// Rate limiting WASMPlugin controller only cares about
		// Gateway API Gateway
		// Gateway API HTTPRoutes
		// Kuadrant RateLimitPolicies

		// The type of object being *reconciled* is the Gateway.
		// TODO(eguzki): consider having the WasmPlugin as the type of object being *reconciled*
		For(&gatewayapiv1.Gateway{}).
		Owns(&istioclientgoextensionv1alpha1.WasmPlugin{}).
		Watches(
			&gatewayapiv1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(httpRouteToParentGatewaysEventMapper.Map),
		).
		Watches(
			&kuadrantv1beta2.RateLimitPolicy{},
			handler.EnqueueRequestsFromMapFunc(rlpToParentGatewaysEventMapper.Map),
		).
		Complete(r)
}
