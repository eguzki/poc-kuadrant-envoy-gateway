package istio

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	_struct "google.golang.org/protobuf/types/known/structpb"
	istiocommon "istio.io/api/type/v1beta1"
	istioclientgoextensionv1alpha1 "istio.io/client-go/pkg/apis/extensions/v1alpha1"
	istioclientnetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	kuadrantgatewayapi "github.com/kuadrant/kuadrant-operator/pkg/library/gatewayapi"
	"github.com/kuadrant/kuadrant-operator/pkg/rlptools/wasm"
)

func WASMPluginName(gw *gatewayapiv1.Gateway) string {
	return fmt.Sprintf("kuadrant-%s", gw.Name)
}

func WorkloadSelectorFromGateway(ctx context.Context, k8sClient client.Client, gateway *gatewayapiv1.Gateway) *istiocommon.WorkloadSelector {
	logger, _ := logr.FromContext(ctx)
	gatewayWorkloadSelector, err := kuadrantgatewayapi.GetGatewayWorkloadSelector(ctx, k8sClient, gateway)
	if err != nil {
		logger.V(1).Info("failed to build Istio WorkloadSelector from Gateway service - falling back to Gateway labels")
		gatewayWorkloadSelector = gateway.Labels
	}
	return &istiocommon.WorkloadSelector{
		MatchLabels: gatewayWorkloadSelector,
	}
}

func IsIstioWASMPluginInstalled(restMapper meta.RESTMapper) (bool, error) {
	_, err := restMapper.RESTMapping(
		schema.GroupKind{Group: istioclientgoextensionv1alpha1.GroupName, Kind: "WasmPlugin"},
		istioclientgoextensionv1alpha1.SchemeGroupVersion.Version,
	)

	if err == nil {
		return true, nil
	}

	if meta.IsNoMatchError(err) {
		return false, nil
	}

	return false, err
}

func IsIstioEnvoyFilterInstalled(restMapper meta.RESTMapper) (bool, error) {
	_, err := restMapper.RESTMapping(
		schema.GroupKind{Group: istioclientnetworkingv1alpha3.GroupName, Kind: "EnvoyFilter"},
		istioclientnetworkingv1alpha3.SchemeGroupVersion.Version,
	)

	if err == nil {
		return true, nil
	}

	if meta.IsNoMatchError(err) {
		return false, nil
	}

	return false, err
}

func WasmConfigToStruct(c *wasm.Config) (*_struct.Struct, error) {
	configJSON, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	configStruct := &_struct.Struct{}
	if err := configStruct.UnmarshalJSON(configJSON); err != nil {
		return nil, err
	}
	return configStruct, nil
}
