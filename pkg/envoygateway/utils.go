package envoygateway

import (
	"encoding/json"
	"fmt"

	egv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kuadrant/kuadrant-operator/pkg/common"
)

func IsEnvoyGatewayEnvoyPatchPolicyInstalled(restMapper meta.RESTMapper) (bool, error) {
	_, err := restMapper.RESTMapping(
		schema.GroupKind{Group: egv1alpha1.GroupName, Kind: "EnvoyPatchPolicy"},
		egv1alpha1.GroupVersion.Version,
	)

	if err == nil {
		return true, nil
	}

	if meta.IsNoMatchError(err) {
		return false, nil
	}

	return false, err
}

func RateLimitEnvoyPatchPolicyName(gw *gatewayapiv1.Gateway) string {
	return fmt.Sprintf("kuadrant-%s", gw.Name)
}

func LimitadorClusterPatch(limitadorSvcHost string, limitadorGRPCPort int) egv1alpha1.EnvoyJSONPatchConfig {
	// The patch defines the rate_limit_cluster, which provides the endpoint location of the external rate limit service.
	// TODO(eguzki): Istio EnvoyFilter uses almost the same structure. DRY
	patchUnstructured := map[string]any{
		"name":                   common.KuadrantRateLimitClusterName,
		"type":                   "STRICT_DNS",
		"connect_timeout":        "1s",
		"lb_policy":              "ROUND_ROBIN",
		"http2_protocol_options": map[string]any{},
		"load_assignment": map[string]any{
			"cluster_name": common.KuadrantRateLimitClusterName,
			"endpoints": []map[string]any{
				{
					"lb_endpoints": []map[string]any{
						{
							"endpoint": map[string]any{
								"address": map[string]any{
									"socket_address": map[string]any{
										"address":    limitadorSvcHost,
										"port_value": limitadorGRPCPort,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	patchRaw, _ := json.Marshal(patchUnstructured)
	value := &apiextensionsv1.JSON{}
	value.UnmarshalJSON(patchRaw)

	return egv1alpha1.EnvoyJSONPatchConfig{
		Type: egv1alpha1.ClusterEnvoyResourceType,
		Name: common.KuadrantRateLimitClusterName,
		Operation: egv1alpha1.JSONPatchOperation{
			Op:    egv1alpha1.JSONPatchOperationType("add"),
			Path:  "",
			Value: value,
		},
	}
}

func WasmBinarySourceClusterPatch(host string, port int) egv1alpha1.EnvoyJSONPatchConfig {
	// The patch defines the Wasm binary source cluster,
	// TLS enabled
	patchUnstructured := map[string]any{
		"name":                   common.RateLimitWasmSourceClusterName,
		"type":                   "STRICT_DNS",
		"connect_timeout":        "1s",
		"dns_lookup_family":      "V4_ONLY",
		"lb_policy":              "ROUND_ROBIN",
		"http2_protocol_options": map[string]any{},
		"load_assignment": map[string]any{
			"cluster_name": common.RateLimitWasmSourceClusterName,
			"endpoints": []map[string]any{
				{
					"lb_endpoints": []map[string]any{
						{
							"endpoint": map[string]any{
								"address": map[string]any{
									"socket_address": map[string]any{
										"address":    host,
										"port_value": port,
									},
								},
							},
						},
					},
				},
			},
		},
		"transport_socket": map[string]any{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   host,
			},
		},
	}

	patchRaw, _ := json.Marshal(patchUnstructured)
	value := &apiextensionsv1.JSON{}
	value.UnmarshalJSON(patchRaw)

	return egv1alpha1.EnvoyJSONPatchConfig{
		Type: egv1alpha1.ClusterEnvoyResourceType,
		Name: common.RateLimitWasmSourceClusterName,
		Operation: egv1alpha1.JSONPatchOperation{
			Op:    egv1alpha1.JSONPatchOperationType("add"),
			Path:  "",
			Value: value,
		},
	}
}
