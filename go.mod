module github.com/kuadrant/kuadrant-operator

go 1.21

require (
	github.com/cert-manager/cert-manager v1.12.1
	github.com/elliotchance/orderedmap/v2 v2.2.0
	github.com/envoyproxy/gateway v1.0.1
	github.com/go-logr/logr v1.4.1
	github.com/google/go-cmp v0.6.0
	github.com/google/uuid v1.6.0
	github.com/istio-ecosystem/sail-operator v0.0.0-20240416130737-d2d3f0cfc882
	github.com/kuadrant/authorino v0.15.0
	github.com/kuadrant/authorino-operator v0.9.0
	github.com/kuadrant/dns-operator v0.1.0
	github.com/kuadrant/limitador-operator v0.7.0
	github.com/martinlindhe/base36 v1.1.1
	github.com/onsi/ginkgo/v2 v2.15.0
	github.com/onsi/gomega v1.31.1
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.22.0
	google.golang.org/protobuf v1.33.0
	gotest.tools v2.2.0+incompatible
	istio.io/api v1.20.0
	istio.io/client-go v1.20.0
	istio.io/istio v0.0.0-20240221233722-55f12a68b4f9
	k8s.io/api v0.29.2
	k8s.io/apiextensions-apiserver v0.29.2
	k8s.io/apimachinery v0.29.2
	k8s.io/client-go v0.29.2
	k8s.io/klog/v2 v2.120.1
	k8s.io/utils v0.0.0-20240102154912-e7106e64919e
	sigs.k8s.io/controller-runtime v0.17.2
	sigs.k8s.io/gateway-api v1.0.1-0.20240207183254-df978ef82cb6
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.11.2 // indirect
	github.com/evanphx/json-patch v5.9.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.9.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-logr/zapr v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.20.2 // indirect
	github.com/go-openapi/jsonreference v0.20.4 // indirect
	github.com/go-openapi/swag v0.22.9 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/pprof v0.0.0-20240125082051-42cd04596328 // indirect
	github.com/imdario/mergo v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.19.0 // indirect
	github.com/prometheus/client_model v0.6.0 // indirect
	github.com/prometheus/common v0.50.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/spf13/cobra v1.8.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tidwall/gjson v1.14.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240119083558-1b970713d09a // indirect
	golang.org/x/oauth2 v0.18.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/term v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.4.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/grpc v1.62.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/component-base v0.29.2 // indirect
	k8s.io/kube-openapi v0.0.0-20240126223410-2919ad4fcfec // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

replace github.com/imdario/mergo => dario.cat/mergo v0.3.5
