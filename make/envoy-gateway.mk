
##@ Envoy Gateway

## Targets to help install and configure EG

EG_CONFIG_DIR = config/dependencies/envoy-gateway
EG_NAMESPACE = envoy-gateway-system

# egctl tool
EGCTL=$(PROJECT_PATH)/bin/egctl
EG_VERSION = v1.0.0
OS = linux
ARCH = amd64
$(EGCTL):
	mkdir -p $(PROJECT_PATH)/bin
	## get-egctl.sh requires sudo and does not allow installing in a custom location. Fails if not in the PATH as well
	# curl -sSL https://gateway.envoyproxy.io/get-egctl.sh | EGCTL_INSTALL_DIR=$(PROJECT_PATH)/bin  VERSION=$(EG_VERSION) bash
	$(eval TMP := $(shell mktemp -d))
	cd $(TMP); curl -sSL https://github.com/envoyproxy/gateway/releases/download/$(EG_VERSION)/egctl_$(EG_VERSION)_$(OS)_$(ARCH).tar.gz -o egctl.tar.gz
	tar xf $(TMP)/egctl.tar.gz -C $(TMP)
	cp $(TMP)/bin/$(OS)/$(ARCH)/egctl $(EGCTL)
	-rm -rf $(TMP)

.PHONY: egctl
egctl: $(EGCTL) ## Download egctl locally if necessary.

.PHONY: envoy-gateway-install
envoy-gateway-install: kustomize
	$(KUSTOMIZE) build $(EG_CONFIG_DIR) | kubectl apply -f -
	kubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available

.PHONY: envoy-gateway-uninstall
envoy-gateway-uninstall: kustomize ## Uninstall envoy gateway.
	$(KUSTOMIZE) build $(EG_CONFIG_DIR) | kubectl delete -f -

.PHONY: deploy-eg-gateway
deploy-eg-gateway: kustomize ## Deploy Gateway API gateway
	$(KUSTOMIZE) build $(EG_CONFIG_DIR)/gateway | kubectl apply -f -
	kubectl wait --timeout=5m -n envoy-gateway-system gateway/eg --for=condition=Programmed
	@echo
	@echo "-- Linux only -- Ingress gateway is exported using loadbalancer service in port 80"
	@echo "export INGRESS_HOST=\$$(kubectl get gtw eg -n envoy-gateway-system -o jsonpath='{.status.addresses[0].value}')"
	@echo "export INGRESS_PORT=\$$(kubectl get gtw eg -n envoy-gateway-system -o jsonpath='{.spec.listeners[?(@.name==\"http\")].port}')"
	@echo "Now you can hit the gateway:"
	@echo "curl --verbose --resolve www.example.com:\$${INGRESS_PORT}:\$${INGRESS_HOST} http://www.example.com:\$${INGRESS_PORT}/get"
