package istio

import (
	"context"

	"github.com/go-logr/logr"
	iopv1alpha1 "istio.io/istio/operator/pkg/apis/istio/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/env"
	istiov1alpha1 "maistra.io/istio-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	maistrav1 "github.com/kuadrant/kuadrant-operator/api/external/maistra/v1"
	maistrav2 "github.com/kuadrant/kuadrant-operator/api/external/maistra/v2"
	kuadrantv1beta1 "github.com/kuadrant/kuadrant-operator/api/v1beta1"
)

const (
	// (Sail) The istio CR must be named default to process GW API resources
	istioCRName = "default"
)

func controlPlaneProviderName() string {
	return env.GetString("ISTIOOPERATOR_NAME", "istiocontrolplane")
}

func controlPlaneConfigMapName() string {
	return env.GetString("ISTIOCONFIGMAP_NAME", "istio")
}

func controlPlaneProviderNamespace() string {
	return env.GetString("ISTIOOPERATOR_NAMESPACE", "istio-system")
}

func RegisterExternalAuthorizer(ctx context.Context, cl client.Client, kObj *kuadrantv1beta1.Kuadrant, scheme *runtime.Scheme) error {
	logger, _ := logr.FromContext(ctx)

	isIstioInstalled, err := registerExternalAuthorizerIstio(ctx, cl, kObj.Namespace)

	if err != nil {
		return err
	}

	if isIstioInstalled {
		return nil
	}

	err = registerExternalAuthorizerOSSM(ctx, cl, kObj, scheme)

	if err != nil {
		logger.Error(err, "failed fo get service mesh control plane")
	}

	return nil
}

func registerExternalAuthorizerIstio(ctx context.Context, cl client.Client, kNamespace string) (bool, error) {
	logger, _ := logr.FromContext(ctx)
	configsToUpdate, err := getIstioConfigObjects(ctx, cl, logger)
	isIstioInstalled := configsToUpdate != nil

	if !isIstioInstalled || err != nil {
		return isIstioInstalled, err
	}

	kuadrantAuthorizer := NewKuadrantAuthorizer(kNamespace)
	for _, config := range configsToUpdate {
		hasKuadrantAuthorizer, err := HasKuadrantAuthorizer(config, *kuadrantAuthorizer)
		if err != nil {
			return true, err
		}
		if !hasKuadrantAuthorizer {
			err = RegisterKuadrantAuthorizer(config, kuadrantAuthorizer)
			if err != nil {
				return true, err
			}
			logger.Info("adding external authorizer to istio meshconfig")
			if err = cl.Update(ctx, config.GetConfigObject()); err != nil {
				return true, err
			}
		}
	}

	return true, nil
}

func getIstioConfigObjects(ctx context.Context, cl client.Client, logger logr.Logger) ([]ConfigWrapper, error) {
	var configsToUpdate []ConfigWrapper

	iop := &iopv1alpha1.IstioOperator{}
	istKey := client.ObjectKey{Name: controlPlaneProviderName(), Namespace: controlPlaneProviderNamespace()}
	err := cl.Get(ctx, istKey, iop)
	if err == nil || apierrors.IsNotFound(err) {
		configsToUpdate = append(configsToUpdate, NewOperatorWrapper(iop))
	} else if !meta.IsNoMatchError(err) {
		logger.V(1).Info("failed to get istiooperator object", "key", istKey, "err", err)
		return nil, err
	} else {
		// Error is NoMatchError so check for Istio CR instead
		ist := &istiov1alpha1.Istio{}
		istKey := client.ObjectKey{Name: istioCRName}
		if err := cl.Get(ctx, istKey, ist); err != nil {
			logger.V(1).Info("failed to get istio object", "key", istKey, "err", err)
			if meta.IsNoMatchError(err) {
				// return nil and nil if there's no istiooperator or istio CR
				return nil, nil
			} else if !apierrors.IsNotFound(err) {
				// return nil and err if there's an error other than not found (no istio CR)
				return nil, err
			}
		}
		configsToUpdate = append(configsToUpdate, NewSailWrapper(ist))
	}

	istioConfigMap := &corev1.ConfigMap{}
	if err := cl.Get(ctx, client.ObjectKey{Name: controlPlaneConfigMapName(), Namespace: controlPlaneProviderNamespace()}, istioConfigMap); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.V(1).Info("failed to get istio configMap", "key", istKey, "err", err)
			return configsToUpdate, err
		}
	} else {
		configsToUpdate = append(configsToUpdate, NewConfigMapWrapper(istioConfigMap))
	}
	return configsToUpdate, nil
}

func registerExternalAuthorizerOSSM(ctx context.Context, cl client.Client, kObj *kuadrantv1beta1.Kuadrant, scheme *runtime.Scheme) error {
	logger, _ := logr.FromContext(ctx)

	if err := registerServiceMeshMember(ctx, cl, kObj, scheme); err != nil {
		return err
	}

	smcp := &maistrav2.ServiceMeshControlPlane{}

	smcpKey := client.ObjectKey{Name: controlPlaneProviderName(), Namespace: controlPlaneProviderNamespace()}
	if err := cl.Get(ctx, smcpKey, smcp); err != nil {
		logger.V(1).Info("failed to get servicemeshcontrolplane object", "key", smcp, "err", err)
		return err
	}
	smcpWrapper := NewOSSMControlPlaneWrapper(smcp)
	kuadrantAuthorizer := NewKuadrantAuthorizer(kObj.Namespace)

	hasKuadrantAuthorizer, err := HasKuadrantAuthorizer(smcpWrapper, *kuadrantAuthorizer)
	if err != nil {
		return err
	}
	if !hasKuadrantAuthorizer {
		err = RegisterKuadrantAuthorizer(smcpWrapper, kuadrantAuthorizer)
		if err != nil {
			return err
		}
		logger.Info("adding external authorizer to OSSM meshconfig")
		if err := cl.Update(ctx, smcpWrapper.GetConfigObject()); err != nil {
			return err
		}
	}

	return nil
}

func registerServiceMeshMember(ctx context.Context, cl client.Client, kObj *kuadrantv1beta1.Kuadrant, scheme *runtime.Scheme) error {
	member := buildServiceMeshMember(kObj.Namespace)

	err := controllerutil.SetControllerReference(kObj, member, scheme)
	if err != nil {
		return err
	}

	memberKey := client.ObjectKeyFromObject(member)
	existing := &maistrav1.ServiceMeshMember{}
	err = cl.Get(ctx, memberKey, existing)
	if err == nil {
		// already exists
		return nil
	}

	if errors.IsNotFound(err) {
		return cl.Create(ctx, member)
	}

	return err
}

func buildServiceMeshMember(kNamespace string) *maistrav1.ServiceMeshMember {
	return &maistrav1.ServiceMeshMember{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceMeshMember",
			APIVersion: maistrav1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: kNamespace,
		},
		Spec: maistrav1.ServiceMeshMemberSpec{
			ControlPlaneRef: maistrav1.ServiceMeshControlPlaneRef{
				Name:      controlPlaneProviderName(),
				Namespace: controlPlaneProviderNamespace(),
			},
		},
	}
}

func UnregisterExternalAuthorizer(ctx context.Context, cl client.Client, kNamespace string) error {
	logger, _ := logr.FromContext(ctx)

	isIstioInstalled, err := unregisterExternalAuthorizerIstio(ctx, cl, kNamespace)

	if err == nil && !isIstioInstalled {
		err = unregisterExternalAuthorizerOSSM(ctx, cl, kNamespace)
	}

	if err != nil {
		logger.Error(err, "failed fo get service mesh control plane")
	}

	return err
}

func unregisterExternalAuthorizerIstio(ctx context.Context, cl client.Client, kNamespace string) (bool, error) {
	logger, _ := logr.FromContext(ctx)
	configsToUpdate, err := getIstioConfigObjects(ctx, cl, logger)
	isIstioInstalled := configsToUpdate != nil

	if !isIstioInstalled || err != nil {
		return isIstioInstalled, err
	}

	kuadrantAuthorizer := NewKuadrantAuthorizer(kNamespace)

	for _, config := range configsToUpdate {
		hasKuadrantAuthorizer, err := HasKuadrantAuthorizer(config, *kuadrantAuthorizer)
		if err != nil {
			return true, err
		}
		if hasKuadrantAuthorizer {
			if err = UnregisterKuadrantAuthorizer(config, kuadrantAuthorizer); err != nil {
				return true, err
			}

			logger.Info("remove external authorizer from istio meshconfig")
			if err = cl.Update(ctx, config.GetConfigObject()); err != nil {
				return true, err
			}
		}
	}
	return true, nil
}

func unregisterExternalAuthorizerOSSM(ctx context.Context, cl client.Client, kNamespace string) error {
	logger, _ := logr.FromContext(ctx)

	smcp := &maistrav2.ServiceMeshControlPlane{}

	smcpKey := client.ObjectKey{Name: controlPlaneProviderName(), Namespace: controlPlaneProviderNamespace()}
	if err := cl.Get(ctx, smcpKey, smcp); err != nil {
		logger.V(1).Info("failed to get servicemeshcontrolplane object", "key", smcp, "err", err)
		return err
	}

	smcpWrapper := NewOSSMControlPlaneWrapper(smcp)
	kuadrantAuthorizer := NewKuadrantAuthorizer(kNamespace)

	hasKuadrantAuthorizer, err := HasKuadrantAuthorizer(smcpWrapper, *kuadrantAuthorizer)
	if err != nil {
		return err
	}
	if hasKuadrantAuthorizer {
		err = UnregisterKuadrantAuthorizer(smcpWrapper, kuadrantAuthorizer)
		if err != nil {
			return err
		}
		logger.Info("removing external authorizer from  OSSM meshconfig")
		if err := cl.Update(ctx, smcpWrapper.GetConfigObject()); err != nil {
			return err
		}
	}

	return nil
}
