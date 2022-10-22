package clustertrustbundle

import (
	"fmt"

	certificatesv1alpha1 "k8s.io/api/certificates/v1alpha1"
	certinformersv1alpha1 "k8s.io/client-go/informers/certificates/v1alpha1"
)

type Manager interface {
	GetClusterTrustBundle(name string) (*certificatesv1alpha1.ClusterTrustBundle, error)
}

type InformerManager struct {
	bundles certinformersv1alpha1.ClusterTrustBundleInformer
}

func NewInformerManager(bundles certinformersv1alpha1.ClusterTrustBundleInformer) *InformerManager {
	return &InformerManager{
		bundles: bundles,
	}
}

func (m *InformerManager) GetClusterTrustBundle(name string) (*certificatesv1alpha1.ClusterTrustBundle, error) {
	if !m.bundles.Informer().HasSynced() {
		return nil, fmt.Errorf("ClusterTrustBundle informer has not yet synced")
	}

	return m.bundles.Lister().Get(name)
}

// NoopManager always returns an error, for use in static kubelet mode.
type NoopManager struct{}

func (m *NoopManager) GetClusterTrustBundle(name string) (*certificatesv1alpha1.ClusterTrustBundle, error) {
	return nil, fmt.Errorf("cluster trust bundle projection is not supported in static kubelet mode")
}
