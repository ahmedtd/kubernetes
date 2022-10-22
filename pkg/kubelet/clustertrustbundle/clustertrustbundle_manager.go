/*
Copyright 2023 The Kubernetes Authors.

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

package clustertrustbundle

import (
	"encoding/pem"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certinformersv1alpha1 "k8s.io/client-go/informers/certificates/v1alpha1"
	certlistersv1alpha1 "k8s.io/client-go/listers/certificates/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

type Manager interface {
	GetTrustAnchorsByName(name string) (string, error)
	GetTrustAnchorsBySigner(signerName string, labelSelector metav1.LabelSelector) (string, error)
}

type InformerManager struct {
	ctbInformer cache.SharedIndexInformer
	ctbLister   certlistersv1alpha1.ClusterTrustBundleLister
}

func NewInformerManager(bundles certinformersv1alpha1.ClusterTrustBundleInformer) *InformerManager {
	// We need to call Informer() before calling start on the shared informer
	// factory, or the informer won't be registered to be started.
	return &InformerManager{
		ctbInformer: bundles.Informer(),
		ctbLister:   bundles.Lister(),
	}
}

func (m *InformerManager) GetTrustAnchorsByName(name string) (string, error) {
	if !m.ctbInformer.HasSynced() {
		return "", fmt.Errorf("ClusterTrustBundle informer has not yet synced")
	}

	ctb, err := m.ctbLister.Get(name)
	if err != nil {
		return "", fmt.Errorf("while getting ClusterTrustBundle: %w", err)
	}

	return ctb.Spec.TrustBundle, nil
}

func (m *InformerManager) GetTrustAnchorsBySigner(signerName string, labelSelector metav1.LabelSelector) (string, error) {
	if !m.ctbInformer.HasSynced() {
		return "", fmt.Errorf("ClusterTrustBundle informer has not yet synced")
	}

	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return "", fmt.Errorf("while parsing label selector: %w", err)
	}

	ctbList, err := m.ctbLister.List(selector)
	if err != nil {
		return "", fmt.Errorf("while listing ClusterTrustBundles matching label selector %v: %w", labelSelector, err)
	}

	// Deduplicate trust anchors from all ClusterTrustBundles that match signerName and labelSelector.
	trustAnchorSet := map[string]bool{}
	for _, ctb := range ctbList {
		if ctb.Spec.SignerName != signerName {
			continue
		}

		rest := []byte(ctb.Spec.TrustBundle)
		var b *pem.Block
		for {
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			trustAnchorSet[string(b.Bytes)] = true
		}
	}

	trustAnchors := make([]string, 0, len(trustAnchorSet))
	for ta := range trustAnchorSet {
		trustAnchors = append(trustAnchors, ta)
	}
	sort.Strings(trustAnchors)

	// Reserialize the deduped and sorted set to PEM.
	pemTrustAnchors := []byte{}
	for _, ta := range trustAnchors {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte(ta),
		}
		pemTrustAnchors = append(pemTrustAnchors, pem.EncodeToMemory(b)...)
	}

	return string(pemTrustAnchors), nil
}

// NoopManager always returns an error, for use in static kubelet mode.
type NoopManager struct{}

func (m *NoopManager) GetTrustAnchorsByName(name string) (string, error) {
	return "", fmt.Errorf("ClusterTrustBundle projection is not supported in static kubelet mode")
}

func (m *NoopManager) GetTrustAnchorsBySigner(signerName string, labelSelector metav1.LabelSelector) (string, error) {
	return "", fmt.Errorf("ClusterTrustBundle projection is not supported in static kubelet mode")
}
