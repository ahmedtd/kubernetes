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

package workloadcertificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	certificatesv1alpha1 "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certinformersv1alpha1 "k8s.io/client-go/informers/certificates/v1alpha1"
	"k8s.io/client-go/kubernetes"
	certlistersv1alpha1 "k8s.io/client-go/listers/certificates/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
)

type Manager interface {
	GetWorkloadCertificate(ctx context.Context, signerName, namespace, podName, podUID, volumeName string, sourceIndex int, keyFileHash string) (string, string, error)
}

type InformerManager struct {
	wcInformer cache.SharedIndexInformer
	wcLister   certlistersv1alpha1.WorkloadCertificateLister

	kc kubernetes.Interface

	clock clock.WithTicker
}

func NewInformerManager(kc kubernetes.Interface, informer certinformersv1alpha1.WorkloadCertificateInformer, clock clock.WithTicker) *InformerManager {
	// We need to call Informer() before calling start on the shared informer
	// factory, or the informer won't be registered to be started.
	return &InformerManager{
		wcInformer: informer.Informer(),
		wcLister:   informer.Lister(),
		kc:         kc,
		clock:      clock,
	}
}

func (m *InformerManager) GetWorkloadCertificate(ctx context.Context, signerName, namespace, podName, podUID, volumeName string, sourceIndex int, keyFileHash string) (string, string, error) {
	// Use a stable name for our WorkloadCertificate.
	wcName := fmt.Sprintf("kubelet-%s-%s-%d", podName, volumeName, sourceIndex)

	wc, err := m.wcLister.WorkloadCertificates(namespace).Get(wcName)
	if k8serrors.IsNotFound(err) {
		wc := &certificatesv1alpha1.WorkloadCertificate{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      wcName,
			},
			Spec: certificatesv1alpha1.WorkloadCertificateSpec{
				SignerName: signerName,
				Pod:        podName,
				PodUID:     podUID,
				// ServiceAccount, Node and Requester will be filled out by an admission plugin.
			},
		}

		privKeyPEM, err := m.rekeyWorkloadCertificate(wc)
		if err != nil {
			return "", "", fmt.Errorf("while initially keying WorkloadCertificate: %w", err)
		}

		_, err = m.kc.CertificatesV1alpha1().WorkloadCertificates(namespace).Create(ctx, wc, metav1.CreateOptions{})
		if err != nil {
			return "", "", fmt.Errorf("while creating WorkloadCertificate: %w", err)
		}

		wc, err = m.waitForWorkloadCertificateIssuance(ctx, namespace, wcName)
		if err != nil {
			return "", "", fmt.Errorf("while waiting for WorkloadCertificate to be issued: %w", err)
		}

		return privKeyPEM, wc.Status.Certificate, nil
	} else if err != nil {
		return "", "", fmt.Errorf("while fetching WorkloadCertificate from informer cache: %w", err)
	}

	// TODO(KEP-WorkloadCertificates): Detect if the WorkloadCertificate looks
	// incompatible --- like we have had a name collision.

	if wc.ObjectMeta.Annotations["workloadcertificates.kubelet.kubernetes.io/private-key-file-hash"] != keyFileHash {
		// TODO(KEP-WorkloadCertificates): Re-key because the workload messed with the key file on disk.
	}

	if m.clock.Now().After(wc.Status.BeginRefreshAt.Time) {
		// TODO: Re-key because it is time to renew the certificate.
		newWC := wc.DeepCopy()
		privKeyPEM, err := m.rekeyWorkloadCertificate(newWC)
		if err != nil {
			return "", "", fmt.Errorf("while rekeying WorkloadCertificate: %w", err)
		}

		_, err = m.kc.CertificatesV1alpha1().WorkloadCertificates(namespace).Update(ctx, newWC, metav1.UpdateOptions{})
		if err != nil {
			return "", "", fmt.Errorf("while creating WorkloadCertificate: %w", err)
		}

		newWC, err = m.waitForWorkloadCertificateIssuance(ctx, namespace, wcName)
		if err != nil {
			return "", "", fmt.Errorf("while waiting for WorkloadCertificate to be issued: %w", err)
		}

		return privKeyPEM, newWC.Status.Certificate, nil
	}

	// Re-keying is not necessary.  However, we might be coming back to a
	// WorkloadCertificate that has not yet been issued.  Wait for issuance if
	// necessary.

	// Wait for the existing certificate to be issued.  Returns immediately if
	// it's already issued.
	wc, err = m.waitForWorkloadCertificateIssuance(ctx, namespace, wcName)
	if err != nil {
		return "", "", fmt.Errorf("while waiting for WorkloadCertificate to be issued: %w", err)
	}

	return "", wc.Status.Certificate, nil
}

func (m *InformerManager) rekeyWorkloadCertificate(wc *certificatesv1alpha1.WorkloadCertificate) (string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("while generating private key: %w", err)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("while marshaling private key: %w", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	keyFileHash := sha512.Sum512_256(privKeyPEM)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("while marshaling public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	if wc.ObjectMeta.Annotations == nil {
		wc.ObjectMeta.Annotations = map[string]string{}
	}
	wc.ObjectMeta.Annotations["workloadcertificates.kubelet.kubernetes.io/private-key-file-hash"] = base64.StdEncoding.EncodeToString(keyFileHash[:])
	wc.Spec.PublicKey = string(pubKeyPEM)

	return string(privKeyPEM), nil
}

func (m *InformerManager) waitForWorkloadCertificateIssuance(ctx context.Context, namespace, name string) (*certificatesv1alpha1.WorkloadCertificate, error) {
	wc, err := m.wcLister.WorkloadCertificates(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("while retrieving WorkloadCertificate from informer cache: %w", err)
	}
	if status, msg := m.isWorkloadCertificateIssued(wc); status == issued {
		return wc, nil
	} else if status == failed {
		return nil, errors.New(msg)
	}

	// Status is pending.

	t := m.clock.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-t.C():
		}

		wc, err := m.wcLister.WorkloadCertificates(namespace).Get(name)
		if err != nil {
			return nil, fmt.Errorf("while retrieving WorkloadCertificate from informer cache: %w", err)
		}
		if status, msg := m.isWorkloadCertificateIssued(wc); status == issued {
			return wc, nil
		} else if status == failed {
			return nil, errors.New(msg)
		}
	}
}

type issuanceStatus int

const (
	issued issuanceStatus = iota
	pending
	failed
)

func (m *InformerManager) isWorkloadCertificateIssued(wc *certificatesv1alpha1.WorkloadCertificate) (issuanceStatus, string) {
	if len(wc.Status.Certificate) != 0 && wc.Status.CertificateObservedGeneration == wc.ObjectMeta.Generation {
		// Certificate is issued.
		return issued, ""
	}

	for _, cond := range wc.Status.Conditions {
		if cond.Type == certificatesv1alpha1.WorkloadCertificateFailed && cond.Status == corev1.ConditionTrue && cond.ObservedGeneration == wc.ObjectMeta.Generation {
			return failed, fmt.Sprintf("the WorkloadCertificate failed issuance (reason=%s): %s", cond.Reason, cond.Message)
		}
	}

	for _, cond := range wc.Status.Conditions {
		if cond.Type == certificatesv1alpha1.WorkloadCertificatePending && cond.Status == corev1.ConditionTrue && cond.ObservedGeneration == wc.ObjectMeta.Generation {
			return pending, fmt.Sprintf("the WorkloadCertificate is explicitly pending (reason=%q): %s", cond.Reason, cond.Message)
		}
	}

	return pending, "the WorkloadCertificate is implicitly pending"
}

// NoopManager always returns an error, for use in static kubelet mode.
type NoopManager struct{}

func (m *NoopManager) GetWorkloadCertificate(ctx context.Context, signerName, namespace, podName, podUID, volumeName string, sourceIndex int, keyFileHash string) (string, string, error) {
	return "", "", fmt.Errorf("WorkloadCertificate projection is not supported in static kubelet mode")
}
