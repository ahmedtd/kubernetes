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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
)

// Built in signerName values that are honoured by kube-controller-manager.
const (
	// This signer issues certificates that are suitable for
	// workload-to-workload authentication.
	DefaultWorkloadCertificateSignerName = "kubernetes.io/default-workload-certificate"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:prerelease-lifecycle-gen:introduced=1.26
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterTrustBundle is a cluster-scoped container for X.509 trust anchors
// (root certificates).
//
// ClusterTrustBundle objects are considered to be readable by any authenticated
// user in the cluster, because they can be mounted by pods using the
// `clusterTrustBundle` projection.  All service accounts have read access to
// ClusterTrustBundles by default.  Users who only have namespace-level access
// to a cluster can read ClusterTrustBundles by impersonating a serviceaccount
// that they have access to.
//
// It can be optionally associated with a particular assigner, in which case it
// contains one valid set of trust anchors for that signer. Signers may have
// multiple associated ClusterTrustBundles; each is an independent set of trust
// anchors for that signer. Admission control is used to enforce that only users
// with permissions on the signer can create or modify the corresponding bundle.
type ClusterTrustBundle struct {
	metav1.TypeMeta `json:",inline"`

	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// spec contains the signer (if any) and trust anchors.
	Spec ClusterTrustBundleSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}

// ClusterTrustBundleSpec contains the signer and trust anchors.
type ClusterTrustBundleSpec struct {
	// signerName indicates the associated signer, if any.
	//
	// In order to create or update a ClusterTrustBundle that sets signerName,
	// you must have the following cluster-scoped permission:
	// group=certificates.k8s.io resource=signers resourceName=<the signer name>
	// verb=attest.
	//
	// If signerName is not empty, then the ClusterTrustBundle object must be
	// named with the signer name as a prefix (translating slashes to colons).
	// For example, for the signer name `example.com/foo`, valid
	// ClusterTrustBundle object names include `example.com:foo:abc` and
	// `example.com:foo:v1`.
	//
	// If signerName is empty, then the ClusterTrustBundle object's name must
	// not have such a prefix.
	//
	// List/watch requests for ClusterTrustBundles can filter on this field
	// using a `spec.signerName=NAME` field selector.
	//
	// +optional
	SignerName string `json:"signerName,omitempty" protobuf:"bytes,1,opt,name=signerName"`

	// trustBundle contains the individual X.509 trust anchors for this
	// bundle, as PEM bundle of PEM-wrapped, DER-formatted X.509 certificates.
	//
	// The data must consist only of PEM certificate blocks that parse as valid
	// X.509 certificates.  Each certificate must include a basic constraints
	// extension with the CA bit set.  The API server will reject objects that
	// contain duplicate certificates, or that use PEM block headers.
	//
	// Users of ClusterTrustBundles, including Kubelet, are free to reorder and
	// deduplicate certificate blocks in this file according to their own logic,
	// as well as to drop PEM block headers and inter-block data.
	TrustBundle string `json:"trustBundle" protobuf:"bytes,2,opt,name=trustBundle"`
}

// +k8s:prerelease-lifecycle-gen:introduced=1.26
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterTrustBundleList is a collection of ClusterTrustBundle objects
type ClusterTrustBundleList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata contains the list metadata.
	//
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// items is a collection of ClusterTrustBundle objects
	Items []ClusterTrustBundle `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +k8s:prerelease-lifecycle-gen:introduced=1.28
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type WorkloadCertificate struct {
	metav1.TypeMeta `json:",inline"`

	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// spec contains the desired signer, and the requesting workload and node identity.
	Spec WorkloadCertificateSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

	// status contains the conditions and the issued certificate.
	// +optional
	Status WorkloadCertificateStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

type WorkloadCertificateSpec struct {
	// signerName is the signer that should handle this request.
	//
	// Immutable after creation.
	SignerName string `json:"signerName" protobuf:"bytes,1,opt,name=signerName"`

	// serviceAccount is the name of the service account of the pod being asserted.
	//
	// Immutable after creation.
	ServiceAccount string `json:"serviceAccount" protobuf:"bytes,2,opt,name=serviceAccount"`

	// pod is the name of the pod being asserted.
	//
	// Immutable after creation.
	Pod string `json:"pod" protobuf:"bytes,4,opt,name=pod"`

	// podUID is the UID of the pod being asserted.
	//
	// Immutable after creation.
	PodUID string `json:"podUID" protobuf:"bytes,5,opt,name=podUID"`

	// node is the node on which the pod being asserted is running.
	//
	// Immutable after creation.
	Node string `json:"node" protobuf:"bytes,6,opt,name=node"`

	// requester is the identity of the certificate requester (typically either the node identity, or the service account of a daemonset).
	//
	// Immutable after creation.
	Requester string `json:"requester" protobuf:"bytes,7,opt,name=requester"`

	// PublicKey is the PEM-formatted public key.
	// +optional
	PublicKey string `json:"publicKey" protobuf:"bytes,8,opt,name=publicKey"`
}

type WorkloadCertificateStatus struct {
	// conditions applied to the request. Known conditions are "Denied" and "Pending".
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []WorkloadCertificateCondition `json:"conditions,omitempty" protobuf:"bytes,1,rep,name=conditions"`

	// +listType=atomic
	// +optional
	Certificate string `json:"certificate,omitempty" protobuf:"bytes,2,opt,name=certificate"`

	// +optional
	CertificateObservedGeneration int64 `json:"certificateObservedGeneration,omitempty" protobuf:"bytes,3,opt,name=certificateObservedGeneration"`

	// +optional
	NotBefore metav1.Time `json:"notBefore,omitempty" protobuf:"bytes,4,opt,name=notBefore"`

	// +optional
	NotAfter metav1.Time `json:"notAfter,omitempty" protobuf:"bytes,5,opt,name=notAfter"`

	// +optional
	BeginRefreshAt metav1.Time `json:"beginRefreshAt,omitempty" protobuf:"bytes,6,opt,name=beginRefreshAt"`
}

// WorkloadCertificateConditionType is the type of a WorkloadCertificateCondition.
type WorkloadCertificateConditionType string

// Well-known condition types for workload certificates.
const (
	// Failed indicates the signer permanently failed to issue the certificate.
	WorkloadCertificateFailed WorkloadCertificateConditionType = "Failed"
	// Pending indicates the signer temporarily failed to issue the certificate.
	WorkloadCertificatePending WorkloadCertificateConditionType = "Pending"
)

// WorkloadCertificateCondition describes a condition of a CertificateSigningRequest object
type WorkloadCertificateCondition struct {
	Type WorkloadCertificateConditionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=WorkloadCertificateConditionType"`
	// status of the condition, one of True, False, Unknown.
	Status corev1.ConditionStatus `json:"status" protobuf:"bytes,2,opt,name=status,casttype=k8s.io/api/core/v1.ConditionStatus"`
	// reason indicates a brief reason for the request state
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,3,opt,name=reason"`
	// message contains a human readable message with details about the request state
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,4,opt,name=message"`
	// observedGeneration is the generation of the object at which this condition was recorded.
	ObservedGeneration int64 `json:"observedGeneration,omitempty" protobuf:"varint,5,opt,name=observedGeneration"`
	// lastUpdateTime is the time of the last update to this condition
	// +optional
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty" protobuf:"bytes,6,opt,name=lastUpdateTime"`
	// lastTransitionTime is the time the condition last transitioned from one status to another.
	// If unset, when a new condition type is added or an existing condition's status is changed,
	// the server defaults this to the current time.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty" protobuf:"bytes,7,opt,name=lastTransitionTime"`
}

// +k8s:prerelease-lifecycle-gen:introduced=1.28
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type WorkloadCertificateList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata contains the list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// items is a collection of WorkloadCertificate objects
	Items []WorkloadCertificate `json:"items" protobuf:"bytes,2,rep,name=items"`
}
