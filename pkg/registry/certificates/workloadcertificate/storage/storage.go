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

package storage

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	api "k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
	"k8s.io/kubernetes/pkg/registry/certificates/workloadcertificate"
)

// REST is a RESTStorage for Workloadcertificate.
type REST struct {
	*genericregistry.Store
}

var _ rest.StandardStorage = &REST{}
var _ rest.TableConvertor = &REST{}
var _ genericregistry.GenericStore = &REST{}

// NewREST returns a RESTStorage object for WorkloadCertificate objects.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &api.WorkloadCertificate{} },
		NewListFunc:               func() runtime.Object { return &api.WorkloadCertificateList{} },
		DefaultQualifiedResource:  api.Resource("workloadcertificates"),
		SingularQualifiedResource: api.Resource("workloadcertificate"),

		CreateStrategy: workloadcertificate.Strategy,
		UpdateStrategy: workloadcertificate.Strategy,
		DeleteStrategy: workloadcertificate.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    getAttrs,
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = workloadcertificate.StatusStrategy
	statusStore.ResetFieldsStrategy = workloadcertificate.StatusStrategy

	return &REST{store}, &StatusREST{store: &statusStore}, nil
}

func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	bundle, ok := obj.(*api.WorkloadCertificate)
	if !ok {
		return nil, nil, fmt.Errorf("not a workloadcertificate")
	}

	selectableFields := generic.MergeFieldsSets(generic.ObjectMetaFieldsSet(&bundle.ObjectMeta, false), fields.Set{
		"spec.signerName": bundle.Spec.SignerName,
		"spec.node":       bundle.Spec.Node,
	})

	return labels.Set(bundle.Labels), selectableFields, nil
}

type StatusREST struct {
	store *genericregistry.Store
}

var _ = rest.Patcher(&StatusREST{})

func (r *StatusREST) New() runtime.Object {
	return &api.WorkloadCertificate{}
}

func (r *StatusREST) Destroy() {
	// Underyling store is shared with REST.  Don't destroy it here.
}

// Get implements rest.Patcher.  We don't have any custom behavior, so just
// dispatch to the underlying store.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	// We are explicitly setting forceAllowCreate to false in the call to the underlying storage because
	// subresources should never allow create on update.
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}
