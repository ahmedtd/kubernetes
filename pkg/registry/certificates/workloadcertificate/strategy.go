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

// Package workloadcertificate provides Registry interface and its RESTStorage
// implementation for storing WorkloadCertificate objects.
package workloadcertificate // import "k8s.io/kubernetes/pkg/registry/certificates/workloadcertificate"

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/certificates"
	certvalidation "k8s.io/kubernetes/pkg/apis/certificates/validation"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
)

// strategy implements behavior for WorkloadCertificates.
type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the create, update, and delete strategy for WorkloadCertificates.
var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

var _ rest.RESTCreateStrategy = Strategy
var _ rest.RESTUpdateStrategy = Strategy
var _ rest.RESTDeleteStrategy = Strategy

func (strategy) NamespaceScoped() bool {
	return true
}

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	wc := obj.(*certificates.WorkloadCertificate)
	return certvalidation.ValidateWorkloadCertificateCreate(wc)
}

func (strategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (strategy) Canonicalize(obj runtime.Object) {}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (s strategy) PrepareForUpdate(ctx context.Context, new, old runtime.Object) {}

// TODO(KEP-WorkloadCertificates): Copy the immutability behavior of CSRs.
func (s strategy) ValidateUpdate(ctx context.Context, new, old runtime.Object) field.ErrorList {
	newWC := new.(*certificates.WorkloadCertificate)
	oldWC := old.(*certificates.WorkloadCertificate)
	return certvalidation.ValidateWorkloadCertificateUpdate(newWC, oldWC)
}

func (strategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

func (strategy) AllowUnconditionalUpdate() bool {
	return false
}

type statusStrategy struct {
	strategy
}

var StatusStrategy = statusStrategy{Strategy}

func (statusStrategy) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	fields := map[fieldpath.APIVersion]*fieldpath.Set{
		"certificates.k8s.io/v1alpha1": fieldpath.NewSet(
			fieldpath.MakePathOrDie("spec"),
		),
	}
	return fields
}

func (statusStrategy) PrepareForUpdate(ctx context.Context, new, old runtime.Object) {
	newWC := new.(*certificates.WorkloadCertificate)
	oldWC := old.(*certificates.WorkloadCertificate)

	// Updating /status should not modify spec.
	newWC.Spec = oldWC.Spec
}

// nowFunc allows overriding for unit tests.
//
// TODO(KEP-WorkloadCertificate): Use a clock adapter instead?
var nowFunc = metav1.Now()

func (statusStrategy) ValidateUpdate(ctx context.Context, new, old runtime.Object) field.ErrorList {
	newWC := new.(*certificates.WorkloadCertificate)
	oldWC := new.(*certificates.WorkloadCertificate)
	return certvalidation.ValidateWorkloadCertificateStatusUpdate(newWC, oldWC)
}

func (statusStrategy) WarningsOnUpdate(ctx context.Context, new, old runtime.Object) []string {
	return nil
}

func (statusStrategy) Canonicalize(obj runtime.Object) {
}
