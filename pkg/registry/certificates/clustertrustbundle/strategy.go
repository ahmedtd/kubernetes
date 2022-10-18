// Package clustertrustbundle provides Registry interface and its RESTStorage
// implementation for storing ClusterTrustBundle objects.
package clustertrustbundle // import "k8s.io/kubernetes/pkg/registry/certificates/clustertrustbundle"

import (
	"context"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/certificates"
	certvalidation "k8s.io/kubernetes/pkg/apis/certificates/validation"
	apivalidation "k8s.io/kubernetes/pkg/apis/core/validation"
)

// strategy implements behavior for ClusterTrustBundles.
type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the create, update, and delete strategy for ClusterTrustBundles.
var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

var _ rest.RESTCreateStrategy = Strategy
var _ rest.RESTUpdateStrategy = Strategy
var _ rest.RESTDeleteStrategy = Strategy

func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {}

func noRestrictionsOnName(name string, prefix bool) []string {
	return nil
}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	bundle := obj.(*certificates.ClusterTrustBundle)

	var allErrors field.ErrorList
	allErrors = append(allErrors, apivalidation.ValidateObjectMeta(&bundle.ObjectMeta, false, noRestrictionsOnName, field.NewPath("metadata"))...)

	if bundle.Spec.SignerName != "" {
		signerNameErrors := certvalidation.ValidateSignerName(field.NewPath("spec", "signerName"), bundle.Spec.SignerName)
		allErrors = append(allErrors, signerNameErrors...)
	}

	// TODO(KEP-3257): Is it OK to modify the object during validate?
	pemTrustAnchors, err := normalizePEMTrustAnchors(bundle.Spec.PEMTrustAnchors)
	if err != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "contains an invalid block"))
		return allErrors
	}
	bundle.Spec.PEMTrustAnchors = pemTrustAnchors

	if bundle.Spec.PEMTrustAnchors == "" {
		allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"))
	}

	return allErrors
}

func (strategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (strategy) Canonicalize(obj runtime.Object) {
	// TODO(KEP-3257): Is it OK to do the canonicalization as part of
	// Validate(), or do we need an explicit call to normalizePEMTrustAnchors
	// here?
}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (s strategy) PrepareForUpdate(ctx context.Context, new, old runtime.Object) {
	s.PrepareForCreate(ctx, new)
}

func (s strategy) ValidateUpdate(ctx context.Context, new, old runtime.Object) field.ErrorList {
	oldBundle := old.(*certificates.ClusterTrustBundle)
	newBundle := new.(*certificates.ClusterTrustBundle)

	var allErrors field.ErrorList
	allErrors = append(allErrors, s.Validate(ctx, newBundle)...)
	allErrors = append(allErrors, apivalidation.ValidateObjectMetaUpdate(&newBundle.ObjectMeta, &oldBundle.ObjectMeta, field.NewPath("metadata"))...)

	if newBundle.Spec.SignerName != oldBundle.Spec.SignerName {
		allErrors = append(allErrors, field.Forbidden(field.NewPath("spec", "signerName"), "updates may not change the signer name"))
	}

	return allErrors
}

func (strategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

func (strategy) AllowUnconditionalUpdate() bool {
	return true
}

// normalizePEMTrustAnchors strips interblock data, strips in-block headers,
// reserializes the blocks to remove line-wrapping and padding differences, then
// sorts them alphabetically.
func normalizePEMTrustAnchors(in string) (string, error) {
	blockSet := map[string]bool{}

	// TODO(KEP-3257): Discuss how protective to be of downstream systems.
	// Should we verify that the PEM data parses as an X.509 certificate?

	rest := []byte(in)
	var b *pem.Block
	b, rest = pem.Decode(rest)
	for b != nil {
		if b.Type != "CERTIFICATE" {
			return "", fmt.Errorf("bad block type %q", b.Type)
		}

		reblocked := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b.Bytes,
		}

		blockSet[string(pem.EncodeToMemory(reblocked))] = true

		b, rest = pem.Decode(rest)
	}

	blockSlice := []string{}
	for block, _ := range blockSet {
		blockSlice = append(blockSlice, block)
	}

	sort.Strings(blockSlice)

	return strings.Join(blockSlice, "\n"), nil
}
