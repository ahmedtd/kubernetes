package storage

import (
	"fmt"

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
	"k8s.io/kubernetes/pkg/registry/certificates/clustertrustbundle"
)

// REST is a RESTStorage for ClusterTrustBundle.
type REST struct {
	*genericregistry.Store
}

// NewREST returns a RESTStorage object for ClusterTrustBundle objects.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, error) {
	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &api.ClusterTrustBundle{} },
		NewListFunc:              func() runtime.Object { return &api.ClusterTrustBundleList{} },
		DefaultQualifiedResource: api.Resource("clustertrustbundles"),

		CreateStrategy: clustertrustbundle.Strategy,
		UpdateStrategy: clustertrustbundle.Strategy,
		DeleteStrategy: clustertrustbundle.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    getAttrs,
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}
	return &REST{store}, nil
}

var _ rest.ShortNamesProvider = &REST{}

// ShortNames returns a list of short names for ClusterTrustBundle.
//
// Implements the ShortNamesProvider interface.
func (r *REST) ShortNames() []string {
	return []string{"ctb"}
}

func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	bundle, ok := obj.(*api.ClusterTrustBundle)
	if !ok {
		return nil, nil, fmt.Errorf("not a clustertrustbundle")
	}

	selectableFields := generic.MergeFieldsSets(generic.ObjectMetaFieldsSet(&bundle.ObjectMeta, false), fields.Set{
		"spec.signerName": bundle.Spec.SignerName,
	})

	return labels.Set(bundle.Labels), selectableFields, nil
}
