package entrusting

import (
	"context"
	"fmt"
	"io"

	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/klog/v2"
	api "k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/plugin/pkg/admission/certificates"
)

const PluginName = "ClusterTrustBundleEntrusting"

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

// Plugin is the ClusterTrustBundle entrusting plugin.
type Plugin struct {
	*admission.Handler
	authz authorizer.Authorizer
}

var _ admission.ValidationInterface = &Plugin{}
var _ genericadmissioninit.WantsAuthorizer = &Plugin{}

func NewPlugin() *Plugin {
	return &Plugin{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}

// SetAuthorizer sets the plugin's authorizer.
func (p *Plugin) SetAuthorizer(authz authorizer.Authorizer) {
	p.authz = authz
}

// ValidateInitialization ensures an authorizer is set.
func (p *Plugin) ValidateInitialization() error {
	if p.authz == nil {
		return fmt.Errorf("%s requires an authorizer", PluginName)
	}
	return nil
}

var clusterTrustBundleGroupResource = api.Resource("clustertrustbundles")

func (p *Plugin) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetResource().GroupResource() != clusterTrustBundleGroupResource {
		return nil
	}

	newBundle, ok := a.GetObject().(*api.ClusterTrustBundle)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type ClusterTrustBundle, got: %T", a.GetOldObject()))
	}

	// Unlike CSRs, it's OK to validate against the *new* object, because
	// updates to signer name will be rejected during validation.  For defense
	// in depth, reject attempts to change signer at this layer as well.
	//
	// We want to use the new object because we also need to perform the signer
	// name permission check on *create*.

	if a.GetOperation() == admission.Update {
		oldBundle, ok := a.GetOldObject().(*api.ClusterTrustBundle)
		if !ok {
			return admission.NewForbidden(a, fmt.Errorf("expected type ClusterTrustBundle, got: %T", a.GetOldObject()))
		}

		if oldBundle.Spec.SignerName != newBundle.Spec.SignerName {
			return admission.NewForbidden(a, fmt.Errorf("changing signerName is forbidden"))
		}
	}

	// If signer name isn't specified, we don't need to perform the entrust
	// check.
	if newBundle.Spec.SignerName == "" {
		return nil
	}

	if !certificates.IsAuthorizedForSignerName(ctx, p.authz, a.GetUserInfo(), "entrust", newBundle.Spec.SignerName) {
		klog.V(4).Infof("user not permitted to entrust ClusterTrustBundle %q with signerName %q", newBundle.Name, newBundle.Spec.SignerName)
		return admission.NewForbidden(a, fmt.Errorf("user not permitted to entrust signerName %q", newBundle.Spec.SignerName))
	}

	return nil
}
