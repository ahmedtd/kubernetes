package wcrestriction

import (
	"context"
	"fmt"
	"io"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/informers"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/component-base/featuregate"
	api "k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/plugin/pkg/admission/certificates"
)

const PluginName = "WorkloadCertificateRestriction"

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

type Plugin struct {
	*admission.Handler
	authz authorizer.Authorizer

	inspectedFeatureGates bool
	enabled               bool

	podLister            corev1listers.PodLister
	serviceAccountLister corev1listers.ServiceAccountLister
}

var _ admission.MutationInterface = &Plugin{}
var _ admission.ValidationInterface = &Plugin{}

var _ admission.InitializationValidator = &Plugin{}

var _ genericadmissioninit.WantsExternalKubeInformerFactory = &Plugin{}
var _ genericadmissioninit.WantsAuthorizer = &Plugin{}
var _ genericadmissioninit.WantsFeatures = &Plugin{}

func NewPlugin() *Plugin {
	return &Plugin{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}

// SetExternalKubeInformerFactory sets the plugin's informer factory.
func (p *Plugin) SetExternalKubeInformerFactory(f informers.SharedInformerFactory) {
	podInformer := f.Core().V1().Pods()
	p.podLister = podInformer.Lister()

	serviceAccountInformer := f.Core().V1().ServiceAccounts()
	p.serviceAccountLister = serviceAccountInformer.Lister()

	p.SetReadyFunc(func() bool {
		return podInformer.Informer().HasSynced() && serviceAccountInformer.Informer().HasSynced()
	})
}

// SetAuthorizer sets the plugin's authorizer.
func (p *Plugin) SetAuthorizer(authz authorizer.Authorizer) {
	p.authz = authz
}

// InspectFeatureGates implements WantsFeatures.
func (p *Plugin) InspectFeatureGates(featureGates featuregate.FeatureGate) {
	p.enabled = featureGates.Enabled(features.WorkloadCertificate)
	p.inspectedFeatureGates = true
}

// ValidateInitialization checks if the plugin is fully initialized.
func (p *Plugin) ValidateInitialization() error {
	if p.authz == nil {
		return fmt.Errorf("%s requires an authorizer", PluginName)
	}
	if !p.inspectedFeatureGates {
		return fmt.Errorf("%s has not inspected feature gates", PluginName)
	}

	if p.podLister == nil {
		return fmt.Errorf("%s is missing its pod lister")
	}

	if p.serviceAccountLister == nil {
		return fmt.Errorf("%s is missing its service account lister")
	}

	return nil
}

var workloadCertificateGroupResource = api.Resource("workloadcertificates")

func (p *Plugin) Admit(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if !p.enabled {
		return nil
	}
	if a.GetResource().GroupResource() != workloadCertificateGroupResource {
		return nil
	}

	newWC, ok := a.GetObject().(*api.WorkloadCertificate)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type WorkloadCertificate, got: %T", a.GetOldObject()))
	}

	pod, err := p.podLister.Pods(newWC.ObjectMeta.Namespace).Get(newWC.Spec.Pod)
	if k8serrors.IsNotFound(err) {
		return admission.NewForbidden(a, fmt.Errorf("the named pod %s/%s does not exist in the cluster", newWC.ObjectMeta.Namespace, newWC.Spec.Pod))
	}
	if err != nil {
		return fmt.Errorf("while getting pod: %w", err)
	}
	if string(pod.ObjectMeta.UID) != newWC.Spec.PodUID {
		return admission.NewForbidden(a, fmt.Errorf("pod UID mismatch (pod has %s, workload certificate has %s)", string(pod.ObjectMeta.UID), newWC.Spec.PodUID))
	}

	newWC.Spec.ServiceAccount = pod.Spec.ServiceAccountName
	newWC.Spec.Node = pod.Spec.NodeName
	newWC.Spec.Requester = a.GetUserInfo().GetName()

	return nil
}

func (p *Plugin) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if !p.enabled {
		return nil
	}
	if a.GetResource().GroupResource() != workloadCertificateGroupResource {
		return nil
	}

	newWC, ok := a.GetObject().(*api.WorkloadCertificate)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type WorkloadCertificate, got: %T", a.GetOldObject()))
	}

	// TODO(KEP-WorkloadCertificates): mTLS lockdown check:  No one is allowed
	// to modify a WorkloadCertificate object if they authenticated with a
	// bearer token.

	// Requester lockdown check: After the WorkloadCertificate is created, no
	// one but the named requester may modify it, except via the /status subresource.
	if a.GetSubresource() == "" && a.GetUserInfo().GetName() != newWC.Spec.Requester {
		return admission.NewForbidden(a, fmt.Errorf("only the original requester %q may modify this WorkloadCertificate", newWC.Spec.Requester))
	}

	// If you want to use the status/ subresource, you have to have the "sign" verb on the signer.
	if a.GetSubresource() == "status" && !certificates.IsAuthorizedForSignerName(ctx, p.authz, a.GetUserInfo(), "sign", newWC.Spec.SignerName) {
		return admission.NewForbidden(a, fmt.Errorf("user not permitted to sign requests with signerName %q", newWC.Spec.SignerName))
	}

	// Node restriction check:
	//
	// 1. The WorkloadCertificate must refer to a pod currently running in the
	// cluster, and be consistent with it.
	//
	// 2. The requester must be related to the named node.  This could either
	// mean that they are using the node identity, or that they are a pod
	// running on that node.
	pod, err := p.podLister.Pods(newWC.ObjectMeta.Namespace).Get(newWC.Spec.Pod)
	if k8serrors.IsNotFound(err) {
		return admission.NewForbidden(a, fmt.Errorf("the named pod %s/%s does not exist in the cluster", newWC.ObjectMeta.Namespace, newWC.Spec.Pod))
	}
	if err != nil {
		return fmt.Errorf("while getting pod: %w", err)
	}
	if string(pod.ObjectMeta.UID) != newWC.Spec.PodUID {
		return admission.NewForbidden(a, fmt.Errorf("pod UID mismatch (pod has %s, workload certificate has %s)", string(pod.ObjectMeta.UID), newWC.Spec.PodUID))
	}
	if pod.Spec.ServiceAccountName != newWC.Spec.ServiceAccount {
		return admission.NewForbidden(a, fmt.Errorf("pod service account mismatch (pod has %s, workload certificate has %s)", pod.Spec.ServiceAccountName, newWC.Spec.ServiceAccount))
	}
	if pod.Spec.NodeName != newWC.Spec.Node {
		return admission.NewForbidden(a, fmt.Errorf("pod node mismatch (pod has %s, workload certificate has %s)", pod.Spec.NodeName, newWC.Spec.Node))
	}

	if strings.TrimPrefix(newWC.Spec.Requester, "system:node:") != newWC.Spec.Node {
		return admission.NewForbidden(a, fmt.Errorf("the requester %s is not related to node %s", newWC.Spec.Requester, newWC.Spec.Node))
	}
	// TODO(KEP-WorkloadCertificates): Allow daemonsets to request
	// WorkloadCertificates for pods on their nodes.

	return nil
}
