package workloadcertificatesigner

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"golang.org/x/time/rate"
	certsv1 "k8s.io/api/certificates/v1"
	certsv1alpha1 "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	certinformersv1alpha1 "k8s.io/client-go/informers/certificates/v1alpha1"
	"k8s.io/client-go/kubernetes"
	certlistersv1alpha1 "k8s.io/client-go/listers/certificates/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	defaultWorkloadCertificateSignerName = "kubernetes.io/default-workload-certificate"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type Controller struct {
	kc kubernetes.Interface

	wcLister certlistersv1alpha1.WorkloadCertificateLister
	wcSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	kubeAPIServerClientKeyPair        *dynamiccertificates.DynamicCertKeyPairContent
	defaultWorkloadCertificateKeyPair *dynamiccertificates.DynamicCertKeyPairContent
}

func New(kc kubernetes.Interface, wcInformer certinformersv1alpha1.WorkloadCertificateInformer, kubeAPIServerClientKeyPair, defaultWorkloadCertificateKeyPair *dynamiccertificates.DynamicCertKeyPairContent) *Controller {
	c := &Controller{
		kc: kc,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "workloadcertificate"),
		kubeAPIServerClientKeyPair:        kubeAPIServerClientKeyPair,
		defaultWorkloadCertificateKeyPair: defaultWorkloadCertificateKeyPair,
	}

	wcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := controller.KeyFunc(obj)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("couldn't get key for object: %w", err))
			}
			c.queue.Add(key)
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := controller.KeyFunc(new)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("couldn't get key for object: %w", err))
			}
			c.queue.Add(key)
		},
		DeleteFunc: func(obj interface{}) {
			key, err := controller.KeyFunc(obj)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("couldn't get key for object: %w", err))
			}
			c.queue.Add(key)
		},
	})

	c.wcLister = wcInformer.Lister()
	c.wcSynced = wcInformer.Informer().HasSynced

	return c
}

func (c *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.FromContext(ctx).Info("Starting WorkloadCertificate controller")
	defer klog.FromContext(ctx).Info("Shutting down WorkloadCertificate controller")

	if !cache.WaitForNamedCacheSync("workloadcertificate", ctx.Done(), c.wcSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.worker, time.Second)
	}

	<-ctx.Done()
}

func (c *Controller) worker(ctx context.Context) {
	for c.processNextWorkloadCertificate(ctx) {
	}
}

func (c *Controller) processNextWorkloadCertificate(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	logger := klog.FromContext(ctx)
	logger = klog.LoggerWithValues(logger, "WorkloadCertificate", key, "LoopID", mathrand.Uint64())
	ctx = klog.NewContext(ctx, logger)

	if err := c.handleWorkloadCertificate(ctx, key.(string)); err != nil {
		c.queue.AddRateLimited(key)
		logger.Error(err, "Failed to process WorkloadCertificate")
		return true
	}

	c.queue.Forget(key)
	return true

}

func (c *Controller) handleWorkloadCertificate(ctx context.Context, key string) error {
	logger := klog.FromContext(ctx)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("while splitting key: %w", err)
	}

	wc, err := c.wcLister.WorkloadCertificates(namespace).Get(name)
	if k8serrors.IsNotFound(err) {
		logger.Info("WorkloadCertificate was deleted before processing.  Nothing to do.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("while retrieving WorkloadCertificate from cache: %w", err)
	}

	// If the certificate was issued at the the current generation, then there's
	// nothing to do.
	if len(wc.Status.Certificate) != 0 && wc.Status.CertificateObservedGeneration == wc.ObjectMeta.Generation {
		logger.Info("WorkloadCertificate issued at current generation.  Nothing to do.")
		return nil
	}

	switch wc.Spec.SignerName {
	case certsv1.KubeAPIServerClientSignerName:
		if err := c.issueKubeAPIServerClientCert(ctx, wc); err != nil {
			return fmt.Errorf("while issuing certificate for %s: %w", certsv1.KubeAPIServerClientSignerName, err)
		}
	case certsv1alpha1.DefaultWorkloadCertificateSignerName:
		if err := c.issueDefaultWorkloadCertificate(ctx, wc); err != nil {
			return fmt.Errorf("while issuing certificate for %s: %w", defaultWorkloadCertificateSignerName, err)
		}
	default:
		// Not addressed to us.  Do nothing.
		logger.Info("Ignoring WorkloadCertificate because it is not addressed to us")
	}

	return nil
}

func (c *Controller) issueKubeAPIServerClientCert(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate) error {
	logger := klog.FromContext(ctx)

	// Don't modify the object we got from the shared informer cache.
	wc = wc.DeepCopy()

	certPEM, keyPEM := c.kubeAPIServerClientKeyPair.CurrentCertKeyContent()
	caCerts, err := cert.ParseCertsPEM(certPEM)
	if err != nil {
		return fmt.Errorf("while reading CA certificate file: %w", err)
	}
	if len(caCerts) != 1 {
		return fmt.Errorf("while reading CA certificate file: %d cert(s) found, one expected", len(caCerts))
	}
	caCert := caCerts[0]

	caPrivKey, err := keyutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("while reading CA key file: %w", err)
	}

	pubKeyObjs, err := keyutil.ParsePublicKeysPEM([]byte(wc.Spec.PublicKey))
	if err != nil {
		logger.Info("Failed to parse public key", "err", err)
		failedErr := c.setWCFailed(ctx, wc, "BadPublicKey", "Public key contained %d keys, wanted 1", len(pubKeyObjs))
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}
	if len(pubKeyObjs) != 1 {
		logger.Info("Public key contained %d keys, wanted 1", len(pubKeyObjs))
		failedErr := c.setWCFailed(ctx, wc, "BadPublicKey", "Public key contained %d keys, wanted 1", len(pubKeyObjs))
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}
	requestPubKey := pubKeyObjs[0]

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(24 * time.Hour)
	beginRenewAt := notBefore.Add(18 * time.Hour)

	tmpl, err := c.apiserverClientCertificateTemplate(ctx, wc, notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("while creating certificate template: %w", err)
	}

	issuedDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, requestPubKey, caPrivKey)
	if err != nil {
		logger.Error(err, "Failed to sign certificate")
		failedErr := c.setWCFailed(ctx, wc, "SigningFailure", "Failed to sign certificate: %v", err)
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}

	issuedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuedDER,
	})

	if err := c.setWCIssued(ctx, wc, string(issuedPEM), notBefore, notAfter, beginRenewAt); err != nil {
		// Things that can go wrong in this function are the same thing that can
		// go wrong with setting pending, so there's no point in trying to mark
		// the WC pending.
		return fmt.Errorf("while setting WorkloadCertificate issued: %w", err)
	}

	return nil
}

func (c *Controller) apiserverClientCertificateTemplate(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("while generating serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("system:serviceaccount:%s:%s", wc.ObjectMeta.Namespace, wc.Spec.ServiceAccount),
		},
		KeyUsage: x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	return tmpl, nil
}

func (c *Controller) issueDefaultWorkloadCertificate(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate) error {
	logger := klog.FromContext(ctx)

	// Don't modify the object we got from the shared informer cache.
	wc = wc.DeepCopy()

	certPEM, keyPEM := c.defaultWorkloadCertificateKeyPair.CurrentCertKeyContent()
	caCerts, err := cert.ParseCertsPEM(certPEM)
	if err != nil {
		return fmt.Errorf("while reading CA certificate file: %w", err)
	}
	if len(caCerts) != 1 {
		return fmt.Errorf("while reading CA certificate file: %d cert(s) found, one expected", len(caCerts))
	}
	caCert := caCerts[0]

	caPrivKey, err := keyutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("while reading CA key file: %w", err)
	}

	pubKeyObjs, err := keyutil.ParsePublicKeysPEM([]byte(wc.Spec.PublicKey))
	if err != nil {
		logger.Info("Failed to parse public key", "err", err)
		failedErr := c.setWCFailed(ctx, wc, "BadPublicKey", "Public key contained %d keys, wanted 1", len(pubKeyObjs))
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}
	if len(pubKeyObjs) != 1 {
		logger.Info("Public key contained %d keys, wanted 1", len(pubKeyObjs))
		failedErr := c.setWCFailed(ctx, wc, "BadPublicKey", "Public key contained %d keys, wanted 1", len(pubKeyObjs))
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}
	requestPubKey := pubKeyObjs[0]

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(24 * time.Hour)
	beginRenewAt := notBefore.Add(18 * time.Hour)

	tmpl, err := c.defaultWorkloadCertificateTemplate(ctx, wc, notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("while creating certificate template: %w", err)
	}

	issuedDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, requestPubKey, caPrivKey)
	if err != nil {
		logger.Error(err, "Failed to sign certificate")
		failedErr := c.setWCFailed(ctx, wc, "SigningFailure", "Failed to sign certificate: %v", err)
		if failedErr != nil {
			return fmt.Errorf("while marking WorkloadCertificate failed: %w", failedErr)
		}
		return nil
	}

	issuedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuedDER,
	})

	if err := c.setWCIssued(ctx, wc, string(issuedPEM), notBefore, notAfter, beginRenewAt); err != nil {
		// Things that can go wrong in this function are the same thing that can
		// go wrong with setting pending, so there's no point in trying to mark
		// the WC pending.
		return fmt.Errorf("while setting WorkloadCertificate issued: %w", err)
	}

	return nil
}

func (c *Controller) defaultWorkloadCertificateTemplate(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("while generating serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("system:serviceaccount:%s:%s", wc.ObjectMeta.Namespace, wc.Spec.ServiceAccount),
		},
		KeyUsage: x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}

	return tmpl, nil
}

func (c *Controller) setWCFailed(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate, reason, format string, args ...any) error {
	// Clear Failed and Pending conditions
	newConditions := []certsv1alpha1.WorkloadCertificateCondition{}
	for _, cond := range wc.Status.Conditions {
		if cond.Type == certsv1alpha1.WorkloadCertificateFailed {
			continue
		}
		if cond.Type == certsv1alpha1.WorkloadCertificatePending {
			continue
		}
		newConditions = append(newConditions, cond)
	}
	wc.Status.Conditions = newConditions

	wc.Status.Conditions = append(wc.Status.Conditions, certsv1alpha1.WorkloadCertificateCondition{
		Type:               certsv1alpha1.WorkloadCertificateFailed,
		Status:             corev1.ConditionTrue,
		ObservedGeneration: wc.ObjectMeta.Generation,
		Reason:             reason,
		Message:            fmt.Sprintf(format, args...),
	})

	_, err := c.kc.CertificatesV1alpha1().WorkloadCertificates(wc.ObjectMeta.Namespace).UpdateStatus(ctx, wc, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating status: %w", err)
	}

	return nil
}

func (c *Controller) setWCIssued(ctx context.Context, wc *certsv1alpha1.WorkloadCertificate, issuedPEM string, notBefore, notAfter, beginRefreshAt time.Time) error {
	wc.Status.Certificate = issuedPEM
	wc.Status.CertificateObservedGeneration = wc.ObjectMeta.Generation
	wc.Status.NotBefore = metav1.Time{Time: notBefore}
	wc.Status.NotAfter = metav1.Time{Time: notAfter}
	wc.Status.BeginRefreshAt = metav1.Time{Time: beginRefreshAt}

	// Clear Failed and Pending conditions
	newConditions := []certsv1alpha1.WorkloadCertificateCondition{}
	for _, cond := range wc.Status.Conditions {
		if cond.Type == certsv1alpha1.WorkloadCertificateFailed {
			continue
		}
		if cond.Type == certsv1alpha1.WorkloadCertificatePending {
			continue
		}
		newConditions = append(newConditions, cond)
	}
	wc.Status.Conditions = newConditions

	_, err := c.kc.CertificatesV1alpha1().WorkloadCertificates(wc.ObjectMeta.Namespace).UpdateStatus(ctx, wc, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating status: %w", err)
	}

	return nil
}
