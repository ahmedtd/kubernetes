package clustertrustbundle

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/certificates"
)

const validCert1 = `
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUUW9bIIsHU61w3yQR6amBuVvRFvcwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCeHgxCjAIBgNVBAgMAXgxCjAIBgNVBAcMAXgxCjAIBgNV
BAoMAXgxCjAIBgNVBAsMAXgxCzAJBgNVBAMMAmNhMRAwDgYJKoZIhvcNAQkBFgF4
MB4XDTIyMTAxODIzNTIyNFoXDTIzMTAxODIzNTIyNFowXDELMAkGA1UEBhMCeHgx
CjAIBgNVBAgMAXgxCjAIBgNVBAcMAXgxCjAIBgNVBAoMAXgxCjAIBgNVBAsMAXgx
CzAJBgNVBAMMAmNhMRAwDgYJKoZIhvcNAQkBFgF4MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4PeK4SmlsNwpw97gTtjODQytUfyqhBIwdENwJUbc019Y
m3VTCRLCGXjUa22mV6/j7V+mZw114ePFYTiGAH+2dUzWAZOphvtzE5ttPuv6A6Zx
k2J69lNFwJ2fPd7XQIH7pEIXjiEBaszxKZKMsN9+jOGu6iFFAwYLMemFYDbZHuqb
OwdQcSEsy5wO2ANzFRuYzGXuNcS8jYLHftE8g2P+L0wXnV9eW6/lM2ZFxS/nzDJz
qtzrEvQrBsmskTNC8gCRRZ7askp3CVdPKjC90sxAPwhpi8JjJZxSe1Bn/WRHUz82
GFytEIJNx9hJY2GI316zkxgTbsxfRQe4QLJN7sRtpwIDAQABo1MwUTAdBgNVHQ4E
FgQU9FGsI8t+cu68fGkhtvO9FtUd174wHwYDVR0jBBgwFoAU9FGsI8t+cu68fGkh
tvO9FtUd174wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAqDIp
In5h2xZfEZcijT3mjfG8Bo6taxM2biy1M7wEpmDrElmrjMLsflZepcjgkSoVz9hP
cSX/k9ls1zy1H799gcjs+afSpIa1N0nUIxAKF1RHsFa+dvXpSA8YdhUnbEcBnqx0
vN2nDBFpdCSNf+EXNEj12+9ZJm6TLzx22f9vHyRCg4D36X3Rj1FCBWxhf0mSt3ek
5px3H53Xu42MqzZCiJc8/m+IqZHaixZS4bsayssaxif2fNxzAIZhgTygo8P8QGjI
rUmstMbg4PPq62x1yLAxEo+8XCg05saWZs384JE+K1SDqxobm51EROWVwi8jUrNC
9nojtkQ+jDZD+1Stiw==
-----END CERTIFICATE-----
`

const validCert2 = `
-----BEGIN CERTIFICATE-----
MIIC/jCCAeagAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
cm5ldGVzMB4XDTIyMTAxOTIzMTY0MFoXDTMyMTAxNjIzMTY0MFowFTETMBEGA1UE
AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO+k
zbj35jHIjCd5mxP1FHMwMtvLFPeKUjtaLDP9Bs2jZ97Igmr7NTysn9QZkRP68/XX
j993Y8tOLg71N4vRggWiYP+T9Xfo0uHZJmzADKx5XkuC4Gqv79dUdb8IKfAbX9HB
ffGmWRnZLLTu8Bv/vfyl0CfE64a57DK+CzNJDwdK46CYYUnEH6Wb9finYrMQ+PLG
Oi2c0J4KAYc1WTId5npNwouzf/IMD33PvuXfE7r+/pDbP8u/X03e7U0cc9l7KRxr
3gpRQemCG74yRuy1dd3lJ1YCD8q96xVVZimGebnJ0IHi+lORRa2ix/o3OzW3FaP+
6kzHU6VnBRDr2rAhMh0CAwEAAaNZMFcwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFGUVOLM74t1TVoZjifsLl3Rwt1A6MBUGA1UdEQQO
MAyCCmt1YmVybmV0ZXMwDQYJKoZIhvcNAQELBQADggEBANHnPVDemZqRybYPN1as
Ywxi3iT1I3Wma1rZyxTWeIq8Ik0gnyvbtCD1cFB/5QU1xPW09YnmIFM/E73RIeWT
RmCNMgOGmegYxBQRe4UvmwWGJzKNA66c0MBmd2LDHrQlrvdewOCR667Sm9krsGt1
tS/t6N/uBXeRSkXKEDXa+jOpYrV3Oq3IntG6zUeCrVbrH2Bs9Ma5fU00TwK3ylw5
Ww8KzYdQaxxrLaiRRtFcpM9dFH/vwxl1QUa5vjHcmUjxmZunEmXKplATyLT0FXDw
JAo8AuwuuwRh2o+o8SxwzzA+/EBrIREgcv5uIkD352QnfGkEvGu6JOPGZVyd/kVg
KA0=
-----END CERTIFICATE-----
`

func TestValidate(t *testing.T) {
	testCases := []struct {
		description string
		bundle      *certificates.ClusterTrustBundle
		wantErrors  field.ErrorList
	}{
		{
			description: "valid, no signer name",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					PEMTrustAnchors: validCert1,
				},
			},
		},
		{
			description: "valid, with signer name",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1,
				},
			},
		},
		{
			description: "invalid, no signer name, no trust anchors",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"),
			},
		},
		{
			description: "invalid, no trust anchors",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName: "k8s.io/foo",
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"),
			},
		},
		{
			description: "invalid, bad signer name",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "invalid",
					PEMTrustAnchors: validCert1,
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "signerName"), "invalid", "must be a fully qualified domain and path of the form 'example.com/signer-name'"),
			},
		},
		{
			description: "invalid, no blocks",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					PEMTrustAnchors: "non block garbage",
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"),
			},
		},
		{
			description: "invalid, bad block",
			bundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					PEMTrustAnchors: validCert1 + "\n" + "-----BEGIN NOTACERTIFICATE-----\nYWJjCg==\n-----END NOTACERTIFICATE-----",
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "contains an invalid block"),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			ctx := context.Background()
			gotErrors := Strategy.Validate(ctx, tc.bundle)
			if diff := cmp.Diff(gotErrors, tc.wantErrors); diff != "" {
				t.Errorf("Unexpected error output from Validate; diff (-got +want)\n%s", diff)
			}

			// ValidateUpdate should also apply the same checks to the new object.
			tc.bundle.ObjectMeta.ResourceVersion = "1"
			newBundle := tc.bundle.DeepCopy()
			newBundle.ObjectMeta.ResourceVersion = "2"
			gotErrors = Strategy.ValidateUpdate(ctx, tc.bundle, newBundle)
			if diff := cmp.Diff(gotErrors, tc.wantErrors); diff != "" {
				t.Errorf("Unexpected error output from ValidateUpdate; diff (-got +want)\n%s", diff)
			}

			// TODO(KEP-3257): Test canonicalization if it turns out to be OK to
			// do canonicalization in validation.
		})
	}
}

func TestWarningsOnCreate(t *testing.T) {
	if warnings := Strategy.WarningsOnCreate(context.Background(), &certificates.ClusterTrustBundle{}); warnings != nil {
		t.Errorf("Got %v, want nil", warnings)
	}
}

func TestAllowCreateOnUpdate(t *testing.T) {
	if Strategy.AllowCreateOnUpdate() != false {
		t.Errorf("Got true, want false")
	}
}

func TestValidateUpdate(t *testing.T) {
	testCases := []struct {
		description          string
		oldBundle, newBundle *certificates.ClusterTrustBundle
		wantErrors           field.ErrorList
	}{
		{
			description: "changing signer name disallowed",
			oldBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1,
				},
			},
			newBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/bar",
					PEMTrustAnchors: validCert1,
				},
			},
			wantErrors: field.ErrorList{
				field.Forbidden(field.NewPath("spec", "signerName"), "updates may not change the signer name"),
			},
		},
		{
			description: "adding certificate allowed",
			oldBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1,
				},
			},
			newBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1 + "\n" + validCert2,
				},
			},
		},
		{
			description: "emptying pemTrustAnchors disallowed",
			oldBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1,
				},
			},
			newBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: "",
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"),
			},
		},
		{
			description: "emptying pemTrustAnchors (replace with non-block garbage) disallowed",
			oldBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: validCert1,
				},
			},
			newBundle: &certificates.ClusterTrustBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: certificates.ClusterTrustBundleSpec{
					SignerName:      "k8s.io/foo",
					PEMTrustAnchors: "non block garbage",
				},
			},
			wantErrors: field.ErrorList{
				field.Invalid(field.NewPath("spec", "pemTrustAnchors"), "<pemTrustAnchors after normalization>", "at least one trust anchor must be provided"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tc.oldBundle.ObjectMeta.ResourceVersion = "1"
			tc.newBundle.ObjectMeta.ResourceVersion = "2"
			gotErrors := Strategy.ValidateUpdate(context.Background(), tc.newBundle, tc.oldBundle)
			if diff := cmp.Diff(gotErrors, tc.wantErrors); diff != "" {
				t.Errorf("Unexpected error output from ValidateUpdate; diff (-got +want)\n%s", diff)
			}
		})
	}
}

func TestWarningsOnUpdate(t *testing.T) {
	if warnings := Strategy.WarningsOnUpdate(context.Background(), &certificates.ClusterTrustBundle{}, &certificates.ClusterTrustBundle{}); warnings != nil {
		t.Errorf("Got %v, want nil", warnings)
	}
}

func TestAllowUnconditionalUpdate(t *testing.T) {
	if Strategy.AllowUnconditionalUpdate() != true {
		t.Errorf("Got false, want true")
	}
}
