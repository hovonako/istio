package custom

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	"istio.io/api/security/v1alpha1"
	mock "istio.io/istio/security/pkg/pki/custom/mock"
	certutil "istio.io/istio/security/pkg/pki/util"
)

const (
	customServerCert   = "testdata/custom-certs/server-cert.pem"
	customServerKey    = "testdata/custom-certs/server-key.pem"
	customClientCert   = "testdata/custom-certs/client-cert.pem"
	customClientKey    = "testdata/custom-certs/client-key.pem"
	customRootCert     = "testdata/custom-certs/root-cert.pem"
	customWorkloadCert = "testdata/custom-certs/workload-cert-chain.pem"
	mixingRootCerts    = "testdata/mixing-custom-istio-root.pem"

	// contains ECC root-cert and custom ca root-cert.
	// to verify spiffe peer
	mixingECCRootCerts = "testdata/mixing-custom-ecc-root.pem"

	selfGenRoot = "testdata/istio-certs/root-cert.pem"
)

func TestCreateCustomCAClient(t *testing.T) {

	g := NewWithT(t)
	fakeServer, err := mock.NewFakeExternalCA(customServerCert, customServerKey, customRootCert, customWorkloadCert)
	g.Expect(err).To(BeNil())
	addr, err := fakeServer.Serve()
	g.Expect(err).To(BeNil())
	keyCertBundle, err := certutil.NewKeyCertBundleWithRootCertFromFile(mixingRootCerts)
	g.Expect(err).ShouldNot(HaveOccurred())
	testCases := map[string]struct {
		clientCertPath              string
		clientKeyPath               string
		rootCertPath                string
		caAddr                      string
		connectExpectError          string
		createCertficateExpectError string
	}{
		"valid client certificate: should successful": {
			clientCertPath: customClientCert,
			clientKeyPath:  customClientKey,
			rootCertPath:   customRootCert,
			caAddr:         addr.String(),
		},
		"Missing client certificate: should failed": {
			clientCertPath:     "./missing.pem",
			clientKeyPath:      "./missing.pem",
			rootCertPath:       customRootCert,
			caAddr:             addr.String(),
			connectExpectError: "can not connect to Custom CA Address: load TLS key pairs (./missing.pem,./missing.pem) failed: open ./missing.pem: no such file or directory",
		},
		"Missing root certificate: should failed": {
			clientCertPath: customClientCert,
			clientKeyPath:  customClientKey,
			rootCertPath:   "./missing-root.pem",
			caAddr:         addr.String(),
			connectExpectError: "can not connect to Custom CA Address: read Root Cert at " +
				"'./missing-root.pem' failed: open ./missing-root.pem: no such file or directory",
		},
		"Invalid root certificate: should failed": {
			clientCertPath: customClientCert,
			clientKeyPath:  customClientKey,
			rootCertPath:   "testdata/istio-certs/root-cert.pem",
			caAddr:         addr.String(),
			createCertficateExpectError: "cannot call CreateCertificate from Custom CA:" +
				" rpc error: code = Unavailable desc = connection error: desc = \"transport:" +
				" authentication handshake failed: x509: certificate signed by unknown authority " +
				"(possibly because of \\\"crypto/rsa: verification error\\\" while trying to verify " +
				"candidate authority certificate \\\"Root CA\\\")\"",
		},
		"Invalid client certificate: should failed": {
			clientCertPath: "testdata/istio-certs/workload-cert.pem",
			clientKeyPath:  "testdata/istio-certs/workload-key.pem",
			rootCertPath:   customRootCert,
			caAddr:         addr.String(),
			createCertficateExpectError: "cannot call CreateCertificate from Custom CA: rpc error:" +
				" code = Unavailable desc = connection closed",
		},
	}

	for id, tc := range testCases {
		t.Run(id, func(tsub *testing.T) {
			gsub := NewWithT(tsub)

			c, err := NewCAClient(&CAClientOpts{
				CAAddr:         addr.String(),
				KeyCertBundle:  keyCertBundle,
				RootCertPath:   tc.rootCertPath,
				ClientCertPath: tc.clientCertPath,
				ClientKeyPath:  tc.clientKeyPath,
				RequestTimeout: 5,
			})

			if tc.connectExpectError != "" {
				gsub.Expect(err).To(MatchError(tc.connectExpectError))
				return
			} else {
				gsub.Expect(err).To(BeNil())
			}

			_, err = c.CreateCertificate(context.TODO(), &v1alpha1.IstioCertificateRequest{
				Csr: "FAKE_CSR",
			})

			if tc.createCertficateExpectError != "" {
				gsub.Expect(err).To(MatchError(tc.createCertficateExpectError))
				return
			} else {
				gsub.Expect(err).To(BeNil())
			}
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	g := NewWithT(t)
	fakeServer, err := mock.NewFakeExternalCA(customServerCert, customServerKey, customRootCert, customWorkloadCert)
	g.Expect(err).To(BeNil())
	addr, err := fakeServer.Serve()
	g.Expect(err).To(BeNil())
	keyCertBundle, err := certutil.NewKeyCertBundleWithRootCertFromFile(mixingRootCerts)
	g.Expect(err).ShouldNot(HaveOccurred())

	c, err := NewCAClient(&CAClientOpts{
		CAAddr:         addr.String(),
		KeyCertBundle:  keyCertBundle,
		RootCertPath:   customRootCert,
		ClientCertPath: customClientCert,
		ClientKeyPath:  customClientKey,
		RequestTimeout: 5,
	})

	r, err := c.CreateCertificate(context.TODO(), &v1alpha1.IstioCertificateRequest{
		Csr: "FAKE_CSR",
	})

	g.Expect(err).ShouldNot(HaveOccurred())

	g.Expect(r.GetCertChain()).To(HaveLen(2))
	g.Expect(r.GetCertChain()).To(ContainElements(string(keyCertBundle.GetRootCertPem())))
}
