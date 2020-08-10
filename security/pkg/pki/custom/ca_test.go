// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package custom

import (
	"context"
	"testing"

	gomega "github.com/onsi/gomega"

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
)

func TestCreateCustomCAClient(t *testing.T) {

	g := gomega.NewWithT(t)
	fakeServer, err := mock.NewFakeExternalCA(customServerCert, customServerKey, customRootCert, customWorkloadCert)
	g.Expect(err).To(gomega.BeNil())

	addr, err := fakeServer.Serve()
	g.Expect(err).To(gomega.BeNil())
	defer fakeServer.Stop()

	keyCertBundle, err := certutil.NewKeyCertBundleWithRootCertFromFile(mixingRootCerts)
	g.Expect(err).ShouldNot(gomega.HaveOccurred())
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
			clientCertPath: "./missing.pem",
			clientKeyPath:  "./missing.pem",
			rootCertPath:   customRootCert,
			caAddr:         addr.String(),
			connectExpectError: "can not connect to Custom CA Address: load TLS key " +
				"pairs (./missing.pem,./missing.pem) failed: open ./missing.pem: no such file or directory",
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
			clientCertPath:              customClientCert,
			clientKeyPath:               customClientKey,
			rootCertPath:                "testdata/istio-certs/root-cert.pem",
			caAddr:                      addr.String(),
			createCertficateExpectError: "cannot call CreateCertificate from Custom CA: rpc error:",
		},
		"Invalid client certificate: should failed": {
			clientCertPath:              "testdata/istio-certs/workload-cert.pem",
			clientKeyPath:               "testdata/istio-certs/workload-key.pem",
			rootCertPath:                customRootCert,
			caAddr:                      addr.String(),
			createCertficateExpectError: "cannot call CreateCertificate from Custom CA: rpc error:",
		},
	}

	for id, tc := range testCases {
		t.Run(id, func(tsub *testing.T) {
			gsub := gomega.NewWithT(tsub)

			c, err := NewCAClient(&CAClientOpts{
				CAAddr:         addr.String(),
				KeyCertBundle:  keyCertBundle,
				RootCertPath:   tc.rootCertPath,
				ClientCertPath: tc.clientCertPath,
				ClientKeyPath:  tc.clientKeyPath,
				RequestTimeout: 5,
			})

			if tc.connectExpectError != "" {
				gsub.Expect(err).To(gomega.MatchError(tc.connectExpectError))
				return
			}
			gsub.Expect(err).To(gomega.BeNil())

			_, err = c.CreateCertificate(context.TODO(), &v1alpha1.IstioCertificateRequest{
				Csr: "FAKE_CSR",
			})

			if tc.createCertficateExpectError != "" {
				gsub.Expect(err).ToNot(gomega.BeNil())
				gsub.Expect(err.Error()).To(gomega.ContainSubstring(tc.createCertficateExpectError))
				return
			}
			gsub.Expect(err).To(gomega.BeNil())

		})
	}
}

func TestCreateCertificate(t *testing.T) {
	g := gomega.NewWithT(t)
	fakeServer, err := mock.NewFakeExternalCA(customServerCert, customServerKey, customRootCert, customWorkloadCert)
	g.Expect(err).To(gomega.BeNil())
	addr, err := fakeServer.Serve()
	g.Expect(err).To(gomega.BeNil())
	keyCertBundle, err := certutil.NewKeyCertBundleWithRootCertFromFile(mixingRootCerts)
	g.Expect(err).ShouldNot(gomega.HaveOccurred())

	c, err := NewCAClient(&CAClientOpts{
		CAAddr:         addr.String(),
		KeyCertBundle:  keyCertBundle,
		RootCertPath:   customRootCert,
		ClientCertPath: customClientCert,
		ClientKeyPath:  customClientKey,
		RequestTimeout: 5,
	})
	g.Expect(err).ShouldNot(gomega.HaveOccurred())

	r, err := c.CreateCertificate(context.TODO(), &v1alpha1.IstioCertificateRequest{
		Csr: "FAKE_CSR",
	})

	g.Expect(err).ShouldNot(gomega.HaveOccurred())

	g.Expect(r.GetCertChain()).To(gomega.HaveLen(2))
	g.Expect(r.GetCertChain()).To(gomega.ContainElements(string(keyCertBundle.GetRootCertPem())))
}
