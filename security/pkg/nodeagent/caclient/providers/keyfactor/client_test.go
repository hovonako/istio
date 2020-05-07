// Copyright 2020 Istio Authors
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

package caclient

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/net/context"

	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
)

var (
	rootCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIFFDCCAvygAwIBAgIUNvN+0FmOtgNTyjKK730i4JgPDeMwDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMTkxMDI4
MTkzMjQxWhcNMjkxMDI1MTkzMjQxWjAiMQ4wDAYDVQQKDAVJc3RpbzEQMA4GA1UE
AwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdaPD8I
ft/fFkqdLiBBQPTLhozaeGkEkGhBsXkoHw38CCdeaRekGOoZI58Ce/iOjCIACEZo
n1Y6SKYnl4FqPFjOy3uF0ZFMeCt8GA+QrlPdEfkDAnj3FFc+C1THov0R+FCv2Qrs
FR0I6OZen+CVWS53xQNagxfBi9XeFI833gKr8Qiv0WOJKuoTY3abw8FJKyPPHX4O
RnqLDwEr8BRQyqgWCQPGGL+quGV22dfI8tVxmj0lXR3fJs3kuNagCoCSSnpJSjGi
eYy80i+esUO0RCNLoA78ia9bua5juyU6sUZca7Yk28cbz29niaT79iB02vQI+U8x
DL11eq7Wg6zsUhTrzIwJKCMyhsQCEYmrYIfv3STqkxzdiePnyjGXorX3mVZsNAxT
fwerb5rGdNm8QVa+LgRMPZmLlRiMjGkut3O0S76bPthbp7dgAiYXfmHlucmrCs80
E8qpPpceZUqEHbK9IUmHeecvl3oSx2H7ym4id1dq55eyQXk7DiZbo0yciGsIhytF
PLXDpeop4r67vZfsn9EqWed8XH7PBGdZMkDH5gMp1OaO/gHmIf/qnCYB6wJOKk7z
+Dol7sggwy+KwU+gjINbJwvFX/3pwY5cIza4Ds2B7oUe4hohZo2HzCd+RaTPNM03
DDyQmKcLhwt3K5oZFVceK6rCOpWzMq7upXPVAgMBAAGjQjBAMB0GA1UdDgQWBBQ3
3/NM2B73DIxoRC4zlw9YP0kP0DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIC5DANBgkqhkiG9w0BAQsFAAOCAgEAxbDDFmN84kPtl0dmAPbHqZRNkZkcZQ2n
M0i7ABVpaj9FH1zG4HeLxKyihfdHpF4N6aR95tmyzJd2OKSC1CiPDF85Lgc/+OdO
U2NRijl3wzcl2yqza1ChQK/clKkKFn4+WQgzBJbtiOmqD8NojJlw3juKclK25SAH
94bCksJg2Z834lsQY9cDIzqEackt/1NAa1IboZTQsJXzLZ9jAxv3TJWGapG7qHc5
5ojcm4h2WbDXoKWCBSU8Z2rFjT48x3YONjwWB7BPUdEOTwdbtpLoTDRFhUZttM9U
ovpsLTMumzUqmaI+2Q0gPVjQo4wvBPeouhEc2KYlvD6U7BrVz2JqEgSmsdJR4wNJ
sBf2kBuqdGiWCbDuGeJBGDc48jAmqvKdaljkt4IFigYuRUx8NFgvichbkpU/ZfuQ
CVpValVTXe7GMJadMnXLsoXMU1z57dbEdarej6TiCymOeIJ9oJF0g9ppNqq6NRnL
Y7pH4lN1U8lHxa52uPZ5HNsld3+fFKNq1tgbNhQ1Q9gn7nLalTsAr4RZJN9QMnse
k4OycvyY2i1iKYl5kcI2g38FzlIlALOrxd8nhQDBF5rRktfqp7t3HtKZubjkBwMQ
tP+N2C0otdj8D6IDHlT8OFr69n+PD4qR6P4bKxnjiYtEAqRvPlR96yrtjbdg/QgJ
0+aVGEMeDqg=
-----END CERTIFICATE-----`)
)

func TestCreateKeyfactorCSRRequest(t *testing.T) {
	mockServerChan := make(chan *httptest.Server)
	go func() {
		handler := http.NewServeMux()
		srv := httptest.NewServer(handler)
		mockServerChan <- srv
	}()

	mockServer := <-mockServerChan
	defer mockServer.Close()

	testCaseForEnvironments := map[string]struct {
		caAddr             string
		keyfactorCa        string
		keyfactorAuthToken string
		appKey             string
		expectedErr        string
	}{
		"Valid Env": {
			caAddr:             mockServer.URL,
			keyfactorCa:        "TestCAName",
			keyfactorAuthToken: "token12345",
			appKey:             "testAppKey",
			expectedErr:        "",
		},
		"Invalid Keyfactor CA name": {
			caAddr:             mockServer.URL,
			keyfactorAuthToken: "token12345",
			appKey:             "testAppKey",
			expectedErr:        "Missing KEYFACTOR_CA env, config at global.keyfactor.ca",
		},
		"Missing auth token": {
			caAddr:      mockServer.URL,
			keyfactorCa: "TestCAName",
			appKey:      "testAppKey",
			expectedErr: "Missing KEYFACTOR_AUTH_TOKEN, config at global.keyfactor.authToken",
		},
		"Missing appKey": {
			caAddr:             mockServer.URL,
			keyfactorCa:        "TestCAName",
			keyfactorAuthToken: "qweqweweqwq",
			expectedErr:        "Missing KEYFACTOR_APPKEY, config at global.keyfactor.appKey",
		},
	}

	for id, tc := range testCaseForEnvironments {
		t.Run(id, func(tsub *testing.T) {
			os.Setenv("KEYFACTOR_CA", tc.keyfactorCa)
			os.Setenv("KEYFACTOR_AUTH_TOKEN", tc.keyfactorAuthToken)
			os.Setenv("KEYFACTOR_APPKEY", tc.appKey)

			defer func() {
				os.Unsetenv("KEYFACTOR_CA")
				os.Unsetenv("KEYFACTOR_AUTH_TOKEN")
				os.Unsetenv("KEYFACTOR_APPKEY")
			}()

			_, err := NewKeyFactorCAClient(tc.caAddr, false, nil, &KeyfactorCAClientMetadata{})

			if err != nil {
				if err.Error() != tc.expectedErr {
					tsub.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErr)
				}
			}

		})
	}

}

func mockKeyfactorServer(mockCertChain []string, errChan chan error) *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/test/abc/xzy/CSRSign", func(w http.ResponseWriter, r *http.Request) {

		var requestBody keyfactorRequestPayload
		json.NewDecoder(r.Body).Decode(&requestBody)

		j, _ := json.Marshal(keyfactorResponse{})
		_, _ = w.Write(j)
	})

	srv := httptest.NewServer(handler)

	return srv
}

func TestKeyfactorWithTLSEnabled(t *testing.T) {

	testCases := map[string]struct {
		rootCert    []byte
		expectedErr string
	}{
		"Nil certificate": {
			rootCert:    nil,
			expectedErr: "",
		},
		"Valid certificate": {
			rootCert:    rootCertPEM,
			expectedErr: "Missing root-cert.pem with enableTLS = true",
		},

		"Invalid certificate": {
			rootCert:    []byte("Invaliddddddddd certificate"),
			expectedErr: fmt.Sprintf("Invalid root-cert.pem: %v", "Invaliddddddddd certificate"),
		},
	}

	for testID, tc := range testCases {
		t.Run(testID, func(tsub *testing.T) {

			os.Setenv("KEYFACTOR_CA", "werwerwe")
			os.Setenv("KEYFACTOR_AUTH_TOKEN", "reweqweqweqwre123")
			os.Setenv("KEYFACTOR_APPKEY", "QEWqweqeqweqw")
			defer func() {
				os.Unsetenv("KEYFACTOR_CA")
				os.Unsetenv("KEYFACTOR_AUTH_TOKEN")
				os.Unsetenv("KEYFACTOR_APPKEY")
			}()

			_, err := NewKeyFactorCAClient("", true, tc.rootCert, &KeyfactorCAClientMetadata{})
			if err != nil {
				if err.Error() != tc.expectedErr {
					tsub.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", testID, err.Error(), tc.expectedErr)
				}
			}
		})
	}

}

func TestKeyfactorSignCSR(t *testing.T) {
	options := pkiutil.CertOptions{
		Host:       "spiffe://cluster.local/ns/default/sa/default",
		RSAKeySize: 2048,
		Org:        "Istio Test",
		IsCA:       false,
		IsDualUse:  false,
		PKCS8Key:   false,
		TTL:        24 * time.Hour,
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, _, err := pkiutil.GenCSR(options)

	if err != nil {
		t.Errorf("Test case: failed to create CSRPem : %v", err)
	}

	cl, err := NewKeyFactorCAClient("https://kmstech.thedemodrive.com", false, nil, &KeyfactorCAClientMetadata{})
	certChain, errSign := cl.CSRSign(context.TODO(), "", csrPEM, "Istio", 6400)

	if errSign != nil {
		t.Errorf("CSRSign failed with errs: %v", errSign)

	}

	for _, cert := range certChain {
		if _, err := nodeagentutil.ParseCertAndGetExpiryTimestamp([]byte(cert)); err != nil {
			t.Errorf("Expect not error, but got: %v", err)
		}

		_, err := pem.Decode([]byte(cert))

		if err != nil {
			t.Errorf("Expect not error, but got: %v", err)
		}

	}
}
