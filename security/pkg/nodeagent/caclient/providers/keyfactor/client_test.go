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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/net/context"

	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
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
