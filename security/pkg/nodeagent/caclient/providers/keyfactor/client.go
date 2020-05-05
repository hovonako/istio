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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	caClientInterface "istio.io/istio/security/pkg/nodeagent/caclient/interface"
	"istio.io/pkg/env"
	"istio.io/pkg/log"
)

var (
	keyFactorCAClientLog    = log.RegisterScope("keyfactor", "KeyFactor CA client debugging", 0)
	certificateAuthorityENV = env.RegisterStringVar("KEYFACTOR_CA", "", "Name of certificate")
	authTokenENV            = env.RegisterStringVar("KEYFACTOR_AUTH_TOKEN", "", "Auth token of keyfactor")
	enrollCSRPathENV        = env.RegisterStringVar("KEYFACTOR_ENROLL_PATH", "/KeyfactorAPI/Enrollment/CSR", "API path of enroll certificate")
	certificateTemplateENV  = env.RegisterStringVar("KEYFACTOR_CA_TEMPLATE", "Istio", "Keyfactor certificate template")
	appKeyENV               = env.RegisterStringVar("KEYFACTOR_APPKEY", "", "KeyFactor Api Key")
)

// KeyfactorCAClientMetadata struct to carry metadata of Keyfactor Client
type KeyfactorCAClientMetadata struct {
	TrustDomain  string
	ClusterID    string
	PodNamespace string
	PodName      string
	PodIP        string
}

type keyFactorCAClient struct {
	caEndpoint   string
	enableTLS    bool
	client       *http.Client
	trustDomain  string
	clusterID    string
	podName      string
	podNamespace string
	podIP        string
}

type san struct {
	IP4 []string `json:"ip4"`
	DNS []string `json:"dns"`
}

type metadata struct {
	Cluster      string `json:"Cluster"`
	Service      string `json:"Service"`
	PodName      string `json:"PodName"`
	PodNamespace string `json:"PodNamespace"`
}

type keyfactorRequestPayload struct {
	CSR                  string   `json:"CSR"`
	CertificateAuthority string   `json:"CertificateAuthority"`
	IncludeChain         bool     `json:"IncludeChain"`
	TimeStamp            string   `json:"TimeStamp"`
	Template             string   `json:"Template"`
	SANs                 san      `json:"SANs"`
	Metadata             metadata `json:"Metadata"`
}

// KeyfactorResponse response structure for keyfactor server
type keyfactorResponse struct {
	CertificateInformation struct {
		SerialNumber       string      `json:"SerialNumber"`
		IssuerDN           string      `json:"IssuerDN"`
		Thumbprint         string      `json:"Thumbprint"`
		KeyfactorID        int         `json:"KeyfactorID"`
		KeyfactorRequestID int         `json:"KeyfactorRequestId"`
		Certificates       []string    `json:"Certificates"`
		RequestDisposition string      `json:"RequestDisposition"`
		DispositionMessage string      `json:"DispositionMessage"`
		EnrollmentContext  interface{} `json:"EnrollmentContext"`
	} `json:"CertificateInformation"`
}

// NewKeyFactorCAClient create a CA client for KeyFactor CA.
func NewKeyFactorCAClient(endpoint string, tls bool, rootCert []byte, metadata *KeyfactorCAClientMetadata) (caClientInterface.Client, error) {

	if certificateAuthorityENV.Get() == "" {
		return nil, fmt.Errorf("Missing KEYFACTOR_CA env, config at global.keyfactor.ca")
	}

	if authTokenENV.Get() == "" {
		return nil, fmt.Errorf("Missing KEYFACTOR_AUTH_TOKEN, config at global.keyfactor.authToken")
	}

	if appKeyENV.Get() == "" {
		return nil, fmt.Errorf("Missing KEYFACTOR_APPKEY, config at global.keyfactor.appKey")
	}

	c := &keyFactorCAClient{
		caEndpoint:   endpoint,
		enableTLS:    tls,
		podName:      metadata.PodName,
		clusterID:    metadata.ClusterID,
		podNamespace: metadata.PodNamespace,
		podIP:        metadata.PodIP,
	}

	if !tls {
		c.client = &http.Client{
			Timeout: time.Second * 10,
		}
	} else {
		c.client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	return c, nil
}

// CSRSign calls KeyFactor CA to sign a CSR.
func (cl *keyFactorCAClient) CSRSign(ctx context.Context, reqID string, csrPEM []byte, subjectID string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {

	serviceName := cl.podName

	if splitPodName := strings.Split(cl.podName, "-"); len(splitPodName) > 2 {

		// example: service-name-A-v1-roiwe0239-24jfef9 => service-name-A-v1
		arrayOfServiceNames := splitPodName[0 : len(splitPodName)-2]
		serviceName = strings.Join(arrayOfServiceNames, "-")
	}

	keyFactorCAClientLog.Infof("- Start sign CSR for service: (%s), in namespace: (%s)", serviceName, cl.podNamespace)

	bytesRepresentation, err := json.Marshal(keyfactorRequestPayload{
		CSR:                  string(csrPEM),
		CertificateAuthority: certificateAuthorityENV.Get(),
		IncludeChain:         true,
		Template:             certificateTemplateENV.Get(),
		TimeStamp:            time.Now().Format(time.RFC3339),
		SANs: san{
			DNS: []string{cl.trustDomain},
			IP4: []string{cl.podIP},
		},
		Metadata: metadata{
			Cluster:      cl.clusterID,
			Service:      serviceName,
			PodName:      cl.podName,
			PodNamespace: cl.podNamespace,
		},
	})

	enrollCSRPath := enrollCSRPathENV.Get()

	requestCSR, err := http.NewRequest("POST", cl.caEndpoint+enrollCSRPath, bytes.NewBuffer(bytesRepresentation))

	if err != nil {
		return nil, fmt.Errorf("Cannot create request with url: %v", cl.caEndpoint+enrollCSRPath)
	}

	requestCSR.Header.Set("authorization", authTokenENV.Get())
	requestCSR.Header.Set("x-keyfactor-requested-with", "APIClient")
	requestCSR.Header.Set("x-Keyfactor-appKey", appKeyENV.Get())
	requestCSR.Header.Set("x-certificateformat", "PEM")
	requestCSR.Header.Set("Content-Type", "application/json")

	if err != nil {
		keyFactorCAClientLog.Errorf("Request to keyfactor is invalid: %v", err)
		return nil, fmt.Errorf("Request to keyfactor is invalid: %v", err)
	}

	res, err := cl.client.Do(requestCSR)
	if err != nil {
		return nil, fmt.Errorf("Could not request to KeyfactorCA server: %v", err)
	}
	defer res.Body.Close()
	status := res.StatusCode

	if status == http.StatusOK {
		jsonResponse := &keyfactorResponse{}
		json.NewDecoder(res.Body).Decode(&jsonResponse)
		return getCertFromResponse(jsonResponse), nil
	}

	var errorMessage interface{}
	json.NewDecoder(res.Body).Decode(&errorMessage)
	keyFactorCAClientLog.Errorf("Request failed with status: %v, message: %v", status, errorMessage)
	return nil, fmt.Errorf("Request failed with status: %v, message: %v", status, errorMessage)
}

func getCertFromResponse(jsonResponse *keyfactorResponse) []string {

	certChains := []string{}

	template := "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n"

	for _, i := range jsonResponse.CertificateInformation.Certificates {
		certChains = append(certChains, fmt.Sprintf(template, i))
	}

	keyFactorCAClientLog.Infof("- Keyfactor response %s certificates in certchain.", len(certChains))

	return certChains
}
