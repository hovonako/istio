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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
)

var cLog = log.RegisterScope("CustomCAClient", "Custom CA Integration Log", 0)

const (
	connectTimeout = 30 * time.Second
)

// CAClientOpts options
type CAClientOpts struct {
	CAAddr         string
	RootCertPath   string
	ClientKeyPath  string
	ClientCertPath string
	KeyCertBundle  util.KeyCertBundle
	RequestTimeout int
}

// CAClient generates keys and certificates for Istio identities.
type CAClient struct {
	opts         *CAClientOpts
	caClientConn *grpc.ClientConn
	pbClient     pb.IstioCertificateServiceClient
}

// NewCAClient returns a new CAClient instance.
func NewCAClient(opts *CAClientOpts) (*CAClient, error) {
	c := &CAClient{
		opts: opts,
	}
	err := c.connectToCustomCA()
	if err != nil {
		cLog.Errorf("can not connect to Custom CA Address: %v", err)
		return nil, fmt.Errorf("can not connect to Custom CA Address: %v", err)
	}

	return c, nil
}

func (c *CAClient) connectToCustomCA() error {

	rootCertBytes, err := ioutil.ReadFile(c.opts.RootCertPath)
	if err != nil {
		cLog.Errorf("read Root Cert at '%v' failed: %v", c.opts.RootCertPath, err)
		return fmt.Errorf("read Root Cert at '%v' failed: %v", c.opts.RootCertPath, err)
	}
	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(rootCertBytes)

	tlsCert, err := tls.LoadX509KeyPair(c.opts.ClientCertPath, c.opts.ClientKeyPath)
	if err != nil {
		cLog.Errorf("load TLS key pairs (%s,%s) failed: %v", c.opts.ClientCertPath, c.opts.ClientKeyPath, err)
		return fmt.Errorf("load TLS key pairs (%s,%s) failed: %v", c.opts.ClientCertPath, c.opts.ClientKeyPath, err)
	}
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCertPool,
	}
	credsTLS := credentials.NewTLS(clientTLSConfig)

	cLog.Infof("connect to custom CA addr: %s", c.opts.CAAddr)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credsTLS),
	}
	timeoutCtx, cancel := context.WithTimeout(context.TODO(), connectTimeout)
	defer cancel()
	grpcConn, err := grpc.DialContext(timeoutCtx, c.opts.CAAddr, opts...)

	if err != nil {
		cLog.Errorf("cannot dial grpc connect to %v: %v", c.opts.CAAddr, err)
		return fmt.Errorf("cannot dial grpc connect to %v: %v", c.opts.CAAddr, err)
	}

	c.caClientConn = grpcConn
	c.pbClient = pb.NewIstioCertificateServiceClient(grpcConn)
	cLog.Info("Custom CA connection is ready")
	return nil
}

func responseTimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	cLog.Infof("%s took %s", name, elapsed)
}

// CreateCertificate is similar to Sign but returns the leaf cert and the entire cert chain.
func (c *CAClient) CreateCertificate(ctx context.Context,
	req *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(c.opts.RequestTimeout)*time.Second)
	defer cancel()

	cLog.Infof("forwarding Workload's CSR to Custom CA server...")
	defer responseTimeTrack(time.Now(), "customCA.CreateCertificate")
	resp, err := c.pbClient.CreateCertificate(timeoutCtx, req)
	certChain := resp.GetCertChain()

	if err != nil {
		cLog.Errorf("cannot call CreateCertificate from Custom CA: %v", err)
		return nil, fmt.Errorf("cannot call CreateCertificate from Custom CA: %v", err)
	}

	if len(certChain) < 2 {
		cLog.Errorf("invalid certificate response: %v", resp.GetCertChain())
		return nil, fmt.Errorf("invalid certificate response: %v", resp.GetCertChain())
	}
	var responseCertChains []string

	certChainWithoutRoot := certChain[:len(certChain)-1]

	for _, cert := range certChainWithoutRoot {
		parsedCert, err := validateAndParseCert(cert)
		if err != nil {
			cLog.Errorf("response certificate from Custom CA is invalid: %v", err)
			return nil, fmt.Errorf("response certificate from Custom CA is invalid: %v", err)
		}
		responseCertChains = append(responseCertChains, parsedCert)
	}

	// Append current roots: Custom CA's root CA and Self signing's root CA
	rootCertBytes := c.opts.KeyCertBundle.GetRootCertPem()
	responseCertChains = append(responseCertChains, string(rootCertBytes))

	return &pb.IstioCertificateResponse{
		CertChain: responseCertChains,
	}, nil
}

func validateAndParseCert(cert string) (string, error) {
	defer responseTimeTrack(time.Now(), "validateAndParseCert")
	certBytes, _ := pem.Decode([]byte(cert))

	if certBytes == nil {
		return "", fmt.Errorf("decode cert is failed, invalid certificate: %v", cert)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes.Bytes,
	}

	c := pem.EncodeToMemory(block)
	return string(c), nil
}
