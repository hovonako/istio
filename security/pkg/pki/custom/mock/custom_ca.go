package mock

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "istio.io/api/security/v1alpha1"
)

// FakeExternalCA fake gRPC server for Istio Signing API
type FakeExternalCA struct {
	pb.UnimplementedIstioCertificateServiceServer
	g            *grpc.Server
	workloadCert string
	rootCert     string
}

// NewFakeExternalCA create fake gRPC server for Istio Signing API
func NewFakeExternalCA(serverCert string, serverKey string, rootCert string,
	workloadCertFile string) (*FakeExternalCA, error) {
	certificate, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, err
	}

	rootCAs := x509.NewCertPool()
	rootBytes, err := ioutil.ReadFile(rootCert)
	if err != nil {
		return nil, err
	}

	if ok := rootCAs.AppendCertsFromPEM(rootBytes); !ok {
		return nil, fmt.Errorf("cannot read root cert from: %v", rootCert)
	}

	workloadCert, err := ioutil.ReadFile(workloadCertFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}

	f := &FakeExternalCA{
		g:            grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig))),
		rootCert:     string(rootBytes),
		workloadCert: string(workloadCert),
	}
	pb.RegisterIstioCertificateServiceServer(f.g, f)
	return f, nil
}

// Serve start listen on random port
func (f *FakeExternalCA) Serve() (net.Addr, error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	go func() {
		err := f.g.Serve(lis)
		fmt.Println(fmt.Errorf("error on start Fake CA Server: %v", err))
	}()

	return lis.Addr(), nil
}

// Stop stop grpc server
func (f *FakeExternalCA) Stop() {
	f.g.Stop()
}

// CreateCertificate fake response cert chain
func (f *FakeExternalCA) CreateCertificate(ctx context.Context,
	req *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {

	time.Sleep(2 * time.Second)

	return &pb.IstioCertificateResponse{
		CertChain: []string{f.workloadCert, f.rootCert},
	}, nil
}
