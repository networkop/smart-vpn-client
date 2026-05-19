package pia

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// helper to create a CA and a server cert. serverNames can be empty to omit SANs.
func makeCerts(t *testing.T, serverName string, includeSAN bool) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// server cert
	srvKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if includeSAN && serverName != "" {
		srvTmpl.DNSNames = []string{serverName}
	}

	caCert, _ := x509.ParseCertificate(caDER)
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	return
}

func TestBuildPIAHTTPClient_StrictAndCNFallback(t *testing.T) {
	// Case 1: cert with matching SAN — should succeed.
	caPEM, certPEM, keyPEM := makeCerts(t, "test-server.local", true)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	c := &Client{caCert: caPEM}
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	remote := net.JoinHostPort(host, port)

	httpClient := c.buildPIAHTTPClient(remote, "test-server.local")
	resp, err := httpClient.Get("https://test-server.local/")
	if err != nil {
		t.Fatalf("expected success with matching SAN cert, got: %v", err)
	}
	resp.Body.Close()

	// Case 2: cert with SANs that don't match the requested name — should fail.
	caPEM2, certPEM2, keyPEM2 := makeCerts(t, "other.local", true)
	cert2, _ := tls.X509KeyPair(certPEM2, keyPEM2)
	srv2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte{})
	}))
	srv2.TLS = &tls.Config{Certificates: []tls.Certificate{cert2}}
	srv2.StartTLS()
	defer srv2.Close()

	c2 := &Client{caCert: caPEM2}
	host2, port2, _ := net.SplitHostPort(srv2.Listener.Addr().String())
	remote2 := net.JoinHostPort(host2, port2)
	httpClient2 := c2.buildPIAHTTPClient(remote2, "should-not-match.local")
	_, err = httpClient2.Get("https://should-not-match.local/")
	if err == nil {
		t.Fatalf("expected hostname verification failure when SANs exist but don't match")
	}

	// Case 3: CN-only cert (no SANs) — should fail; Go 1.15+ requires SANs.
	caPEM3, certPEM3, keyPEM3 := makeCerts(t, "test-server.local", false)
	cert3, _ := tls.X509KeyPair(certPEM3, keyPEM3)
	srv3 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte{})
	}))
	srv3.TLS = &tls.Config{Certificates: []tls.Certificate{cert3}}
	srv3.StartTLS()
	defer srv3.Close()

	c3 := &Client{caCert: caPEM3}
	host3, port3, _ := net.SplitHostPort(srv3.Listener.Addr().String())
	remote3 := net.JoinHostPort(host3, port3)
	httpClient3 := c3.buildPIAHTTPClient(remote3, "test-server.local")
	_, err = httpClient3.Get("https://test-server.local/")
	if err == nil {
		t.Fatalf("expected failure for CN-only cert without SANs")
	}
}
