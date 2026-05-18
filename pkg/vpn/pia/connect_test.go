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
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		IsCA:         true,
		KeyUsage:                 x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid:    true,
		MaxPathLenZero:           true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// server cert
	srvKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	// Create CA and server cert without SANs (CN-only)
	caPEM, certPEM, keyPEM := makeCerts(t, "test-server.local", false)

	// Build a TLS server using the cert
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	// override the client's caCert to the CA we made
	c := &Client{caCert: caPEM}

	// Extract host and port to dial directly
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	remote := net.JoinHostPort(host, port)

	// Client should accept since we use CN fallback with serverName = CommonName
	// Capture logs to ensure CN fallback is logged (skipped here); successful
	// request is used to verify behaviour.
	httpClient := c.buildPIAHTTPClient(remote, "test-server.local")
	resp, err := httpClient.Get("https://test-server.local/")
	if err != nil {
		t.Fatalf("client get with CN fallback failed: %v", err)
	}
	resp.Body.Close()
	// We can't easily capture logrus output here without changing global hooks in
	// the package; relying on functional behaviour (request succeeding) is
	// sufficient for unit tests in this environment.

	// Now create a cert with SANs that don't match the requested name to ensure
	// strict verification fails and we don't incorrectly accept CN when SANs exist.
	caPEM2, certPEM2, keyPEM2 := makeCerts(t, "other.local", true)
	cert2, _ := tls.X509KeyPair(certPEM2, keyPEM2)
	srv2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
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
}
