package pia

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	tokenURL  = "https://%s/authv3/generateToken"
	addKeyURL = "https://%s:1337/addKey"
)

type wgServerConf struct {
	Status    string `json:"status,omitempty"`
	Key       string `json:"server_key,omitempty"`
	Port      int    `json:"server_port,omitempty"`
	PeerIP    string `json:"peer_ip,omitempty"`
	GatewayIP string `json:"server_vip,omitempty"`
	RemoteIP  string `json:"server_ip,omitempty"`
}

type authV3 struct {
	Status string `json:"status,omitempty"`
	Token  string `json:"token,omitempty"`
}

// Connect to PIA VPN headend
func (c *Client) Connect() error {

	logrus.Debugf("Connecting to %s", c.winner.ID)

	token, err := c.genToken(*c.winner)
	if err != nil {
		return err
	}
	logrus.Debugf("Generated token %s", token)

	serverConf, err := c.genServer(*c.winner, token, c.wg.PrivateKey.PublicKey())
	if err != nil {
		return fmt.Errorf("Failed to get wg server configuration: %s", err)
	}

	remoteURL := fmt.Sprintf("%s:%d", serverConf.RemoteIP, serverConf.Port)

	err = c.wg.Up(remoteURL, serverConf.Key, serverConf.PeerIP)
	if err != nil {
		return fmt.Errorf("Failed to bring up wireguard tunnel: %s", err)
	}

	logrus.Info("Wireguard Tunnel is UP")

	err = c.wg.EnsureRouting(serverConf.GatewayIP)
	if err != nil {
		return fmt.Errorf("Error configuring routing: %s", err)
	}

	c.winner.connected = true

	err = c.wg.EnsureMasquerade()
	if err != nil {
		return fmt.Errorf("Error configuring NAT masquerade: %s", err)
	}

	return nil
}

// TODO extract hardcoded values
// buildPIAHTTPClient builds an HTTP client that dials `remote` (usually IP:port)
// but verifies TLS against serverName (usually the CN). Some PIA servers
// present certificates that rely on the legacy Common Name field instead of
// SANs; to support those we perform custom certificate verification that
// validates the chain with the provided CA and falls back to comparing the
// certificate CommonName when SANs are missing.
func (c *Client) buildPIAHTTPClient(remote string, serverName string) *http.Client {
	logrus.Debugf("Building an HTTP client to connect to %s (serverName=%s)", remote, serverName)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(c.caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// We enable InsecureSkipVerify and perform our own verification in
				// VerifyPeerCertificate so we can accept CN-only certs while still
				// validating the chain against our CA pool.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no server certificates presented")
					}

					certs := make([]*x509.Certificate, len(rawCerts))
					for i, asn1 := range rawCerts {
						cert, err := x509.ParseCertificate(asn1)
						if err != nil {
							return fmt.Errorf("failed to parse certificate: %w", err)
						}
						certs[i] = cert
					}

					intermediates := x509.NewCertPool()
					for _, ic := range certs[1:] {
						intermediates.AddCert(ic)
					}

					// First, try strict verification including hostname.
					opts := x509.VerifyOptions{
						Roots:         caCertPool,
						Intermediates: intermediates,
						DNSName:       serverName,
					}
					if _, err := certs[0].Verify(opts); err == nil {
						return nil
					}

					// If strict verification failed, try verifying the chain without
					// hostname checks, then fallback to comparing CommonName (CN)
					// when SANs are absent.
					opts.DNSName = ""
					if _, err := certs[0].Verify(opts); err != nil {
						return fmt.Errorf("certificate chain verification failed: %w", err)
					}

					// If certificate has SANs (DNSNames or IPAddresses) and strict
					// verification already failed, don't accept the CN fallback.
					if len(certs[0].DNSNames) > 0 || len(certs[0].IPAddresses) > 0 {
						return fmt.Errorf("certificate hostname verification failed")
					}

					// Fallback: accept certificate when its CommonName matches the
					// provided serverName. Log a warning so this exceptional path is visible.
					if certs[0].Subject.CommonName == serverName {
						logrus.Warnf("TLS CN fallback: accepting certificate for %s based on CommonName %s", serverName, certs[0].Subject.CommonName)
						return nil
					}

					return fmt.Errorf("server name %q does not match certificate CommonName %q", serverName, certs[0].Subject.CommonName)
				},
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				addr := remote
				return (&net.Dialer{
					Timeout: 10 * time.Second,
				}).DialContext(ctx, network, addr)
			},
		},
	}
}

func (c *Client) buildPIAGetRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.pwd)))
	return req, nil
}

func (c *Client) genToken(r region) (string, error) {
	metaSever := r.Servers.Meta[0]
	url := fmt.Sprintf(tokenURL, metaSever.CN)
	logrus.Debugf("Retrieving token from %s", url)

	client := c.buildPIAHTTPClient(fmt.Sprintf("%s:443", metaSever.IP), metaSever.CN)

	req, err := c.buildPIAGetRequest(url)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	payload := authV3{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return "", err
	}

	if payload.Status != "OK" {
		return "", fmt.Errorf("Failed to retrieve token: %s", err)
	}

	return payload.Token, nil

}

func (c *Client) genServer(r region, token string, pubKey wgtypes.Key) (*wgServerConf, error) {
	wgServer := r.Servers.WG[0]
	url := fmt.Sprintf(addKeyURL, wgServer.CN)
	logrus.Debugf("Retrieving wgServer configuration from %s", url)

	client := c.buildPIAHTTPClient(fmt.Sprintf("%s:1337", wgServer.IP), wgServer.CN)

	req, err := c.buildPIAGetRequest(url)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("pt", token)
	q.Add("pubkey", pubKey.String())
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	payload := wgServerConf{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return nil, err
	}

	if payload.Status != "OK" {
		return nil, fmt.Errorf("Failed to retrieve wg server configuration: %s", err)
	}

	return &payload, nil
}
