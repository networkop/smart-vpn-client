package pia

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// tokenURL is PIA's central token API, the one its manual-connections
	// scripts use. Tokens used to come from each region's meta server
	// (https://<meta>/authv3/generateToken), but most meta servers now present
	// certificates from "ExpressVPN CA3" that fail verification against the PIA
	// CA, while the same regions' WireGuard API on :1337 still verifies. This
	// endpoint has a publicly-trusted certificate and also means credentials go
	// to one host rather than to whichever region wins the election.
	tokenURL  = "https://www.privateinternetaccess.com/api/client/v2/token"
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

type tokenResponse struct {
	Token string `json:"token,omitempty"`
}

// Connect to PIA VPN headend
func (c *Client) Connect() error {
	serverConf, err := c.negotiate()
	if err != nil {
		return err
	}
	return c.bringUp(serverConf)
}

// negotiate asks the winning headend for its tunnel parameters. It changes
// nothing on the host, so re-election can run it while the current tunnel is
// still carrying traffic and abandon the switch if the headend is unusable.
func (c *Client) negotiate() (*wgServerConf, error) {

	logrus.Debugf("Connecting to %s", c.winner.ID)

	token, err := c.genToken()
	if err != nil {
		return nil, err
	}
	logrus.Debugf("Generated token %s", token)

	serverConf, err := c.genServer(*c.winner, token, c.wg.PrivateKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("Failed to get wg server configuration: %s", err)
	}

	return serverConf, nil
}

// bringUp configures the local tunnel using parameters from negotiate.
func (c *Client) bringUp(serverConf *wgServerConf) error {
	remoteURL := fmt.Sprintf("%s:%d", serverConf.RemoteIP, serverConf.Port)

	err := c.wg.Up(remoteURL, serverConf.Key, serverConf.PeerIP)
	if err != nil {
		return fmt.Errorf("Failed to bring up wireguard tunnel: %s", err)
	}

	logrus.Info("Wireguard Tunnel is UP")

	err = c.wg.EnsureRouting(serverConf.GatewayIP)
	if err != nil {
		return fmt.Errorf("Error configuring routing: %s", err)
	}

	c.winner.connected = true

	if err = c.wg.EnsureMasquerade(); err != nil {
		return fmt.Errorf("error configuring NAT masquerade: %w", err)
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

	// Seed with the system CA pool so publicly-trusted certs work, then
	// append PIA's own CA for their self-signed API endpoints.
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		logrus.Warnf("Failed to load system cert pool, falling back to empty pool: %s", err)
		caCertPool = x509.NewCertPool()
	}
	caCertPool.AppendCertsFromPEM(c.caCert)

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// ServerName is still set so SNI is sent correctly even though
				// we bypass Go's standard hostname verification below.
				ServerName: serverName,
				// InsecureSkipVerify disables Go's built-in hostname check, which
				// rejects CN-only certs before any callback can run. All
				// verification is performed manually in VerifyPeerCertificate.
				InsecureSkipVerify: true, //nolint:gosec
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no server certificates")
					}
					certs := make([]*x509.Certificate, len(rawCerts))
					for i, raw := range rawCerts {
						cert, err := x509.ParseCertificate(raw)
						if err != nil {
							return fmt.Errorf("failed to parse certificate: %w", err)
						}
						certs[i] = cert
					}
					leaf := certs[0]
					intermediates := x509.NewCertPool()
					for _, c := range certs[1:] {
						intermediates.AddCert(c)
					}
					// Try strict verification including hostname (modern SANs certs).
					if _, err := leaf.Verify(x509.VerifyOptions{
						Roots:         caCertPool,
						Intermediates: intermediates,
						DNSName:       serverName,
					}); err == nil {
						return nil
					}
					// Strict check failed — verify chain without hostname.
					if _, err := leaf.Verify(x509.VerifyOptions{
						Roots:         caCertPool,
						Intermediates: intermediates,
					}); err != nil {
						return fmt.Errorf("certificate chain verification failed: %w", err)
					}
					// Chain is valid. If SANs exist the hostname mismatch is a hard failure.
					if len(leaf.DNSNames) > 0 || len(leaf.IPAddresses) > 0 {
						return fmt.Errorf("certificate SANs do not match server name %q", serverName)
					}
					// CN-only fallback: CommonName must match.
					if leaf.Subject.CommonName != serverName {
						return fmt.Errorf("CN %q does not match server name %q", leaf.Subject.CommonName, serverName)
					}
					logrus.Debugf("TLS: accepted CN-only cert for %s", serverName)
					return nil
				},
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext(ctx, network, remote)
			},
		},
	}
}

// genToken uses discoverClient so the token request is reused over one
// long-lived client and, like discovery, leaves via the native interface even
// if the tunnel is up but black-holing traffic.
func (c *Client) genToken() (string, error) {
	return c.requestToken(discoverClient, tokenURL)
}

func (c *Client) requestToken(client *http.Client, url string) (string, error) {
	logrus.Debugf("Retrieving token from %s", url)

	var form bytes.Buffer
	w := multipart.NewWriter(&form)
	if err := w.WriteField("username", c.user); err != nil {
		return "", err
	}
	if err := w.WriteField("password", c.pwd); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, url, &form)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	payload := tokenResponse{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if payload.Token == "" {
		return "", fmt.Errorf("token response did not contain a token")
	}

	return payload.Token, nil
}

func (c *Client) genServer(r region, token string, pubKey wgtypes.Key) (*wgServerConf, error) {
	wgServer := r.Servers.WG[0]
	url := fmt.Sprintf(addKeyURL, wgServer.CN)
	logrus.Debugf("Retrieving wgServer configuration from %s", url)

	client := c.buildPIAHTTPClient(fmt.Sprintf("%s:1337", wgServer.IP), wgServer.CN)

	// Authenticated by the pt token alone; the user's password is not sent here.
	req, err := http.NewRequest(http.MethodGet, url, nil)
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("addKey request failed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	payload := wgServerConf{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse addKey response: %w", err)
	}

	if payload.Status != "OK" {
		return nil, fmt.Errorf("failed to retrieve wg server configuration: status %q", payload.Status)
	}

	return &payload, nil
}
