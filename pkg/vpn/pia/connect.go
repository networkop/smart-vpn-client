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
func (c *Client) buildPIAHTTPClient(remote string) *http.Client {
	logrus.Debugf("Building an HTTP client to connect to %s", remote)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(c.caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
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

	client := c.buildPIAHTTPClient(fmt.Sprintf("%s:443", metaSever.IP))

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

	client := c.buildPIAHTTPClient(fmt.Sprintf("%s:1337", wgServer.IP))

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
