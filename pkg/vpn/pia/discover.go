package pia

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	piaV4discoveryURL  = "https://serverlist.piaservers.net/vpninfo/servers/v4"
	piaV4payloadSigLen = 350
)

var (
	defaultHeadendPort = 443
)

type piaV4 struct {
	Regions []*region `json:"regions,omitempty"`
}

type region struct {
	Servers   piaServerInfo `json:"servers,omitempty"`
	latency   time.Duration
	ID        string `json:"id,omitempty"`
	connected bool
}

type piaServerInfo struct {
	WG   []piaServer `json:"wg,omitempty"`
	Meta []piaServer `json:"meta,omitempty"`
}

type piaServer struct {
	IP string `json:"ip"`
	CN string `json:"cn"`
}

// Discover PIA VPN headends
func (c *Client) Discover() error {
	logrus.Info("Discovering VPN headends for PIA")
	req, err := http.NewRequest(http.MethodGet, piaV4discoveryURL, nil)
	if err != nil {
		return err
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Failed to read body: %s", err)
	}

	payload := piaV4{}
	err = json.Unmarshal(body[:len(body)-piaV4payloadSigLen], &payload)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal: %s", err)
	}

	if len(payload.Regions) < 10 {
		return fmt.Errorf("Unexpected number of headends discovered (<10): %d", len(payload.Regions))
	}

	c.Headends = make(map[string]*region)
	for _, region := range payload.Regions {
		if !c.isIgnored(region) {
			c.Headends[region.ID] = region
		}
	}

	return nil
}

func (c *Client) isIgnored(r *region) bool {
	if _, ok := c.ignores[r.ID]; ok {
		return true
	}
	return false
}
