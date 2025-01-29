package pia

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/networkop/smart-vpn-client/pkg/wg"
)

const (
	caURL = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
)

// Client stores VPN client configuration
type Client struct {
	user, pwd      string
	Headends       map[string]*region
	http           http.Client
	caCert         []byte
	wg             *wg.Tunnel
	measureInt     int
	maxFailed      int
	ignores        map[string]struct{}
	preferVPN      string
	measureMaxWait time.Duration
	maxBestLatency time.Duration
	winner         *region
}

// NewClient returns new PIA client
func NewClient(user, pwd string, measureInt, maxFailed int, ignores []string, preferVPN string) (*Client, error) {

	ignoresMap := make(map[string]struct{})
	for _, ignore := range ignores {
		ignoresMap[ignore] = struct{}{}
	}

	return &Client{
		http:           http.Client{Timeout: time.Second * 2},
		user:           user,
		pwd:            pwd,
		measureInt:     measureInt,
		ignores:        ignoresMap,
		measureMaxWait: defaultMeasureMaxWait,
		maxBestLatency: defaultMaxBestLatency,
		maxFailed:      maxFailed,
		preferVPN:      preferVPN,
	}, nil
}

func (c *Client) Init() error {
	if err := c.getCAcert(); err != nil {
		return err
	}

	if err := c.initTunnel(); err != nil {
		return err
	}

	return nil
}

func (c *Client) initTunnel() error {
	wgTunnel, err := wg.New()
	if err != nil {
		return fmt.Errorf("Failed to init wg setup: %s", err)
	}

	c.wg = wgTunnel
	return nil
}

func (c *Client) getCAcert() error {

	client := http.Client{Timeout: time.Second * 2}

	resp, err := client.Get(caURL)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	c.caCert = body
	return nil
}
