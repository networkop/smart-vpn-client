package pia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/networkop/smart-vpn-client/pkg/wg"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	piaV4discoveryURL  = "https://serverlist.piaservers.net/vpninfo/servers/v7"
	piaV4payloadSigLen = 350
	// discoverTimeout is generous because discovery traffic traverses the VPN
	// tunnel, which may be slow (but working) at the moment a reconnect is
	// triggered. A short timeout here causes a reconnect loop on a degraded link.
	discoverTimeout = 15 * time.Second
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
	ID        string        `json:"id,omitempty"`
	Name      string        `json:"name,omitempty"` // human-readable name, optional in v7
	Offline   bool          `json:"offline,omitempty"`
	connected bool
}

// displayName returns the human-readable name if available, falling back to ID.
func (r *region) displayName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}

type piaServerInfo struct {
	WG   []piaServer `json:"wg,omitempty"`
	Meta []piaServer `json:"meta,omitempty"`
}

type piaServer struct {
	IP string `json:"ip"`
	CN string `json:"cn"`
}

// discoverClient is built once and reused. Creating a new http.Client (and
// therefore a new http.Transport) per request leaks the transport's connection
// pool: each abandoned transport keeps its sockets and their readLoop/writeLoop
// goroutines alive, which accumulate until new requests are multiplexed onto
// dead HTTP/2 connections and hang until the client timeout.
//
// Every socket is tagged with wg.DiscoveryMark (SO_MARK), which the
// discovery-bypass ip rule (see wg.Tunnel.EnsureDiscoveryBypass) routes via
// the main table's native default route instead of the WireGuard tunnel.
// This keeps discovery working even when the tunnel is up but dead at the
// headend, since it no longer depends on the tunnel carrying traffic at all.
//
// Dials tcp4 only: serverlist.piaservers.net publishes AAAA records and the
// container has no working IPv6 path off-box.
var discoverClient = &http.Client{
	Timeout: discoverTimeout,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, _ string, c syscall.RawConn) error {
					var sockErr error
					if err := c.Control(func(fd uintptr) {
						sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, wg.DiscoveryMark)
					}); err != nil {
						return err
					}
					return sockErr
				},
			}
			return d.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
}

// Discover PIA VPN headends
func (c *Client) Discover() error {
	logrus.Info("Discovering VPN headends for PIA")

	// Idempotent and independent of tunnel state: guarantees the bypass rule
	// is in place even if Discover is called before any Connect has run, or
	// something external removed it.
	if c.wg != nil {
		if err := c.wg.EnsureDiscoveryBypass(); err != nil {
			return fmt.Errorf("Failed to ensure discovery bypass route: %s", err)
		}
	}

	req, err := http.NewRequest(http.MethodGet, piaV4discoveryURL, nil)
	if err != nil {
		return err
	}

	res, err := discoverClient.Do(req)
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
		if region.Offline {
			logrus.Debugf("Skipping offline region %s", region.displayName())
			continue
		}
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
