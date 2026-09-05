package wg

import (
	"fmt"
	"net"
	"time"

	"github.com/networkop/smart-vpn-client/pkg/metrics"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgInterface      = "wg-pia"
	defaultKeepalive = 15 * time.Second
)

var defaultIPv4Net = net.IPNet{
	IP:   net.ParseIP("0.0.0.0"),
	Mask: net.CIDRMask(0, 32),
}

// BypassConfig describes the split-tunnel escape hatch used by a companion
// proxy (see docs/vpn-agent-integration.md). The proxy tags its upstream
// sockets with SO_MARK; an ip rule at bypassRulePrio steers those packets into
// Table, which holds a default route via the native interface instead of the
// tunnel.
//
// A zero Mark disables the feature. Table is kept populated either way so that
// a standalone `-cleanup` run, which is not given the bypass flags, still has a
// table to flush.
type BypassConfig struct {
	Mark  uint32
	Table int
}

// Enabled reports whether the split-tunnel bypass is configured.
func (b BypassConfig) Enabled() bool { return b.Mark != 0 }

// reservedTables are routing tables the bypass must never be pointed at:
// the kernel's own (local/main/default) plus the WireGuard table this agent
// owns. Writing a native default route into any of them would either be
// ignored or, in the case of wgRouteTable, quietly send tunnel traffic out of
// the native interface.
var reservedTables = map[int]string{
	255:            "local",
	mainRouteTable: "main",
	253:            "default",
	wgRouteTable:   "the WireGuard table",
}

// NewBypassConfig validates operator-supplied bypass settings and converts them
// into a BypassConfig. mark == 0 disables the feature; table is still validated
// in that case because cleanup acts on it regardless.
func NewBypassConfig(mark, table int) (BypassConfig, error) {
	if mark < 0 || int64(mark) > int64(^uint32(0)) {
		return BypassConfig{}, fmt.Errorf("bypass mark %d out of range for a 32-bit fwmark", mark)
	}
	if mark == DiscoveryMark {
		return BypassConfig{}, fmt.Errorf("bypass mark 0x%x collides with the discovery mark", mark)
	}
	if table <= 0 {
		return BypassConfig{}, fmt.Errorf("bypass table %d is not a valid routing table", table)
	}
	if name, reserved := reservedTables[table]; reserved {
		return BypassConfig{}, fmt.Errorf("bypass table %d is %s and cannot be used", table, name)
	}
	return BypassConfig{Mark: uint32(mark), Table: table}, nil
}

type Tunnel struct {
	PrivateKey    wgtypes.Key
	intfName      string
	RemoteAddress net.IPNet
	keepalive     time.Duration
	wgClient      *wgctrl.Client
	link          netlink.Link
	// endpoint is the WireGuard server's external IP, stored so EnsureRouting
	// can add a bypass host route to prevent the encrypted UDP traffic from
	// being routed back into the tunnel.
	endpoint net.IP
	// bypass holds the split-tunnel bypass settings. Disabled when Mark is 0.
	bypass BypassConfig
	// nativeGw and nativeLink describe the native (non-tunnel) default path.
	// Captured by addBypassRoute, which runs before the tunnel default route
	// exists; see nativeDefault for the fallback when that capture is absent.
	nativeGw   net.IP
	nativeLink int
}

// New builds a Tunnel. bypass configures the optional split-tunnel escape
// hatch; pass the zero value to disable it.
func New(bypass BypassConfig) (*Tunnel, error) {

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	if bypass.Enabled() {
		metrics.BypassEnabled.Set(1)
	} else {
		metrics.BypassEnabled.Set(0)
	}

	return &Tunnel{
		intfName:      wgInterface,
		PrivateKey:    key,
		RemoteAddress: defaultIPv4Net,
		keepalive:     defaultKeepalive,
		wgClient:      wgClient,
		bypass:        bypass,
	}, nil
}

func (t *Tunnel) Cleanup() {
	t.delBypassRoute()
	if err := t.delRules(); err != nil {
		logrus.Debugf("delRules during cleanup: %s", err)
	}
	t.link = t.getWgLink()
	if t.link != nil {
		if err := t.delWgLink(); err != nil {
			logrus.Errorf("Error deleting link: %s", err)
			return
		}
	}
	if _, err := t.delIPtables(); err != nil {
		logrus.Debugf("delIPtables during cleanup: %s", err)
	}
}

func (t *Tunnel) IsUp() bool {
	logrus.Debugf("Checking the state of the wireguard tunnel")

	// The bypass is independent of the tunnel's own state, but this is the
	// only periodic pass over the routing configuration, so refresh its gauge
	// here. Without it the metric would only ever be updated on reconnect and
	// would go stale if the rules were flushed from under us.
	t.refreshBypassState()

	// Refresh link reference in case the kernel created/removed the interface
	// since the Tunnel object was initialized. Avoid dereferencing a nil link.
	t.link = t.getWgLink()
	if t.link == nil {
		logrus.Debugf("No wireguard link found for %s", t.intfName)
		return false
	}

	err := t.checkRouting()
	if err != nil {
		logrus.Debugf("Failed checkRouting: %s", err)
		return false
	}

	if _, err = t.getIPtables(); err != nil {
		logrus.Debugf("Failed getIPtables: %s", err)
		return false
	}

	return true
}

func (t *Tunnel) Up(remote, key, peerIP string) error {

	err := t.newWgLink()
	if err != nil {
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return err
	}
	t.endpoint = udpAddr.IP.To4()

	parsedKey, err := wgtypes.ParseKey(key)
	if err != nil {
		return err
	}

	cfg := wgtypes.Config{
		PrivateKey: &t.PrivateKey,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   parsedKey,
				Endpoint:                    udpAddr,
				PersistentKeepaliveInterval: &t.keepalive,
				AllowedIPs:                  []net.IPNet{t.RemoteAddress},
			},
		},
	}
	logrus.Infof("Brining up WG tunnel to %s", remote)

	err = t.wgClient.ConfigureDevice(t.intfName, cfg)
	if err != nil {
		return fmt.Errorf("Failed to configure wg interface: %s", err)
	}

	err = t.addIP(fmt.Sprintf("%s/32", peerIP))
	if err != nil {
		return fmt.Errorf("Failed add IP to wg interface: %s", err)
	}

	return nil
}
