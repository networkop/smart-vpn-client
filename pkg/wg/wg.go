package wg

import (
	"fmt"
	"net"
	"time"

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
}

func New() (*Tunnel, error) {

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	return &Tunnel{
		intfName:      wgInterface,
		PrivateKey:    key,
		RemoteAddress: defaultIPv4Net,
		keepalive:     defaultKeepalive,
		wgClient:      wgClient,
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
