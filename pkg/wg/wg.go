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
	wgInterface       = "wg-pia"
	defaultRouteTable = 59989
	defaultFwMark     = 59989
	defaultKeepalive  = 15 * time.Second
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
	routeTableID  int
	fwMark        int
	link          netlink.Link
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
		routeTableID:  defaultRouteTable,
		fwMark:        defaultFwMark,
		wgClient:      wgClient,
	}, nil
}

func (t *Tunnel) Cleanup() error {
	t.link = t.getWgLink()
	if t.link != nil {
		if err := t.delWgLink(); err != nil {
			return err
		}
	}
	if err := t.delRules(); err != nil {
		return err
	}
	if _, err := t.delIPtables(); err != nil {
		return err
	}
	return nil
}

func (t *Tunnel) IsUp() bool {
	logrus.Debugf("Checking the state of the wireguard tunnel")

	err := t.checkRouting()
	if err != nil {
		logrus.Debugf("Failed checkRouting: %s", err)
		return false
	}

	_, err = t.getIPtables()
	if err != nil {
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

	parsedKey, err := wgtypes.ParseKey(key)
	if err != nil {
		return err
	}

	cfg := wgtypes.Config{
		PrivateKey:   &t.PrivateKey,
		FirewallMark: intPtr(defaultFwMark),
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

func intPtr(v int) *int { return &v }
