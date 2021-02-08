package wg

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	routeCheck = "1.1.1.1"
)

// EnsureRouting for the wireguard tunnel
func (t *Tunnel) EnsureRouting(nexthop string) error {

	nhCIDR := fmt.Sprintf("%s/32", nexthop)
	nhIP, nhNet, err := net.ParseCIDR(nhCIDR)
	if err != nil {
		return err
	}
	logrus.Debugf("wgIP %q, gwNet %q", nhIP, nhNet)

	gwRoute := netlink.Route{
		Dst:       nhNet,
		LinkIndex: t.link.Attrs().Index,
	}

	err = netlink.RouteAdd(&gwRoute)
	if err != nil {
		return fmt.Errorf("RouteAdd gwRoute: %s", err)
	}

	nlDefaultRoute := netlink.Route{
		Dst:       &defaultIPv4Net,
		LinkIndex: t.link.Attrs().Index,
		Table:     defaultRouteTable,
	}

	err = netlink.RouteAdd(&nlDefaultRoute)
	if err != nil {
		return fmt.Errorf("RouteAdd %q: %s", defaultIPv4Net, err)
	}

	return t.ensureRules()
}

func (t *Tunnel) checkRouting() error {

	routes, err := netlink.RouteGet(net.ParseIP(routeCheck))
	if err != nil {
		return err
	}

	for _, route := range routes {
		if route.LinkIndex != t.link.Attrs().Index {
			return fmt.Errorf("Route lookup return a wrong egress interface index. Expected %d, got: %+v", t.link.Attrs().Index, route)
		} else {
			return nil
		}
	}

	return fmt.Errorf("Found no matching routes for %s", routeCheck)
}
