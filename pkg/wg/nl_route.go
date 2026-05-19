package wg

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

	if t.link == nil {
		// try to refresh the link from kernel
		t.link = t.getWgLink()
		if t.link == nil {
			return fmt.Errorf("wireguard link %q not found", t.intfName)
		}
	}

	// Directly inspect the VPN routing table rather than using RouteGet,
	// which resolves against the main table and misses our policy-routed
	// table entirely (RTM_GETROUTE without a mark walks the main FIB).
	filter := &netlink.Route{
		Table:     defaultRouteTable,
		LinkIndex: t.link.Attrs().Index,
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4, filter,
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF,
	)
	if err != nil {
		return fmt.Errorf("failed to list routes in table %d: %w", defaultRouteTable, err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			return nil
		}
	}

	return fmt.Errorf("no default route found in table %d via %s", defaultRouteTable, t.intfName)
}
