package wg

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// EnsureRouting sets up the routes needed for the VPN tunnel:
//
//  1. A host route for the tunnel gateway IP (nexthop/32) via wg-pia.
//  2. A bypass host route for the WireGuard server's external endpoint IP,
//     via the current ISP gateway. This prevents WireGuard's own encrypted
//     UDP traffic from being routed back into the tunnel (routing loop).
//  3. A default route (0.0.0.0/0) in the main routing table via wg-pia,
//     so all downstream traffic is forwarded through the VPN.
//
// No custom routing tables or ip rules are used.
func (t *Tunnel) EnsureRouting(nexthop string) error {

	nhCIDR := fmt.Sprintf("%s/32", nexthop)
	nhIP, nhNet, err := net.ParseCIDR(nhCIDR)
	if err != nil {
		return err
	}
	logrus.Debugf("wgIP %q, gwNet %q", nhIP, nhNet)

	// 1. Host route for the tunnel gateway IP.
	gwRoute := netlink.Route{
		Dst:       nhNet,
		LinkIndex: t.link.Attrs().Index,
	}
	if err = netlink.RouteAdd(&gwRoute); err != nil {
		return fmt.Errorf("RouteAdd gwRoute: %s", err)
	}

	// 2. Bypass route for the WireGuard server's external endpoint.
	//    Look up the current best route for the endpoint *before* we install
	//    the default route, so we get the ISP gateway and interface.
	if err = t.addBypassRoute(); err != nil {
		// Non-fatal: log and continue. The default route may still work if
		// the endpoint is reachable via a more-specific existing subnet route.
		logrus.Warnf("EnsureRouting: bypass route for WireGuard endpoint: %s", err)
	}

	// 3. Default route in the main routing table.
	defaultRoute := netlink.Route{
		Dst:       &defaultIPv4Net,
		LinkIndex: t.link.Attrs().Index,
	}
	if err = netlink.RouteAdd(&defaultRoute); err != nil {
		return fmt.Errorf("RouteAdd default: %s", err)
	}

	return nil
}

// addBypassRoute adds a /32 host route for the WireGuard server's external
// endpoint via the current ISP gateway, keeping the encrypted UDP traffic off
// the tunnel interface.
func (t *Tunnel) addBypassRoute() error {
	if t.endpoint == nil {
		return fmt.Errorf("endpoint IP not set")
	}

	// Find the current route for the endpoint before we add our default route.
	routes, err := netlink.RouteGet(t.endpoint)
	if err != nil || len(routes) == 0 {
		return fmt.Errorf("RouteGet(%s): %w", t.endpoint, err)
	}
	current := routes[0]

	bypass := &netlink.Route{
		Dst:       &net.IPNet{IP: t.endpoint, Mask: net.CIDRMask(32, 32)},
		Gw:        current.Gw,
		LinkIndex: current.LinkIndex,
	}
	if err = netlink.RouteAdd(bypass); err != nil {
		return fmt.Errorf("RouteAdd bypass(%s): %s", t.endpoint, err)
	}
	logrus.Debugf("Added bypass route for WireGuard endpoint %s", t.endpoint)
	return nil
}

// delBypassRoute removes the bypass host route added by addBypassRoute.
// Called during Cleanup so the route doesn't linger after the tunnel is torn down.
func (t *Tunnel) delBypassRoute() {
	if t.endpoint == nil {
		return
	}
	dst := &net.IPNet{IP: t.endpoint, Mask: net.CIDRMask(32, 32)}
	if err := netlink.RouteDel(&netlink.Route{Dst: dst}); err != nil {
		logrus.Debugf("delBypassRoute(%s): %s", t.endpoint, err)
	}
}

func (t *Tunnel) checkRouting() error {

	if t.link == nil {
		t.link = t.getWgLink()
		if t.link == nil {
			return fmt.Errorf("wireguard link %q not found", t.intfName)
		}
	}

	// Check that the main routing table has a default route via wg-pia.
	filter := &netlink.Route{
		Table:     mainRouteTable,
		LinkIndex: t.link.Attrs().Index,
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4, filter,
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF,
	)
	if err != nil {
		return fmt.Errorf("failed to list routes in main table: %w", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			return nil
		}
	}

	return fmt.Errorf("no default route found in main table via %s", t.intfName)
}
