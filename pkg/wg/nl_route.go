package wg

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// EnsureRouting sets up the routes and policy rules needed for the VPN tunnel:
//
//  1. A host route for the tunnel gateway IP (nexthop/32) via wg-pia.
//  2. A bypass host route for the WireGuard server's external endpoint IP,
//     via the current ISP gateway. This prevents WireGuard's own encrypted
//     UDP traffic from being routed back into the tunnel (routing loop).
//  3. A default route (0.0.0.0/0) in the WireGuard routing table (51820) via
//     wg-pia. The main table's default route via eth0 is left untouched.
//  4. IP policy rules that steer all internet traffic into the WireGuard table
//     while still allowing local-subnet and bypass routes in the main table.
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

	// 3. Default route in the WireGuard routing table — not the main table.
	//    This keeps the eth0 default route intact and avoids EEXIST on reconnect.
	defaultRoute := netlink.Route{
		Dst:       &defaultIPv4Net,
		LinkIndex: t.link.Attrs().Index,
		Table:     wgRouteTable,
	}
	if err = netlink.RouteReplace(&defaultRoute); err != nil {
		return fmt.Errorf("RouteAdd default: %s", err)
	}

	// 4. Install IP policy rules that steer traffic into the WireGuard table.
	if err = t.ensureRules(); err != nil {
		return fmt.Errorf("ensureRules: %s", err)
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

	// Capture the native path while we have it: this lookup happens before the
	// tunnel default route is installed, so it describes how the host reaches
	// the internet without the VPN. ensureBypassTableRoute reuses it rather
	// than repeating the discovery.
	t.nativeGw = current.Gw
	t.nativeLink = current.LinkIndex

	bypass := &netlink.Route{
		Dst:       &net.IPNet{IP: t.endpoint, Mask: net.CIDRMask(32, 32)},
		Gw:        current.Gw,
		LinkIndex: current.LinkIndex,
	}
	// RouteReplace handles reconnects where the bypass route already exists.
	if err = netlink.RouteReplace(bypass); err != nil {
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

// nativeDefault returns the gateway and interface index of the native
// (non-tunnel) default path.
//
// addBypassRoute captures this while installing the WireGuard endpoint's /32
// bypass, which runs before the tunnel default route exists, so the captured
// value is the pre-tunnel path. When that capture has not run — or failed —
// fall back to reading the main table's default route directly: this agent
// never touches the main table's default route, so it still describes the
// native path.
func (t *Tunnel) nativeDefault() (net.IP, int, error) {
	if t.nativeLink != 0 {
		return t.nativeGw, t.nativeLink, nil
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Table: mainRouteTable},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("listing main table routes: %w", err)
	}

	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() != "0.0.0.0/0" {
			continue
		}
		if r.LinkIndex == 0 {
			continue
		}
		// Defensive: never treat the tunnel itself as the native path.
		if t.link != nil && r.LinkIndex == t.link.Attrs().Index {
			continue
		}
		return r.Gw, r.LinkIndex, nil
	}

	return nil, 0, fmt.Errorf("no default route in the main table")
}

// ensureBypassTableRoute installs, in the bypass table:
//
//	ip route replace default via <native gw> dev <native iface> table <table>
//
// RouteReplace rather than RouteAdd so reconnects (and a changed ISP gateway)
// are handled without an EEXIST dance.
func (t *Tunnel) ensureBypassTableRoute() error {
	if !t.bypass.Enabled() {
		return nil
	}

	gw, linkIndex, err := t.nativeDefault()
	if err != nil {
		return err
	}

	route := &netlink.Route{
		Dst:       &defaultIPv4Net,
		Gw:        gw,
		LinkIndex: linkIndex,
		Table:     t.bypass.Table,
	}
	if gw == nil {
		// An on-link default route (no gateway) has to be link-scoped or the
		// kernel rejects it.
		route.Scope = netlink.SCOPE_LINK
	}

	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("RouteReplace bypass default (table %d): %w", t.bypass.Table, err)
	}
	logrus.Debugf("Bypass: default route via %s (link %d) installed in table %d", gw, linkIndex, t.bypass.Table)
	return nil
}

// getBypassTableRoute returns the bypass table's default route, nil otherwise.
func (t *Tunnel) getBypassTableRoute() *netlink.Route {
	if !t.bypass.Enabled() {
		return nil
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Table: t.bypass.Table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return nil
	}
	for i, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			return &routes[i]
		}
	}
	return nil
}

// delBypassTableRoute removes the default route from the given bypass table.
// Takes the table explicitly because cleanup may learn it from the installed
// rule rather than from configuration.
func (t *Tunnel) delBypassTableRoute(table int) {
	if table == 0 {
		return
	}
	if _, reserved := reservedTables[table]; reserved {
		// Belt and braces: NewBypassConfig rejects these, but this function is
		// also handed a table read back from the kernel.
		logrus.Warnf("Bypass: refusing to remove the default route from reserved table %d", table)
		return
	}
	route := &netlink.Route{Dst: &defaultIPv4Net, Table: table}
	if err := netlink.RouteDel(route); err != nil {
		logrus.Debugf("delBypassTableRoute(table %d): %s", table, err)
	}
}

func (t *Tunnel) checkRouting() error {

	if t.link == nil {
		t.link = t.getWgLink()
		if t.link == nil {
			return fmt.Errorf("wireguard link %q not found", t.intfName)
		}
	}

	// Check that the WireGuard routing table has a default route via wg-pia.
	filter := &netlink.Route{
		Table:     wgRouteTable,
		LinkIndex: t.link.Attrs().Index,
	}
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4, filter,
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF,
	)
	if err != nil {
		return fmt.Errorf("failed to list routes in wg table: %w", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			if t.getLocalRule() == nil || t.getDefaultRule() == nil {
				return fmt.Errorf("ip policy rules not configured")
			}
			return nil
		}
	}

	return fmt.Errorf("no default route found in wg table via %s", t.intfName)
}
