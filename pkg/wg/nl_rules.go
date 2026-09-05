package wg

import (
	"fmt"

	"github.com/networkop/smart-vpn-client/pkg/metrics"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	// mainRouteTable is the kernel's main routing table (RT_TABLE_MAIN).
	mainRouteTable = 254
	// wgRouteTable is the custom routing table used exclusively for WireGuard
	// traffic. All internet-bound packets are steered here by IP policy rules,
	// leaving the main table's default route via eth0 untouched.
	wgRouteTable = 51820

	// discoveryRulePrio is evaluated before localRulePrio and defaultRulePrio.
	// It matches only DiscoveryMark-tagged packets and sends them to the main
	// table unsuppressed, i.e. via its untouched default route (the native/ISP
	// interface). This lets discovery traffic reach the internet even when the
	// WireGuard default route exists but the tunnel is dead at the headend.
	discoveryRulePrio = 50
	// localRulePrio is evaluated before defaultRulePrio. It consults the main
	// table but suppresses any default (prefix-length 0) routes, so local-subnet
	// and WireGuard-endpoint bypass routes (/32) are still matched without the
	// main default route competing with the VPN default route.
	localRulePrio = 100
	// bypassRulePrio is evaluated between localRulePrio and defaultRulePrio.
	// It matches the configured bypass fwmark (see BypassConfig) and sends
	// that traffic to the bypass table, which holds a default route via the
	// native interface.
	//
	// Below localRulePrio so LAN destinations still resolve from the main
	// table and never reach the bypass table at all; above defaultRulePrio so
	// marked traffic beats the tunnel catch-all.
	bypassRulePrio = 150
	// defaultRulePrio steers all remaining traffic into the WireGuard table.
	defaultRulePrio = 1000
)

// DiscoveryMark is the fwmark that discovery traffic (see pia.discoverClient)
// must tag its sockets with (SO_MARK) to be routed via the native interface
// instead of the WireGuard tunnel. Arbitrary but must stay non-zero and
// unused elsewhere in the netns.
const DiscoveryMark = 0x51820

// addLocalRule installs:
//
//	ip rule add priority 100 lookup main suppress_prefixlength 0
//
// This allows specific routes in the main table (e.g. the /32 bypass for the
// WireGuard endpoint) to be matched while suppressing the main default route.
func (t *Tunnel) addLocalRule() error {
	rule := netlink.NewRule()
	rule.Priority = localRulePrio
	rule.Table = mainRouteTable
	rule.SuppressPrefixlen = 0
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("RuleAdd local: %w", err)
	}
	return nil
}

// delLocalRule removes the rule installed by addLocalRule.
func (t *Tunnel) delLocalRule() error {
	rule := t.getLocalRule()
	if rule == nil {
		return nil
	}
	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("RuleDel local: %w", err)
	}
	return nil
}

// getLocalRule returns the local rule if it exists, nil otherwise.
func (t *Tunnel) getLocalRule() *netlink.Rule {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for i, r := range rules {
		if r.Priority == localRulePrio && r.Table == mainRouteTable && r.SuppressPrefixlen == 0 {
			return &rules[i]
		}
	}
	return nil
}

// addDefaultRule installs:
//
//	ip rule add priority 1000 lookup 51820
//
// All traffic not matched by higher-priority rules is routed through the
// WireGuard table, which holds a default route via wg-pia.
func (t *Tunnel) addDefaultRule() error {
	rule := netlink.NewRule()
	rule.Priority = defaultRulePrio
	rule.Table = wgRouteTable
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("RuleAdd default: %w", err)
	}
	return nil
}

// delDefaultRule removes the rule installed by addDefaultRule.
func (t *Tunnel) delDefaultRule() error {
	rule := t.getDefaultRule()
	if rule == nil {
		return nil
	}
	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("RuleDel default: %w", err)
	}
	return nil
}

// getDefaultRule returns the default rule if it exists, nil otherwise.
func (t *Tunnel) getDefaultRule() *netlink.Rule {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for i, r := range rules {
		if r.Priority == defaultRulePrio && r.Table == wgRouteTable {
			return &rules[i]
		}
	}
	return nil
}

// addDiscoveryRule installs:
//
//	ip rule add priority 50 fwmark 0x51820 lookup main
//
// Unlike addLocalRule this does not suppress the default route, so
// DiscoveryMark-tagged traffic gets the main table's real default route via
// the native interface.
func (t *Tunnel) addDiscoveryRule() error {
	rule := netlink.NewRule()
	rule.Priority = discoveryRulePrio
	rule.Mark = DiscoveryMark
	rule.Table = mainRouteTable
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("RuleAdd discovery: %w", err)
	}
	return nil
}

// delDiscoveryRule removes the rule installed by addDiscoveryRule.
func (t *Tunnel) delDiscoveryRule() error {
	rule := t.getDiscoveryRule()
	if rule == nil {
		return nil
	}
	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("RuleDel discovery: %w", err)
	}
	return nil
}

// getDiscoveryRule returns the discovery rule if it exists, nil otherwise.
func (t *Tunnel) getDiscoveryRule() *netlink.Rule {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for i, r := range rules {
		if r.Priority == discoveryRulePrio && r.Mark == DiscoveryMark && r.Table == mainRouteTable {
			return &rules[i]
		}
	}
	return nil
}

// EnsureDiscoveryBypass idempotently installs the discovery-bypass rule. It
// is independent of the tunnel's up/down state and safe to call at any time
// (including before any tunnel exists, or while the tunnel is up but dead at
// the headend), so callers can invoke it right before every discovery
// request rather than relying on rule state left over from the last Connect.
func (t *Tunnel) EnsureDiscoveryBypass() error {
	if t.getDiscoveryRule() != nil {
		return nil
	}
	return t.addDiscoveryRule()
}

// addBypassSrcRule installs:
//
//	ip rule add priority 150 fwmark <mark> lookup <table>
//
// Marked traffic is sent to the bypass table's default route via the native
// interface, escaping the tunnel. No-op when the bypass is disabled.
func (t *Tunnel) addBypassSrcRule() error {
	if !t.bypass.Enabled() {
		return nil
	}
	rule := netlink.NewRule()
	rule.Priority = bypassRulePrio
	rule.Mark = t.bypass.Mark
	rule.Table = t.bypass.Table
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("RuleAdd bypass: %w", err)
	}
	return nil
}

// delBypassSrcRule removes the bypass rule along with the default route in the
// table it points at.
//
// Unlike its siblings this matches on priority alone rather than on the
// configured mark and table. `-cleanup` is documented as needing no
// configuration, so it runs without the bypass flags; matching strictly would
// leave a rule installed by an earlier, fully-configured run behind, silently
// diverting marked traffic long after the agent is gone. The rule itself
// carries the table to flush.
func (t *Tunnel) delBypassSrcRule() error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("RuleList bypass: %w", err)
	}
	for i, r := range rules {
		if r.Priority != bypassRulePrio {
			continue
		}
		table := r.Table
		if err := netlink.RuleDel(&rules[i]); err != nil {
			return fmt.Errorf("RuleDel bypass: %w", err)
		}
		t.delBypassTableRoute(table)
	}
	// The rule may already be gone while its table route lingers, so clean the
	// configured table unconditionally.
	t.delBypassTableRoute(t.bypass.Table)
	metrics.BypassRulePresent.Set(0)
	return nil
}

// getBypassSrcRule returns the bypass rule if it exists, nil otherwise.
func (t *Tunnel) getBypassSrcRule() *netlink.Rule {
	if !t.bypass.Enabled() {
		return nil
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for i, r := range rules {
		if r.Priority == bypassRulePrio && r.Mark == t.bypass.Mark && r.Table == t.bypass.Table {
			return &rules[i]
		}
	}
	return nil
}

// ensureBypass idempotently installs both halves of the split-tunnel bypass:
// the default route via the native interface in the bypass table, and the ip
// rule that steers fwmark-tagged traffic into it. No-op when disabled.
//
// Failures are deliberately non-fatal — the tunnel is perfectly functional
// without the bypass, and failing the connect would take the VPN down over a
// secondary feature. They are logged at WARN rather than DEBUG and reflected
// in vpn_bypass_rule_present, because the failure this feature exists to
// prevent is a silent one: marked traffic keeps working, it just leaves via
// the tunnel and gets masqueraded to the VPN exit address, with nothing in the
// logs to say so.
func (t *Tunnel) ensureBypass() {
	if !t.bypass.Enabled() {
		metrics.BypassRulePresent.Set(0)
		return
	}

	if err := t.ensureBypassTableRoute(); err != nil {
		logrus.Warnf("Bypass: failed to install default route in table %d: %s", t.bypass.Table, err)
	}

	if t.getBypassSrcRule() == nil {
		if err := t.addBypassSrcRule(); err != nil {
			logrus.Warnf("Bypass: failed to install ip rule at priority %d: %s", bypassRulePrio, err)
		}
	}

	if !t.refreshBypassState() {
		logrus.Warnf("Bypass: fwmark 0x%x is configured but the ip rule or the table %d default route is missing; "+
			"traffic marked by the companion proxy will leave through the tunnel and be masqueraded to the VPN exit address",
			t.bypass.Mark, t.bypass.Table)
		return
	}

	logrus.Infof("Bypass: fwmark 0x%x is routed via table %d (ip rule priority %d)",
		t.bypass.Mark, t.bypass.Table, bypassRulePrio)
}

// refreshBypassState updates vpn_bypass_rule_present and reports whether both
// halves of the bypass are in place. A rule without a route (or vice versa)
// does not divert anything, so both are required for the gauge to read 1.
func (t *Tunnel) refreshBypassState() bool {
	if !t.bypass.Enabled() {
		metrics.BypassRulePresent.Set(0)
		return false
	}

	present := t.getBypassSrcRule() != nil && t.getBypassTableRoute() != nil
	if present {
		metrics.BypassRulePresent.Set(1)
	} else {
		metrics.BypassRulePresent.Set(0)
	}
	return present
}

// ensureRules idempotently installs all ip rules. Safe to call on reconnect.
func (t *Tunnel) ensureRules() error {
	if t.getLocalRule() == nil {
		if err := t.addLocalRule(); err != nil {
			return err
		}
	}
	if t.getDefaultRule() == nil {
		if err := t.addDefaultRule(); err != nil {
			return err
		}
	}
	if err := t.EnsureDiscoveryBypass(); err != nil {
		return err
	}
	t.ensureBypass()
	return nil
}

// delRules removes all ip rules. Called during Cleanup.
func (t *Tunnel) delRules() error {
	if err := t.delLocalRule(); err != nil {
		return err
	}
	if err := t.delDefaultRule(); err != nil {
		return err
	}
	if err := t.delBypassSrcRule(); err != nil {
		return err
	}
	return t.delDiscoveryRule()
}
