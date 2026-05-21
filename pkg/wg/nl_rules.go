package wg

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const (
	// mainRouteTable is the kernel's main routing table (RT_TABLE_MAIN).
	mainRouteTable = 254
	// wgRouteTable is the custom routing table used exclusively for WireGuard
	// traffic. All internet-bound packets are steered here by IP policy rules,
	// leaving the main table's default route via eth0 untouched.
	wgRouteTable = 51820

	// localRulePrio is evaluated before defaultRulePrio. It consults the main
	// table but suppresses any default (prefix-length 0) routes, so local-subnet
	// and WireGuard-endpoint bypass routes (/32) are still matched without the
	// main default route competing with the VPN default route.
	localRulePrio = 100
	// defaultRulePrio steers all remaining traffic into the WireGuard table.
	defaultRulePrio = 1000
)

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

// ensureRules idempotently installs both ip rules. Safe to call on reconnect.
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
	return nil
}

// delRules removes both ip rules. Called during Cleanup.
func (t *Tunnel) delRules() error {
	if err := t.delLocalRule(); err != nil {
		return err
	}
	return t.delDefaultRule()
}
