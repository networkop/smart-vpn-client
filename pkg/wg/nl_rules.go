package wg

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	defaultRulePrio = 50
	mainRouteTable  = 254
)

func (t *Tunnel) ensureRules() error {

	defaultRule := t.getDefaultRule()
	localRule := t.getLocalRule()

	if defaultRule != nil && localRule != nil {
		return nil
	}

	if err := t.addDefaultRule(); err != nil {
		return err
	}

	if err := t.addLocalRule(); err != nil {
		return err
	}

	return nil
}

// ip rule for all default route traffic
func (t *Tunnel) addDefaultRule() error {
	nlRule := netlink.NewRule()
	nlRule.Priority = defaultRulePrio
	nlRule.Family = netlink.FAMILY_V4
	nlRule.Invert = true
	nlRule.Mark = defaultFwMark
	nlRule.Table = defaultRouteTable

	err := netlink.RuleAdd(nlRule)
	if err != nil {
		return fmt.Errorf("RuleAdd %+v: %s", nlRule, err)
	}
	return nil
}

// ip rule for all non-default routes (e.g. local subnets)
func (t *Tunnel) addLocalRule() error {
	nlRule := netlink.NewRule()
	nlRule.Family = netlink.FAMILY_V4
	nlRule.Table = mainRouteTable
	nlRule.Priority = defaultRulePrio - 1
	nlRule.SuppressPrefixlen = 0

	err := netlink.RuleAdd(nlRule)
	if err != nil {
		return fmt.Errorf("RuleAdd (local traffic) %+v: %s", nlRule, err)
	}
	return nil
}

func (t *Tunnel) getDefaultRule() *netlink.Rule {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for _, rule := range rules {
		if rule.Priority == defaultRulePrio && rule.Mark == defaultFwMark {
			return &rule
		}
	}
	return nil
}

func (t *Tunnel) getLocalRule() *netlink.Rule {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for _, rule := range rules {
		if rule.Priority == defaultRulePrio-1 && rule.SuppressPrefixlen == 0 {
			return &rule
		}
	}
	return nil
}

func (t *Tunnel) delDefaultRule() error {
	if rule := t.getDefaultRule(); rule != nil {
		return netlink.RuleDel(rule)
	}

	logrus.Debugf("Rule does not exist, nothing to do")
	return nil
}

func (t *Tunnel) delLocalRule() error {
	if rule := t.getLocalRule(); rule != nil {
		return netlink.RuleDel(rule)
	}

	logrus.Debugf("Rule does not exist, nothing to do")
	return nil
}

func (t *Tunnel) delRules() error {
	if err := t.delDefaultRule(); err == nil {
		return t.delLocalRule()
	}
	return nil
}
