package wg

import (
	"testing"

	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Test-only bypass settings. Deliberately not the documented defaults
// (0x51821 / table 51821) so these tests never tear down a bypass installed by
// a real client running on the same host.
const (
	testBypassMark  = 0x51899
	testBypassTable = 51899
)

func testBypassConfig(t *testing.T) BypassConfig {
	t.Helper()
	cfg, err := NewBypassConfig(testBypassMark, testBypassTable)
	if err != nil {
		t.Fatalf("NewBypassConfig: %v", err)
	}
	return cfg
}

func TestRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping netlink rule tests when not running as root")
	}
	wg, err := New(testBypassConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	wg.intfName = "wg-package-test"

	// Clean up any pre-existing rules from a running VPN client so the test
	// starts from a known state.
	_ = wg.delLocalRule()
	_ = wg.delDefaultRule()
	_ = wg.delDiscoveryRule()
	_ = wg.delBypassSrcRule()
	t.Cleanup(func() {
		_ = wg.delLocalRule()
		_ = wg.delDefaultRule()
		_ = wg.delDiscoveryRule()
		_ = wg.delBypassSrcRule()
	})

	tests := []struct {
		name          string
		changeCommand func() error
		getCommand    func() *netlink.Rule
		wantRule      bool
	}{
		{
			name:          "first",
			changeCommand: wg.addLocalRule,
			getCommand:    wg.getLocalRule,
			wantRule:      true,
		},
		{
			name:          "second",
			changeCommand: wg.addDefaultRule,
			getCommand:    wg.getDefaultRule,
			wantRule:      true,
		},
		{
			name:          "third",
			changeCommand: wg.delLocalRule,
			getCommand:    wg.getLocalRule,
			wantRule:      false,
		},
		{
			name:          "fourth",
			changeCommand: wg.delDefaultRule,
			getCommand:    wg.getDefaultRule,
			wantRule:      false,
		},
		{
			name:          "fifth",
			changeCommand: wg.addDiscoveryRule,
			getCommand:    wg.getDiscoveryRule,
			wantRule:      true,
		},
		{
			name: "sixth",
			changeCommand: func() error {
				// EnsureDiscoveryBypass must be a no-op when the rule already
				// exists rather than erroring on a duplicate RuleAdd.
				return wg.EnsureDiscoveryBypass()
			},
			getCommand: wg.getDiscoveryRule,
			wantRule:   true,
		},
		{
			name:          "seventh",
			changeCommand: wg.delDiscoveryRule,
			getCommand:    wg.getDiscoveryRule,
			wantRule:      false,
		},
		{
			name:          "eighth",
			changeCommand: wg.addBypassSrcRule,
			getCommand:    wg.getBypassSrcRule,
			wantRule:      true,
		},
		{
			name:          "ninth",
			changeCommand: wg.delBypassSrcRule,
			getCommand:    wg.getBypassSrcRule,
			wantRule:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.changeCommand()

			if err != nil {
				t.Errorf("%s test error = %v", tt.name, err)
			} else {
				rule := tt.getCommand()
				if (rule != nil) != tt.wantRule {
					t.Errorf("%s test error, wantRule: %v", tt.name, tt.wantRule)
				}
			}

		})
	}
}

// countRulesAtPrio returns how many ip rules sit at the given priority.
func countRulesAtPrio(t *testing.T, prio int) int {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("RuleList: %v", err)
	}
	var n int
	for _, r := range rules {
		if r.Priority == prio {
			n++
		}
	}
	return n
}

// TestBypassRuleIdempotent covers the reconnect path: ensureRules runs on every
// Connect, so a second call must leave exactly one rule at bypassRulePrio
// rather than erroring on a duplicate RuleAdd or stacking rules.
func TestBypassRuleIdempotent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping netlink rule tests when not running as root")
	}

	wg, err := New(testBypassConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	wg.intfName = "wg-package-test"

	// Start from a known state and put the host back afterwards: ensureRules
	// installs the local, default and discovery rules too.
	delAll := func() {
		_ = wg.delLocalRule()
		_ = wg.delDefaultRule()
		_ = wg.delDiscoveryRule()
		_ = wg.delBypassSrcRule()
	}
	delAll()
	t.Cleanup(delAll)

	for i := 1; i <= 2; i++ {
		if err := wg.ensureRules(); err != nil {
			t.Fatalf("ensureRules call %d: %v", i, err)
		}
		if got := countRulesAtPrio(t, bypassRulePrio); got != 1 {
			t.Fatalf("after ensureRules call %d: got %d rules at priority %d, want 1", i, got, bypassRulePrio)
		}
		if wg.getBypassSrcRule() == nil {
			t.Fatalf("after ensureRules call %d: bypass rule not found", i)
		}
	}

	// delRules must remove the rule as well as the table's default route.
	if err := wg.delRules(); err != nil {
		t.Fatalf("delRules: %v", err)
	}
	if got := countRulesAtPrio(t, bypassRulePrio); got != 0 {
		t.Fatalf("after delRules: got %d rules at priority %d, want 0", got, bypassRulePrio)
	}
	if wg.getBypassTableRoute() != nil {
		t.Fatalf("after delRules: default route still present in table %d", testBypassTable)
	}
}

// TestBypassDisabled checks that the feature stays entirely out of the way when
// no mark is configured — the zero BypassConfig must install nothing.
func TestBypassDisabled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping netlink rule tests when not running as root")
	}

	wg, err := New(BypassConfig{})
	if err != nil {
		t.Fatal(err)
	}
	wg.intfName = "wg-package-test"

	before := countRulesAtPrio(t, bypassRulePrio)
	if err := wg.addBypassSrcRule(); err != nil {
		t.Fatalf("addBypassSrcRule: %v", err)
	}
	if got := countRulesAtPrio(t, bypassRulePrio); got != before {
		t.Fatalf("disabled bypass installed a rule: %d -> %d", before, got)
	}
	if wg.getBypassSrcRule() != nil {
		t.Fatal("getBypassSrcRule returned a rule with the bypass disabled")
	}
}

func TestNewBypassConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mark, table int
		wantErr     bool
		wantEnabled bool
	}{
		{name: "disabled by zero mark", mark: 0, table: 51821, wantEnabled: false},
		{name: "valid", mark: 0x51821, table: 51821, wantEnabled: true},
		{name: "collides with discovery mark", mark: DiscoveryMark, table: 51821, wantErr: true},
		{name: "collides with wireguard table", mark: 0x51821, table: wgRouteTable, wantErr: true},
		{name: "main table", mark: 0x51821, table: mainRouteTable, wantErr: true},
		{name: "local table", mark: 0x51821, table: 255, wantErr: true},
		{name: "zero table", mark: 0x51821, table: 0, wantErr: true},
		{name: "negative mark", mark: -1, table: 51821, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := NewBypassConfig(tt.mark, tt.table)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewBypassConfig(%d, %d) error = %v, wantErr %v", tt.mark, tt.table, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if cfg.Enabled() != tt.wantEnabled {
				t.Fatalf("Enabled() = %v, want %v", cfg.Enabled(), tt.wantEnabled)
			}
		})
	}
}

// Test-only stand-in for a rule owned by another component (envoy-split-proxy
// installs `150: from all fwmark 0x51821 lookup 200`). Same priority as ours,
// different mark and, crucially, a different table.
const (
	foreignBypassMark  = 0x51897
	foreignBypassTable = 51897
)

// countRulesAtPrioTable returns how many ip rules sit at the given priority and
// point at the given table.
func countRulesAtPrioTable(t *testing.T, prio, table int) int {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("RuleList: %v", err)
	}
	var n int
	for _, r := range rules {
		if r.Priority == prio && r.Table == table {
			n++
		}
	}
	return n
}

// addForeignBypassRule installs a rule at bypassRulePrio pointing at a table
// this agent does not manage, plus a blackhole default route in that table, and
// removes both when the test ends. A blackhole route needs no link or gateway,
// so it works on any host.
func addForeignBypassRule(t *testing.T) {
	t.Helper()

	rule := netlink.NewRule()
	rule.Priority = bypassRulePrio
	rule.Mark = foreignBypassMark
	rule.Table = foreignBypassTable
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("RuleAdd foreign: %v", err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(rule) })

	route := &netlink.Route{
		Dst:   &defaultIPv4Net,
		Table: foreignBypassTable,
		Type:  unix.RTN_BLACKHOLE,
	}
	if err := netlink.RouteReplace(route); err != nil {
		t.Fatalf("RouteReplace foreign: %v", err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
}

// foreignBypassRoutePresent reports whether the foreign table still holds a
// route. delBypassSrcRule must never flush a table it does not own.
func foreignBypassRoutePresent(t *testing.T) bool {
	t.Helper()
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Table: foreignBypassTable},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		t.Fatalf("RouteListFiltered: %v", err)
	}
	return len(routes) > 0
}

// TestBypassRuleOwnership is the regression test for the collision that made
// this agent delete envoy-split-proxy's rule (and flush its table) on startup:
// deletion must match on the agent's own bypass table, not on priority alone.
func TestBypassRuleOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping netlink rule tests when not running as root")
	}

	addForeignBypassRule(t)

	wg, err := New(testBypassConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	wg.intfName = "wg-package-test"

	delAll := func() {
		_ = wg.delLocalRule()
		_ = wg.delDefaultRule()
		_ = wg.delDiscoveryRule()
		_ = wg.delBypassSrcRule()
	}
	delAll()
	t.Cleanup(delAll)

	// The foreign rule must survive the teardown that runs before every
	// Connect, as well as the one at the top of this test.
	if got := countRulesAtPrioTable(t, bypassRulePrio, foreignBypassTable); got != 1 {
		t.Fatalf("foreign rule removed by teardown: got %d rules for table %d, want 1", got, foreignBypassTable)
	}

	if err := wg.addBypassSrcRule(); err != nil {
		t.Fatalf("addBypassSrcRule: %v", err)
	}
	if wg.getBypassSrcRule() == nil {
		t.Fatal("own bypass rule not installed")
	}

	if err := wg.delRules(); err != nil {
		t.Fatalf("delRules: %v", err)
	}
	if got := countRulesAtPrioTable(t, bypassRulePrio, testBypassTable); got != 0 {
		t.Fatalf("after delRules: got %d own rules at priority %d, want 0", got, bypassRulePrio)
	}
	if got := countRulesAtPrioTable(t, bypassRulePrio, foreignBypassTable); got != 1 {
		t.Fatalf("after delRules: got %d foreign rules for table %d, want 1", got, foreignBypassTable)
	}
	if !foreignBypassRoutePresent(t) {
		t.Fatalf("after delRules: table %d was flushed", foreignBypassTable)
	}
}

// TestBypassCleanupWithoutFlags covers `-cleanup`, which runs without the
// bypass flags: the mark is unset but the table keeps its default, so a rule
// left by an earlier configured run is still removed while a foreign rule at
// the same priority is left alone.
func TestBypassCleanupWithoutFlags(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping netlink rule tests when not running as root")
	}

	addForeignBypassRule(t)

	configured, err := New(testBypassConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = configured.delBypassSrcRule()
	t.Cleanup(func() { _ = configured.delBypassSrcRule() })

	if err := configured.addBypassSrcRule(); err != nil {
		t.Fatalf("addBypassSrcRule: %v", err)
	}

	// What `-cleanup` builds: mark 0 (flag absent), table still defaulted.
	cleanupCfg, err := NewBypassConfig(0, testBypassTable)
	if err != nil {
		t.Fatalf("NewBypassConfig: %v", err)
	}
	if cleanupCfg.Enabled() {
		t.Fatal("cleanup config should report the bypass as disabled")
	}
	cleanup, err := New(cleanupCfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := cleanup.delBypassSrcRule(); err != nil {
		t.Fatalf("delBypassSrcRule: %v", err)
	}
	if got := countRulesAtPrioTable(t, bypassRulePrio, testBypassTable); got != 0 {
		t.Fatalf("cleanup left %d rules for table %d, want 0", got, testBypassTable)
	}
	if got := countRulesAtPrioTable(t, bypassRulePrio, foreignBypassTable); got != 1 {
		t.Fatalf("cleanup removed the foreign rule: got %d for table %d, want 1", got, foreignBypassTable)
	}
	if !foreignBypassRoutePresent(t) {
		t.Fatalf("cleanup flushed table %d", foreignBypassTable)
	}
}
