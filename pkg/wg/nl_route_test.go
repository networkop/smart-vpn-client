package wg

import (
	"testing"
)

func TestCheckRoutingNilLink(t *testing.T) {
	t.Parallel()
	tnl := &Tunnel{intfName: "nonexistent-wg-test"}
	// checkRouting should return an error (not panic) when link is missing
	if err := tnl.checkRouting(); err == nil {
		t.Fatalf("expected error from checkRouting when link is missing")
	}
}

func TestIsUpNilLink(t *testing.T) {
	t.Parallel()
	tnl := &Tunnel{intfName: "nonexistent-wg-test"}
	if tnl.IsUp() {
		t.Fatalf("expected IsUp to be false when link is missing")
	}
}
