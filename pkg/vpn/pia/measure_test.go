package pia

import (
	"testing"
	"time"
)

func buildFakeRegion(name string, latency time.Duration) *region {
	return &region{
		ID:      name,
		latency: latency,
		Servers: piaServerInfo{
			WG: []piaServer{
				{CN: name},
			},
		},
	}
}

func equalRegions(one, two *region) bool {
	if one.ID != two.ID {
		return false
	}
	if one.latency != two.latency {
		return false
	}
	return true
}

func TestBestHeadend(t *testing.T) {
	var c Client

	c.maxBestLatency = 1 * time.Hour

	c.Headends = map[string]*region{
		"a": buildFakeRegion("a", 1*time.Second),
		"b": buildFakeRegion("b", 3*time.Second),
		"c": buildFakeRegion("c", 2*time.Second),
	}
	c.bestHeadend()
	if !equalRegions(c.winner, buildFakeRegion("a", 1*time.Second)) {
		t.Fatalf("Wrong best headend")
	}
}
