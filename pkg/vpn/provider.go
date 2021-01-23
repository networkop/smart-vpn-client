package vpn

import (
	"time"
)

const maxLatency = 50 * time.Second

// Provider is generic VPN provider interface
type Provider interface {
	Init() error
	Discover() error
	Measure()
	Connect() error
	Monitor(chan bool, chan bool)
	Cleanup() error
}
