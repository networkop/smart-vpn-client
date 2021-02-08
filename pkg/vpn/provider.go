package vpn

// Provider is generic VPN provider interface
type Provider interface {
	Init() error
	Discover() error
	Measure()
	Connect() error
	Monitor(chan bool, chan string)
	Cleanup() error
}
