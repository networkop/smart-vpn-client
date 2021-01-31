package pia

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Monitor connectivity over the VPN tunnel
func (c *Client) Monitor(in chan bool, out chan string) {

	defer c.wg.Cleanup()

	ticker := time.NewTicker(time.Duration(c.measureInt) * time.Second)
	defer ticker.Stop()

	var failedCount int

	for {
		select {
		case healthy := <-in: // health probe

			logrus.Debugf("Current failedCount is %d", failedCount)

			if !healthy { // Failed Check
				failedCount++
				if failedCount >= c.maxFailed {
					logrus.Infof("maxFailed count exceeded, reconnecting...")
					c.discoverAndConnect(out)
					failedCount = 0

				}
			} else if c.winner == nil { // First connection attempt
				failedCount = 0
				c.discoverAndConnect(out)

			} else {
				reduceByOne(failedCount)
				if !c.wg.IsUp() {
					logrus.Infof("Wireguard tunnel is not up, reconfiguring")
					c.Connect()
				}
			}
		case <-ticker.C:
			logrus.Debugf("Triggering periodic latency measurement")
			c.Measure()
		}
	}

}

func (c *Client) discoverAndConnect(out chan string) {
	err := c.Cleanup()
	if err != nil {
		logrus.Panicf("Failed to cleanup the tunnel configuration: %s", err)
	}

	err = c.Discover()
	if err != nil {
		logrus.Infof("Discover failed: %s", err)
		return
	}

	c.Measure()
	c.bestHeadend()

	err = c.Connect()
	if err != nil {
		logrus.Infof("Connect failed: %s", err)
		return
	}

	if c.winner.connected {
		out <- c.winner.ID
	}
}

func reduceByOne(i int) int {
	if i > 0 {
		i--
		return i
	}
	return 0
}
