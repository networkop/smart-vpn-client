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
				failedCount = reduceByOne(failedCount)
				if !c.wg.IsUp() {
					logrus.Infof("Wireguard tunnel is not up, reconfiguring")
					if err := c.Connect(); err != nil {
						logrus.Infof("Reconfigure connect failed: %s; triggering rediscovery", err)
						c.discoverAndConnect(out)
					}
				}
			}
		case <-c.nextCh:
			logrus.Info("Re-election triggered")
			c.reelectNext(out)

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
	c.bestHeadend("")

	err = c.Connect()
	if err != nil {
		logrus.Infof("Connect failed: %s", err)
		if c.winner != nil {
			c.failedRegions[c.winner.ID] = time.Now()
			logrus.Debugf("Cooling down %s for %s", c.winner.ID, connectFailureCooldown)
		}
		return
	}

	if c.winner.connected {
		out <- c.winner.displayName()
	}
}

func reduceByOne(i int) int {
	if i > 0 {
		i--
		return i
	}
	return 0
}

// reelectNext re-runs discovery, measurement and headend selection,
// always excluding the current headend so a different region is guaranteed.
func (c *Client) reelectNext(out chan string) {
	if err := c.Discover(); err != nil {
		logrus.Infof("Re-election: discover failed: %s", err)
		return
	}
	c.Measure()

	excludeID := ""
	if c.winner != nil {
		excludeID = c.winner.ID
		logrus.Infof("Re-election: excluding current headend %s", c.winner.displayName())
	}

	c.bestHeadend(excludeID)

	logrus.Infof("Re-election: switching to %s", c.winner.displayName())
	if err := c.Cleanup(); err != nil {
		logrus.Panicf("Re-election cleanup failed: %s", err)
	}
	if err := c.Connect(); err != nil {
		logrus.Infof("Re-election connect failed: %s", err)
		c.failedRegions[c.winner.ID] = time.Now()
		return
	}
	if c.winner.connected {
		out <- c.winner.displayName()
	}
}
