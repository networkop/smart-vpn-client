package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/networkop/smart-vpn-client/cmd"
)

func main() {
	logrus.Info("Starting VPN Connector")

	if err := cmd.Run(); err != nil {
		logrus.Info(err)
		os.Exit(1)
	}

}
