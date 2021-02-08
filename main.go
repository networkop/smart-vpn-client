package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/networkop/smart-vpn-client/cmd"
)

var (
	GitCommit string
)


func main() {
	logrus.Info("Starting VPN Connector")

	if err := cmd.Run(GitCommit); err != nil {
		logrus.Info(err)
		os.Exit(1)
	}

}
