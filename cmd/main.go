package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/networkop/smart-vpn-client/pkg/health"
	"github.com/networkop/smart-vpn-client/pkg/metrics"
	"github.com/networkop/smart-vpn-client/pkg/vpn"

	"github.com/sirupsen/logrus"

	"github.com/networkop/smart-vpn-client/pkg/vpn/pia"
)

const passwordEnvVar = "VPN_PWD"

var (
	version     = flag.Bool("v", false, "Display version")
	vpnProvider = flag.String("provider", "pia", "VPN provider [pia]")
	vpnUser     = flag.String("user", "", "VPN Username")
	vpnPass     = flag.String("pwd", "", "VPN Password")
	maxFail     = flag.Int("fails", 3, "Maximum number of failed healthchecks before reconnect")
	healthInt   = flag.Int("health", 10, "health-checking interval (sec)")
	ignoreVPNs  = flag.String("ignore", "", `A comma-separated list of VPN headends to ignore, e.g. "--ignore=uk_2"`)
	preferVPN   = flag.String("prefer", "", "VPN headend to prefer")
	latencyInt  = flag.Int("best", 30, "best VPN headend interval (sec)")
	cleanup     = flag.Bool("cleanup", false, "cleanup VPN configuration")
	metricsPort = flag.Int("metrics", 2112, "Port to expose /metrics on")
	debug       = flag.Bool("debug", false, "enable debug logging")

	supportedProviders = struct {
		pia string
	}{
		pia: "pia",
	}
)

func printVersion(gitCommit string) {
	fmt.Printf("Version: %s\n", gitCommit)
	os.Exit(0)
}

// Run the VPN client
func Run(gitCommit string) error {
	flag.Parse()

	if *version {
		printVersion(gitCommit)
	}

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var secret string
	if *vpnPass != "" {
		secret = *vpnPass
	} else {
		secret = os.Getenv(passwordEnvVar)
	}
	if (secret == "" || *vpnUser == "") && !*cleanup {
		return fmt.Errorf("VPN Username and Password must be provided")
	}

	ignores := strings.Split(*ignoreVPNs, ",")
	logrus.Infof("Ignored headends: %+v", ignores)

	var client vpn.Provider
	var err error

	switch *vpnProvider {
	case supportedProviders.pia:
		logrus.Info("VPN provider is PIA")
		client, err = pia.NewClient(*vpnUser, secret, *latencyInt, *maxFail, ignores, *preferVPN)
	default:
		flag.Usage()
		return fmt.Errorf("Unsupported/Undefined VPN provider: %v", *vpnProvider)
	}

	if err != nil {
		return fmt.Errorf("Failed to build VPN client: %s", err)
	}

	if *cleanup {
		return client.Cleanup()
	}

	err = client.Init()
	if err != nil {
		return err
	}

	healthCh := make(chan bool, 1)
	linkUpCh := make(chan string, 1)

	healthChecker := health.NewChecker(*healthInt)

	go healthChecker.Start(healthCh, linkUpCh)

	go client.Monitor(healthCh, linkUpCh)

	go metrics.Server(*metricsPort)

	select {}

}
