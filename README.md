# Smart VPN client

Performs all the standard functions of a VPN client, i.e. manages a connection to a VPN headend. The "smart" functionality includes:

* Automatic discovery and probing of all available VPN headends. The client will connect to the headend with the lowest round-trip time.
* Automatic management of routing and NAT masquerade rules required for a VPN client.
* Periodic VPN connection healthchecks - if more than 3 consecutive healthchecks fail, connection is automatically re-established.
* VPN connection QoS tracking -- takes a baseline round-trip time measurement when a new connection is established and triggers reconnect when the weighted average latency exceeds 10 x baseline for 3 consecutive measurements.


## Supported Providers

* [Private Internet Access](https://www.privateinternetaccess.com/) with Wireguard as the VPN tunnel transport (requires wireguard kernel module).


## Installation

To install run:

```
go get github.com/networkop/smart-vpn-client
```

The binary can be found in `$GOPATH/bin/`:

```
# ls -lah $GOPATH/bin/smart-vpn-client
-rwxr-xr-x 1 root root 7.9M Jan 23 14:57 /go/bin/smart-vpn-client
```


## Run

The binary requires `NET_ADMIN` capabilities in order to set up interfaces and manipulate routing, therefore the simplest way is to run it with `sudo`:

```
sudo VPN_PWD=<VPN_PASSWORD> ./smart-vpn-client -user <VPN_USERNAME>
```

## Using Docker

Build your own docker image with:

```
DOCKER_IMAGE=<YOUR_IMAGE_NAME:TAG> make docker
```

Alternatively, pull a pre-built docker image from dockerhub:

```
docker pull networkop/smart-vpn-client:latest
```

Start a smart vpn client process:

```
docker run -e VPN_PWD=<VPN_PASS> -d --restart=always --name vpn --net=host --cap-add=NET_ADMIN networkop/smart-vpn-client -user <VPN_USER>
```

To cleanup all config, first stop the container with `docker rm -f vpn` and then do:

```
docker run --net=host --cap-add=NET_ADMIN networkop/smart-vpn-client -cleanup
```

The last command will run to completion and the container will stop.

To view the container logs at any stage do:

```
docker logs vpn
```

## TLS compatibility with legacy CN-only certificates

Some VPN headends present certificates that rely on the legacy X.509 Common Name (CN) field instead of SANs. Because modern Go performs hostname verification against SANs, this client implements a conservative fallback:

- The client validates the server certificate chain against the fetched CA.
- It first attempts normal hostname verification (including SANs).
- If the chain verifies but hostname verification fails and the certificate has no SANs, it will accept the certificate when the certificate CommonName matches the expected server name. This behavior is documented and logged.

If you'd prefer to temporarily re-enable legacy CN matching globally for debugging, you can set the environment variable `GODEBUG=x509ignoreCN=0` for the process or container. This is not recommended for production.

## Automated releases and dependency updates

- goreleaser is configured with `.goreleaser.yml` and a release workflow is triggered on Git tags matching `v*`.
- Dependabot is enabled to ensure security vulnerabilities are detected and fixed automatically. To keep regular dependency churn under control, this repository uses a scheduled GitHub Action (runs Jan 1 and Jul 1) to perform full dependency upgrades and open a PR every six months. Dependabot will still open PRs for security advisories as soon as they're detected.

## Tests

Run unit tests with:

```bash
go test ./...
```


## Monitor

By default, all healthchecks metrics are exposed on `localhost:2112/metrics` and can be scraped with Grafana Agent (or Prometheus) like this:

```
prometheus:
  configs:
      scrape_configs:
      - job_name: vpn
        scrape_interval: 5s
        static_configs:
        - targets: ['localhost:2112']
```

## Manual build

Clone this repo and run: 

```
make
```