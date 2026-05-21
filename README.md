# Smart VPN client

Performs all the standard functions of a VPN client, i.e. manages a connection to a VPN headend. The "smart" functionality includes:

* Automatic discovery and probing of all available VPN headends. The client will connect to the headend with the lowest round-trip time.
* Automatic management of routing and NAT masquerade rules required for a VPN client. Uses Linux IP policy routing (custom table 51820 + `ip rule`) so the host's existing default route via eth0 is never replaced — only VPN-bound traffic is steered through the tunnel.
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

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `-user` | — | VPN username (**required**) |
| `-pwd` | — | VPN password. Prefer the `VPN_PWD` environment variable to avoid the password appearing in shell history |
| `-provider` | `pia` | VPN provider. Currently only `pia` (Private Internet Access) is supported |
| `-ignore` | — | Comma-separated list of headend names to skip during discovery, e.g. `-ignore=uk_2,us_1` |
| `-prefer` | — | Headend name to prefer during election. Still falls back to lowest-latency if the preferred headend is unreachable |
| `-best` | `30` | How often (seconds) to re-probe all headends and re-elect the best one |
| `-health` | `10` | Health-check interval in seconds |
| `-probe` | `http://1.1.1.1` | URL used for health checks. A successful HTTP response means the tunnel is healthy |
| `-fails` | `3` | Number of consecutive failed health checks before the connection is re-established |
| `-metrics` | `2112` | Port for the Prometheus `/metrics` endpoint and `/api/next` control endpoint (binds to all interfaces) |
| `-web` | `8080` | Port for the HTML dashboard (binds to eth0 only by default) |
| `-web-iface` | `eth0` | Interface whose first IPv4 address the dashboard binds to |
| `-cleanup` | `false` | Tear down all VPN configuration (routes, rules, interface) and exit. No credentials required |
| `-debug` | `false` | Enable debug-level logging |
| `-v` | `false` | Print the build version and exit |

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

## Docker image publishing

This repository publishes multi-arch Docker images when code is pushed to `main` or when a tag matching `v*` is created. The GitHub Action uses Docker Hub credentials stored in repository secrets. To enable publishing, add these secrets to your repository settings:

- `DOCKERHUB_USERNAME` — your Docker Hub username
- `DOCKERHUB_PASSWORD` — a Docker Hub access token or password

Images pushed:
- `networkop/smart-vpn-client:latest` (on push to main)
- `networkop/smart-vpn-client:<commit-sha>` (always)
- `networkop/smart-vpn-client:<tag>` (when you push a tag like `v1.2.3`)

If you still see a 4-year-old image as `latest` after enabling the workflow, make sure the action completed successfully and that your Docker Hub credentials are correct. Creating a new tag (e.g. `git tag v0.0.1 && git push origin v0.0.1`) will force the action to push a tag-based image.

## Routing design

The client uses Linux IP policy routing to forward traffic through the WireGuard tunnel without touching the host's main routing table:

| What | Where | How |
|---|---|---|
| Default route via `wg-pia` | Custom table 51820 | Added on connect, removed with the link |
| Bypass route for VPN endpoint `/32` | Main table via eth0 | Prevents the encrypted UDP stream from looping back into the tunnel |
| `ip rule` priority 100 | `lookup main suppress_prefixlength 0` | Matches specific routes (e.g. the bypass `/32`) in the main table, but ignores its default route |
| `ip rule` priority 1000 | `lookup 51820` | Steers all remaining traffic into the WireGuard table |
| Default route via eth0 | Main table | **Left untouched** |

On cleanup, both `ip rule` entries and the bypass route are removed. The table 51820 default route is removed automatically by the kernel when the `wg-pia` interface is deleted.

## Tests

Run unit tests with:

```bash
go test ./...
```

Routing and rule tests require `NET_ADMIN` and run as root only; they are skipped automatically otherwise:

```bash
sudo go test ./pkg/wg/ -run TestRules -v
```


## HTTP servers

The daemon starts two HTTP servers:

### Prometheus metrics — port 2112 (all interfaces)

Exposes `/metrics` in Prometheus text format and a `/api/next` control endpoint. Configurable with `-metrics <port>`.

Can be scraped with Grafana Agent (or Prometheus) like this:

```yaml
prometheus:
  configs:
      scrape_configs:
      - job_name: vpn
        scrape_interval: 5s
        static_configs:
        - targets: ['localhost:2112']
```

### HTML dashboard — port 8080 (eth0 only)

A browser-based health monitor at `http://<eth0-ip>:8080/`. It shows the rolling latency chart, region, baseline, threshold and current status, auto-refreshes every 5 seconds, and has a **Re-elect headend** button.

The dashboard binds only to the first IPv4 address of `eth0` (configurable with `-web-iface <iface>`) so it is never reachable via the WireGuard tunnel. The port is configurable with `-web <port>`.

Example with non-default ports:

```
sudo VPN_PWD=<VPN_PASSWORD> ./smart-vpn-client -user <VPN_USERNAME> -metrics 9090 -web 9091
```

## tool — operator utility

`tool` is a small CLI binary bundled in the Docker container at `/tmp/tool`. It contacts the daemon via the metrics/control port and provides two subcommands:

```
tool metrics          # one-shot ASCII health chart
tool metrics -watch   # keep the chart refreshing in place (Ctrl-C to quit)
tool next             # ask the daemon to re-elect the best VPN headend
```

Usage inside a running container:

```bash
# Print a snapshot of the health chart
docker exec vpn /tmp/tool metrics

# Live-refresh every 5 seconds
docker exec vpn /tmp/tool metrics -watch

# Change the refresh interval
docker exec vpn /tmp/tool metrics -watch -interval 10

# Trigger headend re-election
docker exec vpn /tmp/tool next

# Point at a non-default daemon address
docker exec vpn /tmp/tool -addr http://localhost:9090 metrics
```

The binary can also be run outside the container as long as the daemon's metrics port is reachable.

## Manual build

Clone this repo and run: 

```
make
```