# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`smart-vpn-client` is a single Go binary that manages a WireGuard connection to a
commercial VPN provider (currently only Private Internet Access) on a Linux host.
Beyond dialling the tunnel, it discovers every available headend, probes their
latency, elects the fastest one, installs the routing/NAT plumbing, and keeps
watching the link — reconnecting on health-check failures or sustained latency
degradation.

It is a long-running daemon (`select {}` at the end of `cmd.Run`), normally run as
root or in a `--net=host --cap-add=NET_ADMIN` container. Almost every interesting
code path touches netlink, iptables, or a live network, which is why so little of
it is unit-testable in CI.

## Layout

| Path | Role |
|---|---|
| `main.go` | Thin entrypoint; holds the `GitCommit` ldflags var |
| `cmd/main.go` | Flag parsing, provider selection, goroutine wiring |
| `cmd/tool/main.go` | Standalone operator CLI shipped into the image as `/tmp/tool` |
| `pkg/vpn/provider.go` | The `Provider` interface every VPN backend implements |
| `pkg/vpn/pia/` | The PIA implementation (discover / measure / connect / monitor / cleanup) |
| `pkg/wg/` | All netlink + iptables work: link, addresses, routes, policy rules, masquerade |
| `pkg/health/` | Periodic HTTP probe, baseline, rolling window, degradation detection |
| `pkg/metrics/` | Prometheus registry + `/api/next` control endpoint (`metrics.go`), HTML dashboard (`web.go`) |
| `pkg/util/` | Tiny `exec.Command` builder used by the iptables code |

## Runtime architecture

`cmd.Run` starts four goroutines that communicate over two channels:

```
health.Checker.Start ──healthCh (bool)──▶ pia.Client.Monitor
                     ◀─linkUpCh (string)─┘
metrics.Server   (port 2112: /metrics, /api/next) ──TriggerNext()──▶ Monitor
metrics.WebServer(port 8080: HTML dashboard)      ──TriggerNext()──▶ Monitor
```

* `healthCh` carries one bool per probe interval. `Monitor` counts consecutive
  failures and reconnects once `-fails` is reached; successes decrement the
  counter rather than zeroing it.
* `linkUpCh` carries the name of a newly connected headend. The health checker
  uses it to reset its window and take a fresh latency baseline.
* `TriggerNext` is a non-blocking signal on a buffered channel of size 1 —
  redundant re-election requests are dropped, not queued.

`Monitor` is the single owner of connection state. Everything that mutates the
tunnel (`Cleanup`, `Discover`, `Measure`, `Connect`) runs on its goroutine, so
there is no locking around `Client.winner` / `Client.Headends`. **Keep it that
way**: if you add a code path that reconfigures the tunnel, route it through
`Monitor`'s select loop rather than calling `Connect` from another goroutine.

## The routing model (the part that is easy to break)

The client never replaces the host's default route. It uses IP policy routing:

| Priority | Rule | Purpose |
|---|---|---|
| 50 | `fwmark 0x51820 lookup main` | Discovery traffic escapes via the native interface |
| 100 | `lookup main suppress_prefixlength 0` | Specific main-table routes (the `/32` endpoint bypass, local subnets) still match; the main default route does not |
| 150 | `fwmark <mark> lookup <table>` | Optional split-tunnel bypass for a companion proxy; installed only when `-bypass-mark` is set |
| 1000 | `lookup 51820` | Everything else goes into the tunnel |

Table `51820` holds the tunnel's default route; deleting the `wg-pia` link drops
it automatically. Constants live in `pkg/wg/nl_rules.go`.

The split-tunnel bypass at priority 150 exists for `envoy-split-proxy`, which
marks its upstream sockets with `SO_MARK` so they leave via the native
interface (`docs/vpn-agent-integration.md` is the original brief). Its
placement is load-bearing: below 100 so LAN destinations still resolve from the
main table, above 1000 so marked traffic beats the tunnel. Both halves — the
rule and the bypass table's default route — are required; either alone diverts
nothing, which is why `vpn_bypass_rule_present` checks for both.

The discovery bypass is important and non-obvious: `pia.discoverClient` sets
`SO_MARK = wg.DiscoveryMark` on every socket via a `Dialer.Control` hook, so
headend discovery works even when the tunnel is up but black-holing traffic.
`EnsureDiscoveryBypass` is idempotent and called at the top of `Discover`, before
any tunnel exists. If you touch either side, change both.

## Conventions worth matching

* **Comments explain *why*, at length.** Several fixes in this repo are encoded
  as multi-line comments above the code (connection-pool leaks from per-request
  `http.Client`s, the CI Go/golangci-lint pinning, the tcp4-only dial, the
  reconnect-loop-on-slow-link timeout). Preserve them; add the same kind when you
  fix something subtle.
* **Long-lived `http.Client`s only.** `discoverClient`, `Health.client`, and
  `Client.http` are constructed once. Creating a client (and therefore a
  transport) per request leaks sockets and goroutines here — this has bitten the
  project already.
* **Failures degrade, they don't crash.** `bestHeadend` returns `false` instead of
  panicking when nothing is selectable; failed regions go into `failedRegions`
  with a 5-minute cooldown. The two `logrus.Panicf` calls are for cleanup
  failures only, where continuing would leave the host's routing broken.
* Logging is `logrus`; operational events at `Info`, per-probe chatter at `Debug`.
* Errors returned to the user are `fmt.Errorf` with context, no custom types.

## Build, test, lint

```bash
make                 # test + build ./smart-vpn-client (CGO_ENABLED=0)
make test            # sudo go test -race ./... -v
make lint            # golangci-lint run (no config file; defaults)
make docker          # multi-arch buildx build + push, needs DOCKER_IMAGE
make update-deps     # go get -u ./... && go mod tidy
```

`make test` uses `sudo` because `pkg/wg` tests manipulate real netlink rules and
iptables. They call `t.Skip` when `os.Geteuid() != 0`, so plain `go test ./...`
passes but silently covers less. When changing anything in `pkg/wg`, run the
tests as root.

CI (`.github/workflows/ci.yml`) pins `GO_VERSION` and `GOLANGCI_LINT_VERSION` to
an exact, tested pair, and builds golangci-lint from source. Do not float either
one independently — the header comment in that file explains why the export-data
format breaks. Bump them together and confirm `make lint` locally first.

## Things to know before changing behaviour

* **Adding a provider**: implement `vpn.Provider`, then add a case in the
  `switch *vpnProvider` in `cmd/main.go` and a name in `supportedProviders`.
  Everything below `pkg/wg` is provider-agnostic.
* **`-cleanup` runs without credentials.** The credential check in `cmd.Run` is
  explicitly skipped for it. Any new required config must respect that.
* **The dashboard binds to one interface** (`-web-iface`, default `eth0`, first
  IPv4 address) while `/metrics` binds to all interfaces. That asymmetry is
  deliberate.
* **TLS to PIA endpoints uses a hand-rolled verifier** (`buildPIAHTTPClient`):
  `InsecureSkipVerify` is on so Go's hostname check can't reject CN-only certs,
  and `VerifyPeerCertificate` does chain verification manually, falling back to
  CN matching *only* when the chain verifies and the cert has no SANs. This is
  security-sensitive; `connect_test.go` covers both branches — extend it if you
  touch the logic.
* **The bypass fails loudly on purpose.** A missing bypass rule is invisible
  from the outside — marked traffic still flows, it just exits via the VPN
  address after `EnsureMasquerade` rewrites it. That cost someone a debugging
  session, so `ensureBypass` logs at WARN (not DEBUG), exports
  `vpn_bypass_enabled` / `vpn_bypass_rule_present`, and shows a red **MISSING**
  on the dashboard. Keep all three when changing that code. Its failures are
  non-fatal by design: the tunnel is fine without the bypass, and failing the
  connect over a secondary feature would take the VPN down.
* **`delBypassSrcRule` matches on priority alone**, unlike the other rule
  deleters, because `-cleanup` runs without the bypass flags and would
  otherwise strand a rule from an earlier configured run.
* **Health tuning constants** live at the top of `pkg/health/health.go`
  (`baselineSamples`, `windowSize`, `degradationFactor`, `degradationQuorum`,
  `minSamples`). The baseline is a median of samples and degradation requires a
  quorum of the window, specifically so a single latency spike does not cause a
  reconnect.

Note: `README.md` describes the degradation threshold as `10 x baseline` and the
default probe URL as `http://1.1.1.1`; the code currently uses `5.0` and
`http://cp.cloudflare.com/generate_204`. Trust the code, and consider fixing the
README when you are next in that area.

## Docs

`README.md` is the user-facing documentation: full CLI flag table, Docker usage,
routing design, and release/publishing setup. Update it whenever you add or
change a flag, a port, or the routing behaviour.
