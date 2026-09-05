# Integrating with smart-vpn-client

`envoy-split-proxy` marks bypassed upstream sockets with an fwmark. Something on
the host has to turn that mark into a routing decision. When the box also runs
[smart-vpn-client](https://github.com/networkop/smart-vpn-client), that agent
already owns the `ip rule` set, so it is the right place for the rule to live.

The rest of this file is a task brief you can hand to a coding agent working in
the `smart-vpn-client` repo.

---

## Task: add a bypass fwmark rule

### Background

`smart-vpn-client` installs three ip rules (`pkg/wg/nl_rules.go`):

| prio | rule | purpose |
|---|---|---|
| 50 | `fwmark 0x51820 lookup main` | PIA discovery traffic escapes the tunnel |
| 100 | `lookup main suppress_prefixlength 0` | specific main-table routes match, main's default does not |
| 1000 | `lookup 51820` | everything else goes to `wg-<provider>` |

A companion process (`envoy-split-proxy`) proxies selected traffic and wants it
to leave via the native interface rather than the tunnel. It binds those
upstream sockets to the native interface's address and sets `SO_MARK` on them
(default `0x51821`, configurable).

Rule 1000 currently catches that traffic anyway, and `EnsureMasquerade`'s
`POSTROUTING -o wg-<provider> -j MASQUERADE` then rewrites the source to the
tunnel address. The result is a silent failure: connections succeed, no error is
logged anywhere, and the only symptom is that remote servers see the VPN exit
address. This cost a full debugging session to find, so the observability
requirement below is not optional.

### Requirements

1. **New rule.** Install, between prios 100 and 1000:

   ```
   ip rule add fwmark <mark> lookup <table> priority 150
   ```

   Suggested constant `bypassRulePrio = 150`. It must sit *below* the
   `suppress_prefixlength` rule so LAN destinations still resolve from `main`
   and never reach the bypass table, and *above* the catch-all so it beats the
   tunnel.

2. **New table.** Populate it with a single default route via the native
   gateway:

   ```
   ip route replace default via <gw> dev <native-iface> table <table>
   ```

   Derive the gateway and interface from the main table's default route as it
   exists *before* the tunnel is created — the agent already captures this to
   build `addBypassRoute`, so reuse that rather than adding new discovery.

3. **CLI flags**, all optional, feature off unless `-bypass-mark` is set:

   | flag | default | meaning |
   |---|---|---|
   | `-bypass-mark` | `0` (disabled) | fwmark to match; must not collide with `DiscoveryMark` (`0x51820`) |
   | `-bypass-table` | `51821` | routing table for bypassed traffic |

4. **Lifecycle.** Follow the existing pattern exactly: `addBypassSrcRule` /
   `delBypassSrcRule` / `getBypassSrcRule`, called from `ensureRules` and
   `delRules`. `ensureRules` runs on every reconnect and must stay idempotent —
   check for the rule before adding it, as the other three do.

5. **Observability.** This is the point of the exercise.
   - Export a gauge (e.g. `vpn_bypass_rule_present`) alongside the existing
     Prometheus metrics, 1 when both rule and table route are in place.
   - Surface the same on the HTML dashboard next to the tunnel state.
   - Log at WARN, not DEBUG, when `-bypass-mark` is set but the rule is missing
     after `ensureRules`.

6. **Tests.** `pkg/wg/nl_rules_test.go` already covers the other rules; extend
   it in the same style, including the idempotent-reconnect case (call
   `ensureRules` twice, assert one rule).

### Acceptance

On a host with the tunnel up and `-bypass-mark 0x51821`:

```
$ ip rule show | grep 150
150:    from all fwmark 0x51821 lookup 51821

$ ip route show table 51821
default via 172.16.0.1 dev eth0

# marked traffic goes direct...
$ ip route get 1.1.1.1 mark 0x51821
1.1.1.1 via 172.16.0.1 dev eth0 table 51821

# ...unmarked traffic still uses the tunnel
$ ip route get 1.1.1.1
1.1.1.1 dev wg-pia table 51820 src 10.31.196.44

# and LAN destinations are unaffected (matched at prio 100, not 150)
$ ip route get 172.16.0.1 mark 0x51821
172.16.0.1 dev eth0
```

`ip route get ... mark` asks the kernel the same question the rule answers, so
it verifies the policy without generating any traffic.

`ensureRules` called twice leaves exactly one rule at priority 150, and
`delRules` removes both the rule and the table's default route.

### Out of scope

- Changing rules 50, 100 or 1000
- Anything in `envoy-split-proxy` — the mark is already set there
- IPv6 (the agent is IPv4-only today; keep it that way for this change)

---

## Notes for whoever runs this

`SO_MARK` is set by Envoy on its own upstream sockets, so `CAP_NET_ADMIN` goes
on the **envoy** container, not on the `envoy-split-proxy` control plane. If you
would rather not grant it, run with `-bypass-mark 0` and match on the source
address instead:

```
ip rule add from <bypass-ip> lookup <table> priority 150
```

That works with no extra capability, but it is broader: *any* process that binds
an outbound socket to that address escapes the tunnel, not just Envoy.
