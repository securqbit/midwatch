# midwatch CLI reference

Complete documentation for the `midwatch` command line: every command, every flag,
every exit code, the exact shape of each output format, and the full catalogue
of level codes and finding IDs.

For what the checks mean and why they work, see the [README](../README.md).
This document is about how to drive the tool.

- [Synopsis](#synopsis)
- [Commands](#commands)
- [Flags](#flags)
- [Argument parsing rules](#argument-parsing-rules)
- [Exit codes](#exit-codes)
- [Output formats](#output-formats)
  - [Human output (default)](#human-output-default)
  - [Quiet output](#quiet-output)
  - [JSON output](#json-output)
- [Levels](#levels)
- [Findings](#findings)
- [Scoring and verdicts](#scoring-and-verdicts)
- [Environment variables](#environment-variables)
- [Signals and cancellation](#signals-and-cancellation)
- [What midwatch connects to](#what-midwatch-connects-to)
- [Recipes](#recipes)
- [Troubleshooting](#troubleshooting)
- [Building and installing](#building-and-installing)

---

## Synopsis

```
midwatch <command> [flags]
```

A command selects which check modules run. Flags are the same for every
command; ones that do not apply to the selected module are simply inert
(`--targets` only affects `tls`, `--deep` affects `tls` and `comms`).

```sh
midwatch scan                              # every module, then an overall verdict
midwatch tls --deep                        # one module, with the extra probes
midwatch scan --quiet --fail-on medium     # CI and monitoring
midwatch scan --json > report.json         # machine readable
```

## Commands

| Command | Runs | Notes |
|---|---|---|
| `scan` | `tls`, `dns`, `http`, `egress`, `comms`, `time` | The usual choice. All six run concurrently but stream in that fixed order, then a verdict block closes the run. |
| `tls` | TLS interception only | Honours `--targets` and `--deep`. |
| `dns` | DNS interception only | Reads `/etc/resolv.conf` for the system resolvers. |
| `http` | HTTP path integrity only | |
| `egress` | Egress policy only | |
| `comms` | Messenger, call and conferencing reachability only | Honours `--deep`. |
| `time` | Time source integrity only | |
| `version`, `--version`, `-v` | Prints build information, exits `0` | |
| `help`, `--help`, `-h` | Prints usage to **stdout**, exits `0` | |

Single-module commands print the same module block a `scan` would, followed by
the verdict block. The verdict is computed from whatever ran, so a `midwatch tls`
score reflects TLS findings only.

**Special cases**

- `midwatch` with no arguments prints usage to **stdout** and exits `2`.
- `midwatch <unknown>` prints an error and usage to **stderr** and exits `2`.
- `midwatch --json` (a bare flag with no command) is treated as `midwatch scan --json`.
  Any leading flag implies a full scan.

`version` output is two lines:

```
$ midwatch version
midwatch 1.0.0 (a1b2c3d, 2026-02-11)
linux/amd64, go1.25.0
```

A released binary — one built from a tagged commit by the
[Makefile](../Makefile) or [.goreleaser.yaml](../.goreleaser.yaml), or installed
with `go install github.com/securqbit/midwatch/cmd/midwatch@v1.0.0` — is named
after its tag. A build from an untagged commit is named after the commit
instead, since there is no release to name it after:

```
midwatch dev-a1b2c3d (2026-02-11)          # untagged commit
midwatch dev-a1b2c3d-dirty (2026-02-11)    # ...with uncommitted changes
midwatch dev                               # built outside a git checkout
```

The commit and date come from the toolchain's own build stamp, so they are
present even without linker flags. What is never printed is the Go pseudo
version (`v0.0.0-20260211092241-a1b2c3d4e5f6`) that `go install` assigns to an
untagged module.

## Flags

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--json` | bool | `false` | Emit the whole run as one JSON object on stdout. Suppresses streaming and colour. |
| `--quiet` | bool | `false` | Print only tab-separated levels, findings and the verdict. Suppresses the banner and evidence tables. |
| `--deep` | bool | `false` | Run additional, slower and noisier probes. Used by the `tls` and `comms` modules. |
| `--timeout` | duration | `8s` | Per-probe timeout. Must be positive. |
| `--targets` | string | built-in list | Comma-separated `host[:port]` list for the TLS module, replacing the built-in endpoints. |
| `--fail-on` | string | `high` | Exit `1` when a finding of this severity or worse was reported. One of `info`, `low`, `medium`, `high`, `critical`, `never`. |
| `--color` | bool | `false` | Force ANSI colour even when stdout is not a terminal. |
| `--no-color` | bool | `false` | Disable ANSI colour. Wins over `--color`. |

### `--timeout`

The value is a Go duration string: `500ms`, `3s`, `1m30s`. It bounds each
individual probe, **not** the whole run. Probes inside a module run
concurrently, and the modules run concurrently with each other, so a `scan`
costs roughly its single slowest probe rather than the sum of them. Output is
still printed in module order, so a slow early module delays what you see even
though the later ones have already finished.

Two probes deliberately ignore a longer value and cap themselves at `3s`: the
DNS and NTP blackhole probes, whose expected outcome is silence. A device
intercepting port 53 or 123 answers in milliseconds, so waiting longer only
penalises honest networks.

`--timeout 0` or a negative value is an error (exit `2`).

### `--targets`

Applies to the `tls` module only. Entries are trimmed, empty entries dropped,
and any entry without a `:` gets `:443` appended:

```sh
midwatch tls --targets bank.example.com                    # → bank.example.com:443
midwatch tls --targets intranet.corp:8443,vpn.corp:443
```

Supplying targets also **relaxes the protocol-degradation signals**. The
built-in endpoints are known to support TLS 1.3, HTTP/2 and Certificate
Transparency, so a missing feature there is a property of the path. A target
you chose may simply not support them, so `tls.tls13-blocked` and
`tls.alpn-stripped` are not raised, and L1 (metadata visibility) is not derived,
for custom target lists. Certificate-based detection is unaffected.

The downgrade probe (a deliberate TLS 1.0 handshake) always runs against the
**first** target in the list.

### `--fail-on`

Compared against the worst severity across every module in the run:

| Value | Exits `1` when the run contains |
|---|---|
| `info` | any finding at all |
| `low` | a low, medium, high or critical finding |
| `medium` | a medium, high or critical finding |
| `high` *(default)* | a high or critical finding |
| `critical` | a critical finding |
| `never` | never — always exits `0` unless the run itself failed |

Severity names are matched case-insensitively (`HIGH` works). The literal
`never` must be lowercase; `NEVER` is rejected as an invalid value.

### Colour resolution

Colour is enabled only when all of the following hold:

1. `--no-color` was not passed and `--json` was not passed.
2. Either `--color` was passed, **or** `NO_COLOR` is unset, `TERM` is not
   `dumb`, and stdout is a character device (a terminal).

`--no-color` and `--json` are checked first, so they beat `--color`. Piping into
`less`, a file, or another process therefore produces plain text by default, and
`--color | cat` is the way to keep the escapes.

## Argument parsing rules

midwatch uses Go's standard `flag` package, which has a few behaviours worth
knowing:

- Single and double dashes are equivalent: `-json` and `--json` are the same
  flag.
- Values may be attached or separate for non-boolean flags: `--timeout=3s` and
  `--timeout 3s` both work.
- Boolean flags **must** use the attached form to pass a value:
  `--json` sets it true, `--json=false` sets it false, and `--json false` sets
  it true and leaves `false` as a stray argument.
- Parsing stops at the first non-flag argument, and stray arguments are ignored
  silently. `midwatch scan --json extra` runs a JSON scan; `midwatch --json scan`
  also runs a JSON scan, because the leading flag already implied `scan` and
  the trailing `scan` is discarded.
- Flags must come **after** the command for the command to be honoured.
- `--help` anywhere in the flag list prints usage and exits `0`.

## Exit codes

| Code | Constant | Meaning |
|---|---|---|
| `0` | `ExitClean` | The run completed and nothing met the `--fail-on` threshold. |
| `1` | `ExitFinding` | The run completed and a finding at or above `--fail-on` was reported. |
| `2` | `ExitError` | midwatch could not complete the requested checks: bad usage, an invalid flag value, an interrupted run, or a failure writing JSON. |

These are part of the interface — CI and monitoring depend on them, so they
will not be reshuffled.

Note the distinction: exit `2` means *midwatch did not finish*, never *midwatch found
something bad*. A module that could not reach any endpoint records a note and an
inconclusive level, but the run itself still exits `0` or `1`.

## Output formats

Exactly one of three formats is produced. `--json` wins over `--quiet`.

### Human output (default)

Written to stdout as the run progresses:

1. A banner with the version, platform and start time.
2. One block per module **as it finishes**, so a long scan shows results early.
   Each block has a rule with the module title, the level badge and summary,
   then the evidence sections, then the findings, then any notes.
3. A `VERDICT` block: a score bar, `NN/100`, the verdict sentence, a count of
   findings by severity, the per-module level codes, and elapsed time.

Row status glyphs are `ok`, `info`, `warn`, `bad` and `skip`. `skip` means the
probe could not run (unreachable endpoint), which is an absence of evidence, not
evidence of cleanliness.

### Quiet output

`--quiet` suppresses the banner, the streaming blocks and the evidence tables.
What remains is tab-separated and stable enough to parse with `cut` or `awk`:

```
<module-id>	<LEVEL-CODE>	<level name>          # one per module that produced a level
<SEVERITY>	<finding-id>	<finding title>       # one per finding, severity uppercased
<score>/100	<verdict>                             # always the last line
```

```sh
$ midwatch time --quiet
time	T0	Time source intact
100/100	Clean — no interception detected on this network
```

Findings follow their module's level line and are ordered most severe first.
Note that the verdict on the final line is bold-wrapped when colour is enabled,
so pass `--no-color` if you intend to parse it.

### JSON output

`--json` writes one indented JSON object to stdout and nothing else. Colour is
disabled automatically. Field names are stable.

```json
{
  "tool": "midwatch",
  "version": "1.0.0",
  "started_at": "2026-02-11T09:22:41.626616-05:00",
  "duration_ms": 4204,
  "platform": "linux/amd64",
  "modules": [
    {
      "id": "time",
      "title": "Time source integrity",
      "kind": "posture",
      "level": {
        "score": 0,
        "code": "T0",
        "name": "Time source intact",
        "summary": "Independent time sources agree with each other and with this machine's clock, so the validity windows your security decisions depend on are being measured correctly."
      },
      "sections": [
        {
          "title": "time sources",
          "rows": [
            { "status": "ok",   "label": "Cloudflare", "value": "+360ms",     "note": "local clock agrees with this source" },
            { "status": "skip", "label": "NTP Pool",   "value": "unreachable", "note": "no reply" }
          ]
        }
      ],
      "duration_ms": 4204
    }
  ],
  "score": 100,
  "verdict": "Clean — no interception detected on this network"
}
```

#### Top level

| Field | Type | Notes |
|---|---|---|
| `tool` | string | Always `"midwatch"`. |
| `version` | string | Release version (`"1.0.0"`), or `"dev-<commit>"` for a build from an untagged commit. |
| `started_at` | string | RFC 3339 with the local offset. |
| `duration_ms` | number | Whole-run wall clock. |
| `platform` | string | `GOOS/GOARCH`. |
| `modules` | array | One entry per module that ran, in run order. |
| `score` | number | 0–100, see [Scoring](#scoring-and-verdicts). |
| `verdict` | string | One of four sentences, see [Scoring](#scoring-and-verdicts). |

#### Module

| Field | Type | Notes |
|---|---|---|
| `id` | string | `tls`, `dns`, `http`, `egress`, `comms` or `time`. |
| `title` | string | Human readable module name. |
| `kind` | string | `interception`, `censorship` or `posture`. The first two drive the score and the verdict; `posture` drives neither. |
| `level` | object | Omitted if the module produced no level. |
| `level.score` | number | 0–4 position on the ladder. |
| `level.code` | string | `L2`, `D4`, `H0`, `E1`, `C3`, `T2`, or an inconclusive `L?` / `C?` / `T?`. |
| `level.name` | string | Short name for the level. |
| `level.summary` | string | Prose explanation. |
| `sections` | array | Evidence tables. Omitted when empty. |
| `sections[].title` | string | See [section titles](#section-titles) below. |
| `sections[].rows[].status` | string | `ok`, `info`, `warn`, `bad` or `skip`. |
| `sections[].rows[].label` | string | Row subject, e.g. an endpoint or resolver. |
| `sections[].rows[].value` | string | Optional measured value. |
| `sections[].rows[].note` | string | Optional explanation. |
| `findings` | array | Sorted most severe first. Omitted when empty. |
| `findings[].id` | string | Stable identifier, see [Findings](#findings). |
| `findings[].title` | string | One-line statement. |
| `findings[].severity` | string | `info`, `low`, `medium`, `high` or `critical`. |
| `findings[].detail` | string | Optional prose. |
| `findings[].evidence` | array | Optional supporting strings. |
| `findings[].kind` | string | Present only when the finding measures something other than its module's `kind`, and then it wins for scoring. Currently only `comms.intercepted`, which is `interception` inside a `censorship` module. |
| `errors` | array | Module-level problems (a check that could not run). Omitted when empty. |
| `duration_ms` | number | Module wall clock. |

Severity and status are emitted as lowercase names, never as ordinals.

#### Section titles

| Module | Sections |
|---|---|
| `tls` | `endpoints`, `downgrade`, `deep` (`--deep` only) |
| `dns` | `path`, `configuration`, `transparent redirection`, `resolver reachability`, `answer integrity`, `query integrity`, `cross-resolver comparison`, `dnssec`, `encrypted dns` |
| `http` | `local configuration`, `captive portal`, `far-end view`, `intermediaries`, `downgrade` |
| `egress` | `path`, `tcp egress`, `udp egress`, `ipv6` |
| `comms` | `path`, `call media`, `services`, `blocking method` |
| `time` | `time sources`, `transparent redirection` |

Sections appear only when they have at least one row, so do not assume a fixed
set.

## Levels

Each module places itself on a 0–4 ladder. Higher is worse. `?` codes mean the
module could not gather enough evidence to judge.

| Module | Codes |
|---|---|
| `tls` | `L0` no interception · `L1` metadata visibility · `L2` selective decryption · `L3` full decryption via an installed root · `L4` untrusted interception · `L?` inconclusive (no handshake completed) |
| `dns` | `D0` clean · `D1` resolver lock-in · `D2` transparent redirection · `D3` answer manipulation · `D4` answer forgery · `D?` inconclusive (a tunnel answered port 53, so the network's DNS was never reached) |
| `http` | `H0` no tampering · `H1` transparent proxying · `H2` response substitution · `H3` content interception |
| `egress` | `E0` open egress · `E1` partially filtered · `E2` privacy protocols filtered · `E3` web-only egress |
| `comms` | `C0` unrestricted · `C1` calls degraded · `C2` selective blocking · `C3` private messengers blocked, or communication heavily restricted · `C4` communication intercepted · `C?` inconclusive (the control endpoint was unreachable, so this machine may simply be offline) |
| `time` | `T0` intact · `T1` clock skew · `T2` time source under network control · `T?` inconclusive (no source reachable) |

`egress` and `time` are **posture** modules: they describe policy, and their
levels are deliberately excluded from the verdict. A restrictive firewall is a
choice; a forged certificate is an attack.

`comms` is a **censorship** module, and is not excluded. Its findings deduct
from the score and are named in the verdict, because a network that takes away
the messenger you reach for when a conversation matters has not made a policy
decision about bandwidth — the conversation does not stop, it moves somewhere
readable. The one thing that softens `comms` findings to informational is a
tunnel owning the default route, where the forwarding policy being measured
belongs to software you installed on purpose.

Note that `C3` covers three shapes at the same rung, distinguished by
`level.name`:

| `level.name` | Raised when |
|---|---|
| *Private messengers blocked* | Every blocked service is end-to-end encrypted while the ones keeping server-readable history still work — filtering that follows confidentiality rather than traffic. |
| *Private messaging blocked* | At least one end-to-end encrypted service is unreachable, without the blocking being that neatly shaped. Losing Signal does not become a mild event because Discord was blocked alongside it. |
| *Communication heavily restricted* | Half or more of the services are unreachable, whatever their encryption. |

The `L?`, `C?` and `T?` codes carry a level score of `0`, so an inconclusive
module never inflates the verdict — but it does not clear the network either.

## Findings

Finding IDs are stable and safe to match on in automation.

### `tls`

| ID | Severity | Raised when |
|---|---|---|
| `tls.intercepted` | high, or **critical** when the chain does not validate or the name does not match | Certificates were minted by something other than the real site. One finding per intercepting root. |
| `tls.selective` | medium | Some endpoints are re-signed while others pass through — an inspection policy with a bypass list. |
| `tls.tls13-blocked` | medium | Endpoints known to support TLS 1.3 settled on an older version. Built-in targets only. |
| `tls.alpn-stripped` | low | HTTP/2 was offered but not negotiated. Built-in targets only. |
| `tls.weak-crypto` | high | The intercepting device uses a weak key, signature or cipher suite. |
| `tls.shared-key` | critical | Two unrelated hostnames presented the same public key. |
| `tls.downgrade-swap` | critical | A forced TLS 1.0 handshake returned a certificate that does not belong to the origin — a different key **and** a chain that either fails to validate for the hostname or anchors at a different root. A different key alone is not enough: hosts mid-certificate-rotation legitimately serve several valid leaves, so that case is reported as an informational `downgrade` row instead. |
| `tls.sni-required` | low | A handshake without SNI was rejected while one with SNI succeeds. **`--deep` only.** |

### `dns`

| ID | Severity | Raised when |
|---|---|---|
| `dns.forged-answer` | critical | A fixed-address anchor hostname resolved to something else. |
| `dns.dot-intercepted` | critical | A DNS-over-TLS endpoint presented a certificate that does not validate. |
| `dns.transparent-redirect` | high, or **info** when a tunnel owns the default route | A query to an unroutable documentation address was answered. Behind a tunnel this is its resolver doing its job, so it is recorded as informational and the level becomes `D?` rather than `D2`. |
| `dns.nxdomain-hijack` | high | A random, impossible hostname resolved to a real address. |
| `dns.sinkholed` | high | A public site resolved to a private, loopback, CGNAT or documentation address. |
| `dns.query-rewritten` | medium | 0x20 capitalisation was normalised, so the query was parsed and regenerated in flight. |
| `dns.no-dnssec` | medium | A domain with deliberately broken signatures still resolved. |
| `dns.encrypted-blocked` | medium, or **info** behind a tunnel | Every DoT and DoH endpoint was unreachable while port 53 works. |
| `dns.forced-resolver` | medium, or **info** behind a tunnel | Every public resolver was unreachable on port 53 while the network's own resolver answers. |
| `dns.udp53-filtered` | medium, or **info** behind a tunnel | Resolvers that ignore a UDP query on port 53 answer the same question over TCP. |
| `dns.encrypted-partial` | low | Some, but not all, encrypted resolvers were unreachable. |
| `dns.public-resolvers-blocked` | low | Some, but not all, public resolvers were unreachable on port 53. |

### `http`

| ID | Severity | Raised when |
|---|---|---|
| `http.split-tls` | critical | The far end reports a different TLS or HTTP version than this machine negotiated. |
| `http.portal` | high | A fixed-response endpoint returned substituted content or a redirect. |
| `http.ssl-strip` | high | An HSTS-preloaded host served plaintext content instead of redirecting. |
| `http.proxy-headers` | medium | The response carried `Via`, `X-Cache` or similar intermediary headers. |

### `egress`

| ID | Severity | Raised when |
|---|---|---|
| `egress.quic-blocked` | medium, or **info** when a tunnel owns the default route | UDP leaves the network but QUIC reached no port tested, so the block follows the protocol rather than a port. Downgraded to informational behind a tunnel, where the policy measured belongs to the tunnel operator. |
| `egress.http3-unavailable` | info | udp/443 does not carry traffic, but the same QUIC packet is answered on udp/8443 — HTTP/3 falls back to HTTP/2 over TCP and QUIC itself is not filtered. Deliberately costs nothing. |
| `egress.privacy-blocked` | medium | Encrypted alternatives (DoT, NTS, QUIC) are blocked while plaintext works. QUIC only counts here when it is blocked on every port and no tunnel is in the path. |
| `egress.udp-blocked` | low | The STUN binding request did not complete. |
| `egress.v6-asymmetry` | low | IPv6 routes freely while IPv4 destinations are blocked. |

### `comms`

Every blocking finding is downgraded to **info** when a tunnel owns the default
route, exactly as `egress` and `dns` do: what was measured is then the tunnel
operator's forwarding policy. `comms.intercepted` is never downgraded — a
certificate that does not belong to Signal does not belong to Signal whoever is
carrying the packets.

| ID | Severity | Raised when |
|---|---|---|
| `comms.intercepted` | critical | A messaging endpoint completed a handshake with a certificate that is not the one it identifies itself with: for an ordinary endpoint, a chain that does not validate for the hostname or carries no CT proofs; for one that pins its own authority, any issuer other than that authority. Carries `"kind": "interception"`. |
| `comms.sni-filtered` | high, or **info** behind a tunnel | A handshake to a service failed, and the identical handshake to the **same address** under a benign hostname succeeded. The name is what is being filtered, which means something is reading every ClientHello. |
| `comms.dns-poisoned` | high, or **info** behind a tunnel | Messaging hostnames resolve to addresses no public service can be at, while the control host resolves correctly. Not raised when the control host is redirected too — that is network-wide and belongs to the `dns` module. |
| `comms.e2ee-blocked` | high, or **info** behind a tunnel | Every blocked service is end-to-end encrypted by default and at least one service that keeps server-readable history still works. Replaces `comms.blocked` when it applies. |
| `comms.blocked` | **high** when an end-to-end encrypted service is among them, or when half or more of everything tested is unreachable; **medium** otherwise; **info** behind a tunnel | One or more services were unreachable on **every** endpoint while the control endpoint worked. The title names the services, so `--quiet` output says *which* are gone. |
| `comms.reset-injected` | medium, or **info** behind a tunnel | Connections were established and then reset mid-stream rather than refused or dropped. |
| `comms.calls-blocked` | medium, or **info** behind a tunnel | No STUN binding request completed, so the UDP path calls negotiate media over is unavailable. |
| `comms.port-scoped-block` | info | A blocked endpoint answered on an alternate port, so the filter follows the port rather than the service. **`--deep` only.** |

### `time`

| ID | Severity | Raised when |
|---|---|---|
| `time.skew` | low, or **high** past 24 hours | The median offset from real time exceeds 60 seconds. |
| `time.redirected` | medium | An NTP query to an unroutable documentation address was answered. |
| `time.disagreement` | medium | Independent NTP sources differ by more than 10 seconds. |

## Scoring and verdicts

Two kinds of finding deduct from a perfect 100, floored at 0:

- **interception** (`tls`, `dns`, `http`, plus `comms.intercepted`) — somebody
  is reading or rewriting what your traffic says.
- **censorship** (`comms`) — somebody is deciding who you are permitted to
  reach.

| Severity | Deduction |
|---|---|
| critical | −34 |
| high | −18 |
| medium | −8 |
| low | −3 |
| info | 0 |

**Posture** findings (`egress`, `time`) deduct nothing and never appear in the
verdict, for the same reason their levels do not: a closed port is a choice, and
a run that mixes it in tells you a filtered network is a compromised one.
Posture findings are still printed, still appear in JSON, and are still visible
to `--fail-on`, which reads the worst severity in the whole run.

### How the verdict sentence is built

The two scoring axes are kept apart while the sentence is chosen, because their
thresholds mean different things — deductions for blocked messengers must never
push a run into "traffic is being decrypted", a claim midwatch would have no
evidence for. Each axis produces a clause from its **own** subtotal (100 minus
that axis's deductions only).

**Interception clause**, from the highest interception level and the
interception subtotal:

| Condition | Clause |
|---|---|
| level ≥ 3, subtotal < 40, or a **critical** interception finding | `Compromised — traffic is being decrypted or rewritten in transit` |
| level = 2, or subtotal < 65 | `Tampered — a middlebox is selectively intercepting traffic` |
| level = 1, subtotal < 85, or a medium-or-worse interception finding | `Observed — traffic is intact but metadata is visible and constrained` |
| otherwise | *(none)* |

**Censorship clause**, from the worst censorship finding:

| Condition | Clause |
|---|---|
| a **high** or **critical** censorship finding | `Censored — this network decides who you are able to contact` |
| a **medium** censorship finding | `Restricted — this network limits how you are able to communicate` |
| otherwise | *(none)* |

The two are then combined:

| Present | `verdict` |
|---|---|
| both | `<A> and <b> — <detail A>, and <detail B>`, e.g. `Compromised and censored — traffic is being decrypted or rewritten in transit, and this network decides who you are able to contact` |
| one | that clause alone |
| neither, and `comms` ran | `Clean — no interception or blocking detected on this network` |
| neither, and `comms` did not run | `Clean — no interception detected on this network` |

Two rules there are deliberate. A run is never called clean while something
worth acting on is outstanding, even when the arithmetic still looks
comfortable. And the clean sentence only claims nothing was blocked when
blocking was actually checked, so `midwatch tls` does not vouch for something it
never looked at.

A worked example — a network that filters Signal's hostname out of the
handshake and poisons DNS for Telegram, with TLS otherwise clean:

```
comms.sni-filtered   high   −18
comms.dns-poisoned   high   −18
comms.blocked        high   −18
                            = 46/100
Censored — this network decides who you are able to contact
```

Because the score is computed from whatever ran, single-module invocations
produce a partial score. `midwatch dns --json | jq .score` scores the DNS module
alone, not the network.

## Environment variables

midwatch reads no configuration file and has no settings of its own. It does
observe:

| Variable | Effect |
|---|---|
| `NO_COLOR` | Any value disables colour, unless `--color` was passed. |
| `TERM=dumb` | Disables colour, unless `--color` was passed. |
| `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy` | **Reported, not used.** The `http` module lists them under `local configuration` and then bypasses them, because measuring your proxy instead of the network would defeat the point. |

The `dns` module reads `/etc/resolv.conf` to learn the system resolvers. Where
that file does not exist — Windows, or a sandbox — the module records
`system resolvers: not readable` and compares public resolvers only.

No elevated privileges, packet capture or kernel extension is required.

## Signals and cancellation

`SIGINT` (Ctrl-C) and `SIGTERM` cancel the probes in flight rather than killing
the process mid-write. The modules that already completed are still rendered,
the remaining ones are skipped, and the run exits `2` because the requested
checks did not all complete.

## What midwatch connects to

Useful when allowlisting on a locked-down network, or when you need to explain
the traffic to whoever runs it. Everything below is an ordinary connection to a
public endpoint; nothing is uploaded and no host you did not point at is
scanned.

| Module | Destinations |
|---|---|
| `tls` | `www.google.com`, `cloudflare.com`, `github.com`, `www.mozilla.org`, `en.wikipedia.org`, `www.apple.com` — all TCP 443, or your `--targets` instead |
| `dns` | Every nameserver in `/etc/resolv.conf`; `1.1.1.1`, `8.8.8.8`, `9.9.9.9` on UDP 53, retried on TCP 53 when UDP is dropped; `1.1.1.1:853` and `9.9.9.9:853` (DoT); `cloudflare-dns.com` and `dns.google` (DoH, TCP 443); blackhole probes to `192.0.2.53`, `198.51.100.53`, `203.0.113.53` on UDP 53 |
| `http` | `connectivitycheck.gstatic.com`, `captive.apple.com`, `www.msftconnecttest.com`, `example.com`, `github.com` on TCP 80; `cloudflare.com` on TCP 443 |
| `egress` | TCP: `example.com:80`, `example.com:443`, `github.com:22`, `smtp.gmail.com:25`, `smtp.gmail.com:587`, `imap.gmail.com:993`, `1.1.1.1:53`, `1.1.1.1:853`, `time.cloudflare.com:4460`. UDP: `stun.l.google.com:19302`, falling back to `stun.cloudflare.com:3478` then `stun.nextcloud.com:443` if that one is unreachable, and `cloudflare.com:443` (QUIC), plus `cloudflare.com:8443` (QUIC control probe, only when udp/443 is silent). IPv6: `[2606:4700:4700::1111]:443` |
| `comms` | TCP 443 to `chat.signal.org`, `cdn.signal.org`, `web.whatsapp.com`, `g.whatsapp.net`, `mmg.whatsapp.net`, `api.telegram.org`, `web.telegram.org`, `149.154.167.51` (a Telegram data centre, by address), `init-p01st.push.apple.com`, `gateway.icloud.com`, `matrix.org`, `discord.com`, `gateway.discord.gg`, `zoom.us`, `meet.google.com`, `meet.jit.si`, and `example.com` as the control; TCP 5223 to `courier.push.apple.com`; TCP 5222 to `xmpp.org`. UDP: `stun.l.google.com:19302` and `stun.cloudflare.com:3478`. With `--deep`, blocked hosts are retried on TCP 80 and 5222 |
| `time` | UDP 123 to `time.cloudflare.com`, `time.google.com`, `time.apple.com`, `pool.ntp.org`, and a blackhole probe to `192.0.2.123` |

The lookups midwatch performs are deliberately visible to those operators, exactly
as a browser's would be. See [Privacy](../README.md#privacy).

## Recipes

### CI gate

```sh
midwatch scan --quiet --no-color --fail-on medium
```

Exits `1` on a medium-or-worse finding, `2` if the scan could not run. In GitHub
Actions:

```yaml
- name: Audit the runner's network
  run: |
    go install github.com/securqbit/midwatch/cmd/midwatch@latest
    midwatch scan --quiet --no-color --fail-on high
```

### Separate "found something" from "could not run"

```sh
midwatch scan --quiet > report.txt
case $? in
  0) echo "clean" ;;
  1) echo "findings"; cat report.txt ;;
  2) echo "scan failed"; exit 2 ;;
esac
```

### Report without ever failing the build

```sh
midwatch scan --json --fail-on never > report.json
```

### Extract findings with jq

```sh
midwatch scan --json > r.json

jq -r '.modules[].findings[]? | "\(.severity)\t\(.id)\t\(.title)"' r.json
jq -r '.modules[] | select(.level) | "\(.id) \(.level.code)"' r.json
jq '[.modules[].findings[]? | select(.severity == "critical")] | length' r.json
jq -r '.verdict, "\(.score)/100"' r.json
```

### Watch one module while iterating on it

```sh
make build && ./bin/midwatch dns --json --timeout 3s | jq '.modules[0].sections'
```

### Test your own endpoints

```sh
midwatch tls --targets intranet.corp:8443,vpn.corp:443,mail.corp --deep
```

Remember that protocol-degradation findings are suppressed for custom targets;
certificate evidence still applies.

### Find out how a messenger is being blocked

```sh
midwatch comms --deep
```

The `blocking method` section names the layer that stopped each endpoint, and
`--deep` retries the blocked ones on alternate ports so you can tell a filter
that follows the service from one that follows the port. To list just the
mechanism:

```sh
midwatch comms --json |
  jq -r '.modules[0].sections[] | select(.title=="blocking method")
         | .rows[] | "\(.label)\t\(.value)\t\(.note)"'
```

### Compare two networks

```sh
midwatch scan --json > office.json
# switch networks
midwatch scan --json > cafe.json
diff <(jq -r '.modules[] | "\(.id) \(.level.code // "-")"' office.json) \
     <(jq -r '.modules[] | "\(.id) \(.level.code // "-")"' cafe.json)
```

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `L?  Inconclusive` on TLS | No handshake completed at all. The network is offline, or every built-in endpoint is blocked. Try `--timeout 20s`, or `--targets` with a host you know is reachable. |
| `T?  Inconclusive` on time | No NTP source answered — UDP 123 is blocked outright. Cross-check with the `egress` module. |
| `C?  Inconclusive` on comms | The control endpoint `example.com:443` could not be reached either, so there is no baseline to compare the messengers against. This machine is probably offline. |
| `comms` findings all at `info`, and a `Clean` verdict | A tunnel owns the default route, named in the `path` row. What was measured is the tunnel operator's forwarding policy, not the network's. Disconnect the tunnel to judge the network itself. |
| `comms` reports a service you do not use as blocked | The service list is fixed, and midwatch reports the network's policy rather than your habits. A blocked service you never open is still evidence about what this network permits. |
| A deliberate corporate block scores as `Censored` | Intentional, and the same call midwatch makes about an installed inspection root: it reports that communication is being restricted and how far it goes, not whether you agreed to it. Use `--fail-on never`, or gate on finding IDs, if the policy is expected. |
| `system resolvers: not readable` | `/etc/resolv.conf` is missing or unreadable (normal on Windows). The module still runs against public resolvers. |
| Lots of `skip` rows | Probes could not reach their endpoints. `skip` is an absence of evidence — it does not mean clean. Raise `--timeout` on a slow link. |
| Exit `2` with no output | Usage error. Run `midwatch help` and check the command spelling; unknown commands print to stderr. |
| `invalid --fail-on value` | Use one of `info`, `low`, `medium`, `high`, `critical`, `never` — and lowercase `never` specifically. |
| Colour escapes in a log file | Default output already detects a non-terminal; if you passed `--color`, drop it, or add `--no-color`. |
| A run takes far longer than `--timeout` | The flag is per probe, not per run. A full `scan` runs five modules, each with several probes. |
| `default route: utun0` under `path`, or egress findings you do not recognise | A VPN or tunnel owns the default route, so every probe measures the tunnel's policy rather than the network's. Egress findings are downgraded accordingly. Disconnect the tunnel to audit the network itself. |
| `HTTP/3 is unavailable` at info | udp/443 is closed but QUIC works on another port, so HTTP/3 falls back to HTTP/2 over TCP. This is a transport preference, not filtering, and costs nothing in the score. |
| Findings on a corporate laptop | Expected where an inspection root is installed deliberately. midwatch reports that it is happening and how far it goes, not whether you agreed to it. See [Reading the results](../README.md#reading-the-results). |

## Building and installing

```sh
go install github.com/securqbit/midwatch/cmd/midwatch@latest
```

Or from a clone:

```sh
make build      # ./bin/midwatch, version stamped from git
make install    # into $GOBIN
make test       # go test -race ./...
make cover      # coverage total
make all        # fmt, vet, test, build
make run        # build, then ./bin/midwatch scan
```

Prebuilt binaries for Linux, macOS, Windows and FreeBSD are attached to each
[release](https://github.com/securqbit/midwatch/releases), with signed checksums.
See [CONTRIBUTING.md](../CONTRIBUTING.md) for the development workflow.
