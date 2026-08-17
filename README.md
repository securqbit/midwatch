# midwatch

**Find out who is watching your network.**

`midwatch` is a single-binary CLI that tells you whether the network you are on is
reading, rewriting or constraining your traffic — and how deeply. It detects
TLS interception and grades it on a five-level ladder, catches DNS redirection
and answer forgery, spots transparent proxies and captive portals, maps what
your network will actually let out, tells you which messengers and calling
services it will let you reach, and verifies that even your clock has not been
tampered with.

It has **zero third-party dependencies**. Everything — the DNS resolver, the
STUN client, the NTP client, the QUIC probe — is implemented against the
standard library. A tool you run to audit your network should have a supply
chain you can read in an afternoon.

📖 **[CLI reference](docs/cli.md)** · [Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md)

```
$ midwatch scan

  midwatch 1.0.0  linux/amd64  ·  2026-02-11 09:22:41 EST

  ── TLS INTERCEPTION ────────────────────────────────────────────────
   L0   No interception detected
        All 6 endpoints served publicly trusted, CT-logged
        certificates over a modern negotiated protocol.

  endpoints
  ok    www.google.com:443    TLS1.3 h2 ECDSA-P256 ct:2  WR2 / Google Trust Services
  ok    cloudflare.com:443    TLS1.3 h2 ECDSA-P256 ct:2  WE1 / Google Trust Services
  ok    github.com:443        TLS1.3 h2 ECDSA-P256 ct:2  Sectigo Public Server Auth CA
  …

  ── DNS INTERCEPTION ────────────────────────────────────────────────
   D2   Transparent redirection
        Port 53 is intercepted and answered locally regardless of
        which resolver you configure.

  transparent redirection
  bad   192.0.2.53:53     NOERROR  answered by a local device returning 93.184.216.34
  bad   198.51.100.53:53  NOERROR  answered by a local device returning 93.184.216.34

  findings
  HIGH      All DNS traffic is being transparently redirected  dns.transparent-redirect
            A query addressed to an unroutable documentation address
            received a reply, which is only possible if a device on this
            network is intercepting every packet sent to port 53. Changing
            your DNS settings will not move your lookups.

  ── VERDICT ───────────────────────────────────────────────────────
  ███████████████████░░░░░  82/100
  Tampered — a middlebox is selectively intercepting traffic
```

## Install

```sh
go install github.com/securqbit/midwatch/cmd/midwatch@latest
```

Or grab a prebuilt binary from [Releases](https://github.com/securqbit/midwatch/releases),
or build from source:

```sh
git clone https://github.com/securqbit/midwatch && cd midwatch
make build      # ./bin/midwatch
```

No root, no packet capture, no kernel extension. `midwatch` opens ordinary
connections to public endpoints and reasons about the answers.

## Usage

```sh
midwatch scan                     # everything, with an overall verdict
midwatch tls                      # just TLS interception
midwatch dns                      # just DNS
midwatch comms                    # can you reach Signal, WhatsApp, FaceTime?
midwatch tls --deep               # additional, noisier probes
midwatch tls --targets bank.example.com:443,intranet.corp:8443
midwatch scan --json > report.json
midwatch scan --quiet --fail-on medium    # for CI and monitoring
```

| Flag | Meaning |
|---|---|
| `--json` | full report as JSON, stable field names |
| `--quiet` | tab-separated levels, findings and verdict |
| `--deep` | extra probes: SNI-less handshakes, protocol policing |
| `--timeout` | per-probe timeout (default `8s`) |
| `--targets` | your own `host:port` list for the TLS check |
| `--fail-on` | exit 1 at this severity or worse (default `high`, or `never`) |
| `--no-color` | plain output; also honours `NO_COLOR` and non-TTY stdout |

**Exit codes:** `0` clean or below threshold · `1` a finding met `--fail-on` ·
`2` midwatch could not complete the checks.

The table above is the short version. The **[CLI reference](docs/cli.md)**
documents every command and flag in full, along with the
[JSON schema](docs/cli.md#json-output), the complete
[finding catalogue](docs/cli.md#findings), how the
[score and verdict](docs/cli.md#scoring-and-verdicts) are derived, and the exact
list of [endpoints midwatch contacts](docs/cli.md#what-midwatch-connects-to).

## What it checks

Six modules, each placing itself on a 0–4 ladder. The sections below explain
the reasoning behind each one; the [CLI reference](docs/cli.md#levels) lists
every level code and every finding ID in one place.

### TLS interception — levels L0–L4

Interception is proved by the **certificate**, not by the protocol version.
midwatch opens real handshakes to endpoints known to support TLS 1.3, HTTP/2 and
Certificate Transparency, captures whatever chain the network delivers, and
asks:

- Does the chain validate against **this machine's** trust store?
- Is it anchored in a root that belongs to the **public web PKI**?
- Does the leaf carry **Signed Certificate Timestamps**? Every certificate from
  a public CA has them since 2018, because browsers reject those that don't.
  An appliance minting certificates locally cannot produce them. This is the
  single most reliable tell.
- Do two **unrelated hostnames share one public key**? No legitimate pair of
  sites shares a private key. Only an interceptor produces this.
- Does a **downgraded handshake return a certificate that does not belong to the
  origin**? A deliberate TLS 1.0 handshake is compared against the modern one —
  but a different key is not enough to accuse anyone, because a host mid-rotation
  serves several valid leaves at once. What counts is a chain that fails to
  validate for the hostname, or one that anchors at a different root than the
  modern connection reached. That, an origin cannot produce.
- Was the handshake itself degraded — TLS 1.3 blocked, ALPN rewritten?
- Does the issuer name a known product? midwatch recognises over 50 enterprise
  appliances (Zscaler, Netskope, Blue Coat, FortiGate, Palo Alto, iboss …),
  endpoint AV suites (Kaspersky, ESET, Bitdefender, Sophos …) and developer
  proxies (mitmproxy, Burp, Charles, Fiddler).

| Level | Meaning |
|---|---|
| **L0** | No interception. Certificates are authentic and CT-logged. |
| **L1** | *Metadata visibility.* No forged certificates, but the handshake is manipulated — TLS 1.3 blocked, ALPN stripped. Payloads are private; **which sites you visit is not**. |
| **L2** | *Selective decryption.* Some endpoints are re-signed, others pass through. The signature of an inspection product with a bypass list — somebody chose which of your traffic to open. |
| **L3** | *Full decryption via an installed root.* Every endpoint re-signed by a CA your machine trusts but the public PKI does not. Someone installed a root here and reads every session in cleartext. |
| **L4** | *Untrusted interception.* The chain does not validate, the interceptor uses weak crypto, reuses one key across sites, or answers a downgraded handshake with a certificate that does not chain back to the origin's anchor. **Do not send credentials over this network.** |

### DNS interception — levels D0–D4

midwatch never trusts a single vantage point. It asks the same questions through
your configured resolver and through public resolvers reached directly, then
compares.

- **Transparent redirection.** A query is sent to `192.0.2.53` — an RFC 5737
  documentation address where nothing can exist. A reply proves every packet to
  port 53 is intercepted and answered locally. *Changing your DNS settings will
  not help; whatever you configure, that device answers.*
- **Resolver reachability.** Before comparing answers, midwatch establishes
  whether it is *allowed* to ask anyone else. A network where the resolver it
  handed you works while every public resolver is unreachable on port 53 has
  taken your choice away without forging a single answer — and midwatch says so
  rather than reporting a clean result it had no way to corroborate. Each
  blocked resolver is retried over TCP: a network that drops UDP/53 and permits
  TCP/53 to the same address has shaped that filter deliberately, because no
  capacity limit distinguishes those two packets.
- **Answer forgery.** `dns.google`, `one.one.one.one` and `dns.quad9.net` have
  fixed anycast addresses, not CDN-dependent ones. Any deviation is a rewritten
  answer, not load balancing.
- **NXDOMAIN hijacking.** A random 20-character name that cannot exist must
  return NXDOMAIN. An address means the resolver fabricates answers.
- **Query rewriting (0x20).** Names are sent with randomised capitalisation. A
  conforming resolver echoes the question byte for byte; normalised case means
  a middlebox parsed and regenerated your query — and stripped the entropy that
  protects you from cache poisoning.
- **DNSSEC validation**, via a domain published with deliberately broken
  signatures, plus the AD bit on a valid one.
- **Encrypted DNS**: DoT and DoH reachability, and whether the DoT endpoint
  presents a **forged certificate** — an interceptor attacking the very channel
  you used to escape it.

| Level | Meaning |
|---|---|
| **D0** | Clean. |
| **D1** | *Resolver lock-in.* Answers intact, but you have no choice about who answers: off-network resolvers are unreachable, encrypted DNS is blocked, queries are regenerated, or nothing validates signatures. |
| **D2** | *Transparent redirection.* Port 53 answered locally regardless of configuration. |
| **D3** | *Answer manipulation.* Nonexistent or filtered names get addresses the operator chose. |
| **D4** | *Answer forgery.* Names with fixed, verifiable addresses come back pointing elsewhere. |

### HTTP path integrity — levels H0–H3

- **Captive portals and substitution**: endpoints that exist to return one
  fixed, boring answer (`generate_204`, Apple's hotspot probe, Microsoft's
  connect test). Anything else means a device answered instead of the origin.
- **Split TLS detection**: Cloudflare's trace endpoint reports the TLS version
  and HTTP version *the far end actually saw*. A single unbroken connection
  cannot disagree with itself — a mismatch means there are two connections,
  and everything you send is cleartext at the join. This catches proxies whose
  certificates look perfect.
- **Transparent proxies** announcing themselves via `Via`, `X-Cache` and
  friends.
- **SSL stripping**: an HSTS-preloaded host serving plaintext content instead
  of redirecting.

### Egress policy — levels E0–E3

Interception and filtering are two faces of one policy. A network permitting
only 80 and 443 forces everything through the ports it can inspect; one
blocking 853 and QUIC is closing the escape hatches that would deny it
visibility.

TCP reachability across nine services, a real **STUN binding request** (RFC
5389) that also reveals your mapped address, a real **QUIC version negotiation
probe** (RFC 9000 §6.1 — no QUIC implementation required), and IPv6 asymmetry.
midwatch distinguishes *silently dropped* from *actively refused*, because the
difference tells you whether you are being firewalled or blackholed.

A silent udp/443 is not enough to accuse a network of anything, so it is never
reported alone. The same packet is sent to a QUIC port nothing bothers to
filter, which separates two very different situations: a path that **carries
QUIC fine but does not carry udp/443** — a transport preference for HTTP/2 that
tunnels and CDNs make routinely, recorded as informational — from one that
**drops QUIC on every port while other UDP flows**, which follows the protocol
rather than a port and is the visibility-motivated case worth a finding.

### Communication reachability — levels C0–C4

Every other module asks what this network does to your traffic. This one asks
what it does to your contact with other people: whether Signal, WhatsApp,
Telegram, iMessage and FaceTime, Matrix, XMPP, Discord, Zoom, Meet and Jitsi
can be reached at all — and when they cannot, **which layer stopped them**.

That last part is the point. "WhatsApp doesn't work here" is something you
already knew. midwatch separates:

- **DNS redirection**, where the name resolves to an address no public service
  can be at, while ordinary names resolve fine.
- **Address blocking**, where the name resolves correctly and the address is
  refused or silently dropped.
- **Hostname filtering**, the strongest signal available. When a handshake dies
  only when a messenger's name appears in it, midwatch reconnects **to the same
  address** offering a dull hostname instead. If that gets through, nothing
  about the route was ever broken — a device is reading the server name out of
  every ClientHello leaving the network and deciding, per name, whether to let
  it live. That device sees which services every person here contacts.
- **Reset injection**, where connections are established and then torn down
  mid-stream. A server that doesn't want you refuses at the start; a reset
  partway through is something on the path acting after it saw what the
  connection was for.
- **A certificate that isn't the service's own**, checked against the way each
  endpoint actually identifies itself. Signal pins its own CA, so its chain
  validates against no browser trust store and appears in no CT log — normal
  for Signal, and midwatch expects exactly that issuer rather than reporting
  the world's most private messenger as intercepted on every network.
- **The call path**, tested separately from the text path with a real STUN
  binding request. Every one of these apps negotiates media with ICE, so when
  that UDP path is closed, messaging still works while voice and video fail or
  fall back to a vendor relay — slower, and one more party positioned to see
  that the call happened.

Telegram is also probed **by address**, at a data centre a DNS block cannot
touch. If the names are poisoned while that answers, the block is in the
resolver and the app itself would still connect.

midwatch watches the *shape* of the blocking, not only its extent. A network
where Zoom, Meet and Discord work while Signal, WhatsApp and Matrix do not has
not run out of bandwidth. It has singled out the services whose contents nobody
else can read.

| Level | Meaning |
|---|---|
| **C0** | Unrestricted. Every service answered as itself and the call path is open. |
| **C1** | *Calls degraded.* Messaging works; the UDP path calls negotiate media over does not. |
| **C2** | *Selective blocking.* Some services are unreachable while the rest work. |
| **C3** | *Private messaging blocked.* An end-to-end encrypted service is unreachable. Named *private messengers blocked* when the blocking lands exactly on that line — every blocked service encrypted, every working one keeping server-readable history — and *communication heavily restricted* when half or more of everything tested is gone. |
| **C4** | *Communication intercepted.* A service was answered by a certificate that does not belong to it. |

Blocking findings are graded by what was taken, not just how much: losing an
end-to-end encrypted service, or half of everything tested, is **high**, and a
high censorship finding makes the verdict `Censored`. The `comms.intercepted`
finding is filed as *interception* rather than censorship even though this
module found it — a forged certificate is an attack on what the conversation
says, and it is scored and described as one.

Nothing here is interpreted until an ordinary control endpoint works, so a
machine that is merely offline never reports the world's messengers as censored.

### Whose network is this?

Before drawing conclusions, `dns`, `egress` and `comms` all ask which interface owns the
default route. When a VPN forwards your packets, what they measure is the tunnel
operator's forwarding and resolution policy — usually software you installed on
purpose — and reporting that as network interception blames the wrong party while
burying the findings that matter.

So a tunnel in the path is named in a `path` row, and the findings that describe
**policy** are attributed to it and recorded as informational: a closed udp/443,
a blocked encrypted resolver, a port 53 answered by the tunnel's own resolver, or
a messenger the tunnel declines to carry.
DNS drops to `D?` *inconclusive* rather than `D2` in that case, because a query
answered by the tunnel never reached the network being audited — calling that
network clean would be as wrong as calling it hostile.

Findings about **answer integrity** are never downgraded: forged addresses,
NXDOMAIN hijacking, sinkholing, a DoT certificate that does not validate and a
messaging endpoint answered by a certificate that is not its own all keep their
full severity, because a forged identity matters whoever produced it. The same reasoning governs `HTTPS_PROXY`, which is reported and then
bypassed — measuring your own software instead of the network defeats the point.

### Time source integrity — levels T0–T2

Time is load-bearing for security and almost never checked. Certificate
validity, TOTP codes, Kerberos tickets, JWT expiry and DNSSEC lifetimes are all
judged against the local clock. NTP is unauthenticated by default. midwatch
measures offset against three independent sources, detects **transparent NTP
redirection** with the same documentation-address trick, and flags sources that
disagree with each other — because whoever controls your clock controls whether
an expired certificate looks valid.

## Scoring

Findings deduct from a perfect 100 (critical −34, high −18, medium −8, low −3),
and midwatch scores **two** different things a network can do to you:

- **Interception** — `tls`, `dns`, `http` — somebody is reading or rewriting
  what your traffic says.
- **Censorship** — `comms` — somebody is deciding who you are permitted to
  reach.

Both deduct, and both are named in the verdict. Blocking Signal is not a
bandwidth decision: the conversation does not stop, it moves somewhere readable,
and a tool that files that next to a closed SMTP port has buried the more
serious of the two.

**Posture** findings (`egress`, `time`) are reported in full but deduct nothing,
so a network that filters a port or prefers HTTP/2 is not presented as a
compromised one. They remain visible to `--fail-on`, which reads the worst
severity in the run, so `midwatch scan --fail-on medium` still gates on them.

The two scoring axes are added together but reasoned about separately, so a
blocked messenger can never push a run into "traffic is being decrypted" — a
claim midwatch would have no evidence for. Each contributes its own clause:

```
Censored — this network decides who you are able to contact

Compromised and censored — traffic is being decrypted or rewritten in transit,
and this network decides who you are able to contact
```

A run is never called clean while a medium-or-worse interception or censorship
finding is outstanding. The exception is a tunnel owning the default route:
blocking findings drop to informational there, because the forwarding policy
being measured belongs to software you installed on purpose.

The exact thresholds are tabulated in
[Scoring and verdicts](docs/cli.md#scoring-and-verdicts).

## Reading the results

**Not every finding is an attack.** Managed corporate laptops routinely have an
inspection root installed, deliberately and with disclosure. midwatch's job is to
tell you *that it is happening and how far it goes*, not to guess whether you
consented. What it does insist on:

- L3 means somebody can read your passwords in plaintext. That may be your IT
  department. It should still not be a surprise.
- L4 means the interception is not even properly trusted or is actively
  weakening your crypto. That is worth escalating regardless of who runs it.
- A **clean result is not a guarantee.** midwatch detects interception that leaves
  evidence. A sufficiently resourced adversary with a genuinely trusted
  CT-logged certificate would not.

## Privacy

midwatch stores nothing and sends nothing anywhere. It makes ordinary connections
to well-known public endpoints (Google, Cloudflare, Quad9, Apple, Microsoft,
Mozilla, Wikipedia, GitHub, the NTP pool) and reads the answers. Those
operators see a connection from your address, exactly as they would from a
browser. There is no telemetry, no phone-home and no account.

It does not scan hosts you did not point it at, and it does not attempt to
exploit anything it finds.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
The most valuable contributions are **new interception signatures** (issuer
strings from appliances you have encountered) and **false-positive reports**: a
check that cries wolf is worse than no check, so a case where midwatch is wrong
about your network is a real bug.

## License

[Mozilla Public License 2.0](LICENSE) © SecurQbit.

File-level copyleft: you can vendor midwatch into a proprietary product without
that product becoming subject to the MPL, but changes to midwatch's own source
files have to be published. Improvements to the detection logic — the appliance
signatures, the thresholds, the false-positive fixes — come back to everyone
who relies on them.

The **midwatch** and **SecurQbit** names and logos are trademarks and are not
covered by the licence; see [TRADEMARK.md](TRADEMARK.md). Packaging and
redistributing midwatch unmodified needs no permission. Shipping *modified*
detection logic under our name does — pick your own name, so that whoever reads
the verdict knows whose judgement produced it.
