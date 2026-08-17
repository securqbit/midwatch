# Security Policy

## Reporting a vulnerability

Please report security issues privately, not as public GitHub issues.

- Preferred: open a [private security advisory](https://github.com/securqbit/midwatch/security/advisories/new)
- Or email **security@securqbit.com**

Please include what you did, what happened, and what you expected. We aim to
acknowledge within 3 working days and to ship a fix or a public advisory within
90 days.

## What counts as a vulnerability in midwatch

midwatch is a detection tool that people trust to tell them whether a network is
safe. The most serious bugs are therefore not memory-safety issues but
**wrong answers**:

- **A false negative that can be induced.** If an interception technique
  reliably evades midwatch — for example, a way to present a forged certificate
  that the CT, chain and key-reuse checks all miss — that is a security bug,
  because someone will read "L0 · No interception detected" and send a password.
- **A hostile network causing midwatch to misbehave.** Every response midwatch parses
  comes from an untrusted source: DNS messages, STUN attributes, NTP packets,
  QUIC datagrams, HTTP bodies and X.509 chains are all attacker-controllable on
  an intercepted network. A crafted response that causes a panic, an infinite
  loop, unbounded memory use, or a misreported verdict is in scope.
- **Anything that makes midwatch leak data.** midwatch must not transmit results
  anywhere or write them outside stdout unless the user redirected it.

Ordinary false positives are bugs but not vulnerabilities — please file those
as normal issues, as described in [CONTRIBUTING.md](CONTRIBUTING.md).

## Deliberate design decisions

Two things look like flaws in a scan of the source and are not:

**`InsecureSkipVerify` is used on purpose.** The TLS module and the DoT probe
disable Go's built-in verification so that the certificate chain an interceptor
presents can be *captured and examined* rather than discarded by a failed
handshake. Verification is then performed explicitly with
`x509.Certificate.Verify`, and the result is what the tool reports. Removing
this would blind the tool to exactly what it exists to find. midwatch never
transmits data over these connections; it reads the handshake and closes.

**Probes are sent to unroutable addresses.** Queries to `192.0.2.0/24` and
friends (RFC 5737 documentation ranges) are intentional. Nothing on the
internet can answer them, so a reply is proof of transparent redirection.

## Scope

In scope: this repository's code and released binaries.

Out of scope: vulnerabilities in the third-party services midwatch connects to,
and the behaviour of networks it reports on.
