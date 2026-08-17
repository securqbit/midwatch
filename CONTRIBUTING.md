# Contributing to midwatch

Thanks for wanting to help. midwatch is a detection tool, so the bar it has to
clear is not "does the code work" but "is the conclusion true". These notes are
about that.

## The two most valuable contributions

**1. Interception signatures.** If you have encountered an appliance or
endpoint product that re-signs TLS, the issuer string it presents is directly
useful. Add it to `knownInterceptors` in
`internal/checks/tlscheck/certs.go` with the vendor name and category, and
include the observed issuer in the pull request description. Redact anything
identifying about your organisation — the vendor's product name is all that is
needed.

**2. False-positive reports.** A check that cries wolf is worse than no check:
it teaches people to ignore the tool. If midwatch reports interception on a
network you know is clean, that is a real bug and we want it. Please include
`midwatch scan --json` output (see the privacy note below) and anything you know
about the network.

While building midwatch we found that several large providers still accept TLS 1.0
on their edge, which broke an early "obsolete protocol means a middlebox"
heuristic. That class of mistake is exactly what these reports catch.

## Adding a check

A good midwatch check has a **falsifiable** signal behind it, not a heuristic
correlation. The strongest checks in the tool work because something is
*impossible* rather than merely unusual:

- Nothing can answer a query sent to an RFC 5737 documentation address.
- No publicly trusted certificate lacks Certificate Transparency proofs.
- No two unrelated sites share a private key.
- One TLS connection cannot disagree with itself about its own version.

Before adding a check, write down what result would prove it wrong. If you
cannot, it probably belongs as an informational row rather than a finding.

Checks live in `internal/checks/<name>check/` and return a
`*report.Module`. Modules build up `Row`s (observations) and `Finding`s (things
to act on) and set a `Level`. Renderers consume only that model, so you never
need to touch output code.

Pick `report.KindInterception` if the module measures somebody reading or
altering traffic, and `report.KindPosture` if it measures policy. Only
interception modules drive the overall verdict.

Finding IDs, level codes and section titles are a public interface — people
match on them in CI and in dashboards. A new one is not finished until it is
listed in the [CLI reference](docs/cli.md#findings), and an existing one should
not be renamed without a good reason.

## Severity

Be conservative. Severity drives both the score and the exit code, which people
wire into CI.

- **critical** — proof that traffic is being decrypted or forged right now
- **high** — strong evidence of interception, or a serious weakening of it
- **medium** — the network constrains privacy, or something is being rewritten
- **low** — worth knowing, not worth acting on tonight
- **info** — context

Write findings in plain language and say **what it means for the reader**, not
just what was observed. "The certificate lacks SCTs" is a fact; "whoever
controls that key can read your passwords" is the finding.

## Development

```sh
make test     # go test -race ./...
make vet
make fmt
make build    # ./bin/midwatch
make cover
```

Two hard rules:

1. **No third-party dependencies.** People run this tool to audit their
   network's trustworthiness; its own supply chain should be reviewable in an
   afternoon. CI fails if anything appears in `go.mod`. If you need DNS, STUN,
   NTP or QUIC, the wire formats are already implemented in-tree.
2. **Unit tests must be hermetic.** No test may require network access. Build
   the bytes you want to parse, or the struct you want to classify, and assert
   on the result. The end-to-end smoke test in CI is the only networked step.

## Ethics

midwatch only ever connects to endpoints it was pointed at, and only to well-known
public services by default. Please do not propose checks that scan third-party
hosts, attempt exploitation, or generate load a network operator would consider
abusive. The tool is for auditing networks you are on, not for probing networks
you are not.

## Privacy when filing issues

A `midwatch scan --json` report contains your public IP address, your configured
resolvers, and your approximate location. Redact whatever you are not
comfortable publishing — the findings and levels are usually enough.

## Licence

midwatch is licensed under the [Mozilla Public License 2.0](LICENSE), and
contributions are accepted under the same terms.

MPL-2.0 is file-level copyleft. In practice that means: if you modify a midwatch
source file and ship it, those file changes have to be published, but you can
combine midwatch with proprietary code without that code becoming subject to the
MPL. It is deliberately not the GPL — you can vendor midwatch into a commercial
product — and deliberately not MIT, because improvements to the detection logic
itself should come back to everyone relying on it.

Every source file carries the standard MPL header. New files need it too:

```go
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
```

The **midwatch** and **SecurQbit** names are trademarks and are not covered by
the licence — see [TRADEMARK.md](TRADEMARK.md). Forking is welcome; forking
under our name is not.

## Developer Certificate of Origin

Every commit must be signed off, certifying that you wrote the patch or
otherwise have the right to submit it under the project's licence. Read the
full text at [developercertificate.org](https://developercertificate.org/).

Add the sign-off automatically with:

```sh
git commit -s
```

which appends a line like:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and a working email address. There is no CLA and no
copyright assignment: you keep the copyright in your contribution. The sign-off
just gives the project a clean provenance chain, which for a security tool is
part of the product.
