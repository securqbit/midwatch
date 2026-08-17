// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/securqbit/midwatch/internal/report"
)

// cleanEndpoint is what an untouched, publicly trusted connection looks like.
func cleanEndpoint(t *testing.T, host string) *endpoint {
	t.Helper()
	leaf := makeCert(t, host, []string{host})
	return &endpoint{
		Target:      host + ":443",
		Host:        host,
		Version:     tls.VersionTLS13,
		ALPN:        "h2",
		Leaf:        leaf,
		Presented:   []*x509.Certificate{leaf},
		SCTs:        3,
		SPKI:        spkiFingerprint(leaf),
		Issuer:      "ISRG Root X1 / Let's Encrypt",
		RootSubject: "ISRG Root X1 / Let's Encrypt",
		KeyDesc:     "ECDSA-P256",
		Lifetime:    90,
	}
}

func TestClassifyAcceptsGenuineEndpoint(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	classify(ep)
	if ep.Intercepted {
		t.Errorf("a CT-logged, publicly anchored certificate was flagged intercepted: %v", ep.Reasons)
	}
}

func TestClassifyFlagsMissingTransparency(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	ep.SCTs = 0
	classify(ep)
	if !ep.Intercepted {
		t.Error("a certificate with no SCTs was not flagged; CT absence is the primary tell")
	}
}

// An unrecognised root alone must not accuse a clean network: the public CA
// list cannot be exhaustive, and a genuinely forged certificate is caught by
// the absence of Certificate Transparency proofs instead.
func TestClassifyTreatsUnknownRootAsCorroborationOnly(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	ep.RootSubject = "Some Regional CA Nobody Listed"
	classify(ep)
	if ep.Intercepted {
		t.Errorf("a CT-logged certificate was flagged solely for an unfamiliar root: %v", ep.Reasons)
	}
	if !ep.SuspectRoot {
		t.Error("an unfamiliar root should still be recorded as suspect")
	}
}

func TestClassifyFlagsPrivateRootWithoutTransparency(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	ep.RootSubject = "Acme Corp Internal CA"
	ep.SCTs = 0
	classify(ep)
	if !ep.Intercepted {
		t.Error("a locally minted certificate with no CT proofs was not flagged")
	}
	var mentionsRoot bool
	for _, r := range ep.Reasons {
		if strings.Contains(r, "Acme Corp Internal CA") {
			mentionsRoot = true
		}
	}
	if !mentionsRoot {
		t.Errorf("the offending root was not named in the reasons: %v", ep.Reasons)
	}
}

func TestClassifyFlagsVendorIssuer(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	ep.VendorHit = true
	ep.Vendor = interceptor{needle: "zscaler", vendor: "Zscaler", kind: "enterprise"}
	classify(ep)
	if !ep.Intercepted {
		t.Error("a certificate issued by a named interception product was not flagged")
	}
}

func TestClassifyFlagsBrokenChain(t *testing.T) {
	ep := cleanEndpoint(t, "example.org")
	ep.VerifyErr = errors.New("certificate signed by unknown authority")
	classify(ep)
	if !ep.Intercepted {
		t.Error("a chain that fails validation was not flagged")
	}
}

func TestCrossCheckDetectsSharedKey(t *testing.T) {
	a := cleanEndpoint(t, "alpha.example")
	b := cleanEndpoint(t, "beta.example")
	// One interceptor signing both hosts with a single key.
	b.SPKI = a.SPKI

	crossCheck([]*endpoint{a, b})
	if !a.Intercepted || !b.Intercepted {
		t.Error("two hosts sharing one public key were not both flagged as intercepted")
	}
}

func TestCrossCheckIgnoresDistinctKeys(t *testing.T) {
	a := cleanEndpoint(t, "alpha.example")
	b := cleanEndpoint(t, "beta.example")

	crossCheck([]*endpoint{a, b})
	if a.Intercepted || b.Intercepted {
		t.Error("endpoints with distinct keys were flagged by the cross check")
	}
}

func TestDeriveLevelLadder(t *testing.T) {
	tests := []struct {
		name           string
		build          func(t *testing.T) []*endpoint
		splitResponder bool
		baseline       bool
		want           int
	}{
		{
			name: "clean",
			build: func(t *testing.T) []*endpoint {
				return []*endpoint{cleanEndpoint(t, "a.example"), cleanEndpoint(t, "b.example")}
			},
			baseline: true,
			want:     0,
		},
		{
			name: "metadata only",
			build: func(t *testing.T) []*endpoint {
				a := cleanEndpoint(t, "a.example")
				a.TLS13Blocked = true
				return []*endpoint{a, cleanEndpoint(t, "b.example")}
			},
			baseline: true,
			want:     1,
		},
		{
			name: "protocol quirks ignored for custom targets",
			build: func(t *testing.T) []*endpoint {
				a := cleanEndpoint(t, "a.example")
				a.TLS13Blocked = true
				a.ALPNStripped = true
				return []*endpoint{a}
			},
			baseline: false,
			want:     0,
		},
		{
			name: "selective decryption",
			build: func(t *testing.T) []*endpoint {
				a := cleanEndpoint(t, "a.example")
				a.Intercepted = true
				return []*endpoint{a, cleanEndpoint(t, "b.example")}
			},
			baseline: true,
			want:     2,
		},
		{
			name: "full decryption",
			build: func(t *testing.T) []*endpoint {
				a := cleanEndpoint(t, "a.example")
				b := cleanEndpoint(t, "b.example")
				a.Intercepted, b.Intercepted = true, true
				return []*endpoint{a, b}
			},
			baseline: true,
			want:     3,
		},
		{
			name: "untrusted interception",
			build: func(t *testing.T) []*endpoint {
				a := cleanEndpoint(t, "a.example")
				a.Intercepted = true
				a.VerifyErr = errors.New("unknown authority")
				return []*endpoint{a}
			},
			baseline: true,
			want:     4,
		},
		{
			name: "downgrade answered by another key",
			build: func(t *testing.T) []*endpoint {
				return []*endpoint{cleanEndpoint(t, "a.example")}
			},
			splitResponder: true,
			baseline:       true,
			want:           4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eps := tc.build(t)
			live := 0
			for _, ep := range eps {
				if ep.Err == nil {
					live++
				}
			}
			m := report.NewModule("tls", "TLS interception", report.KindInterception)
			deriveLevel(m, eps, live, tc.splitResponder, tc.baseline)
			if m.Level == nil {
				t.Fatal("deriveLevel did not set a level")
			}
			if m.Level.Score != tc.want {
				t.Errorf("level = %d (%s), want %d", m.Level.Score, m.Level.Name, tc.want)
			}
		})
	}
}

func TestReportLegacySameKeyIsNotInterception(t *testing.T) {
	primary := cleanEndpoint(t, "a.example")
	m := report.NewModule("tls", "TLS interception", report.KindInterception)

	// The origin itself still speaks TLS 1.0 and returns its own certificate.
	split := reportLegacy(m, legacyProbe{
		Attempted: true, Accepted: true, SPKI: primary.SPKI, Issuer: primary.Issuer,
	}, primary, "a.example:443")

	if split {
		t.Error("legacy support by the origin was misreported as a second responder")
	}
	if len(m.Findings) != 0 {
		t.Errorf("server-side legacy support produced %d findings, want 0", len(m.Findings))
	}
}

func TestReportLegacyDifferentKeyIsInterception(t *testing.T) {
	primary := cleanEndpoint(t, "a.example")
	other := cleanEndpoint(t, "a.example")
	m := report.NewModule("tls", "TLS interception", report.KindInterception)

	split := reportLegacy(m, legacyProbe{
		Attempted: true, Accepted: true, SPKI: other.SPKI, Issuer: "Acme Internal CA",
	}, primary, "a.example:443")

	if !split {
		t.Fatal("a downgraded handshake answered by a different key was not reported")
	}
	if len(m.Findings) != 1 || m.Findings[0].Severity != report.SevCritical {
		t.Errorf("expected one critical finding, got %+v", m.Findings)
	}
}

func TestCompactErrTrimsNoise(t *testing.T) {
	got := compactErr(errors.New("tls: handshake failure"))
	if got != "handshake failure" {
		t.Errorf("compactErr = %q, want %q", got, "handshake failure")
	}
	if compactErr(nil) != "" {
		t.Error("compactErr(nil) should be empty")
	}
}
