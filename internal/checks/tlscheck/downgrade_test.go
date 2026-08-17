// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tlscheck

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/securqbit/midwatch/internal/report"
)

// modernEndpoint is a healthy TLS 1.3 result to compare a downgrade against.
func modernEndpoint() *endpoint {
	return &endpoint{
		Target:      "www.google.com:443",
		Host:        "www.google.com",
		Leaf:        &x509.Certificate{},
		SPKI:        "dcc7e4e51348ae84aa",
		Issuer:      "WR2",
		RootSubject: "GTS Root R4 / Google Trust Services LLC",
	}
}

func findingIDs(m *report.Module) []string {
	ids := make([]string, 0, len(m.Findings))
	for _, f := range m.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

// A site mid-rotation serves a second, entirely valid leaf. Different key, same
// anchor — that is not interception, and it must not produce a critical finding
// or push the module to L4.
func TestDowngradeRotationIsNotInterception(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	primary := modernEndpoint()
	legacy := legacyProbe{
		Attempted: true, Accepted: true,
		SPKI:        "d85f654b1b0946cfbb", // different leaf...
		Issuer:      "WR2",
		Verified:    true,
		RootSubject: primary.RootSubject, // ...same trust anchor
	}

	if split := reportLegacy(m, legacy, primary, "www.google.com:443"); split {
		t.Error("reportLegacy called certificate rotation a split responder")
	}
	if ids := findingIDs(m); len(ids) != 0 {
		t.Errorf("findings = %v, want none for a rotated certificate", ids)
	}
	if len(m.Sections) == 0 || len(m.Sections[0].Rows) == 0 {
		t.Fatal("no downgrade row was recorded; the observation must still be reported")
	}
	row := m.Sections[0].Rows[0]
	if row.Status != report.StatusInfo {
		t.Errorf("row status = %v, want info", row.Status)
	}
	if !strings.Contains(row.Note, "rotation") {
		t.Errorf("row note does not explain rotation: %q", row.Note)
	}
}

// The case the check exists for: the downgraded chain does not validate. That is
// still critical, and the carve-out above must not swallow it.
func TestDowngradeSwapWithUnverifiableChainStillCritical(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	legacy := legacyProbe{
		Attempted: true, Accepted: true,
		SPKI:        "0badc0de00000000aa",
		Issuer:      "Acme Inspection CA",
		Verified:    false,
		RootSubject: "Acme Inspection Root",
	}

	if split := reportLegacy(m, legacy, modernEndpoint(), "www.google.com:443"); !split {
		t.Error("an unverifiable downgraded chain was not reported as a split responder")
	}
	ids := findingIDs(m)
	if len(ids) != 1 || ids[0] != "tls.downgrade-swap" {
		t.Fatalf("findings = %v, want [tls.downgrade-swap]", ids)
	}
	if m.Findings[0].Severity != report.SevCritical {
		t.Errorf("severity = %v, want critical", m.Findings[0].Severity)
	}
}

// A validating chain that anchors somewhere else is the enterprise-MITM shape:
// the root was installed locally, so verification passes but the anchor differs.
func TestDowngradeSwapWithDifferentAnchorStillCritical(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	legacy := legacyProbe{
		Attempted: true, Accepted: true,
		SPKI:        "feed0000face0000bb",
		Issuer:      "Corp Proxy CA",
		Verified:    true, // trusted because the root is installed on this host
		RootSubject: "Corp Proxy Root",
	}

	if split := reportLegacy(m, legacy, modernEndpoint(), "www.google.com:443"); !split {
		t.Error("a chain anchored at a different root was not reported as a split responder")
	}
	if ids := findingIDs(m); len(ids) != 1 || ids[0] != "tls.downgrade-swap" {
		t.Fatalf("findings = %v, want [tls.downgrade-swap]", ids)
	}
	if !strings.Contains(m.Findings[0].Evidence[1], "Corp Proxy Root") {
		t.Errorf("evidence does not name the rogue anchor: %q", m.Findings[0].Evidence[1])
	}
}

// A modern connection that itself failed verification cannot be used as the
// trusted baseline for an anchor comparison, so the finding must stand.
func TestDowngradeSwapWhenModernChainAlsoFails(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	primary := modernEndpoint()
	primary.VerifyErr = errors.New("x509: certificate signed by unknown authority")
	legacy := legacyProbe{
		Attempted: true, Accepted: true,
		SPKI:        "d85f654b1b0946cfbb",
		Issuer:      "WR2",
		Verified:    true,
		RootSubject: primary.RootSubject,
	}

	if split := reportLegacy(m, legacy, primary, "www.google.com:443"); !split {
		t.Error("rotation was inferred from an untrusted modern baseline")
	}
}

// Matching keys mean the origin itself still speaks TLS 1.0: a property of the
// server, not of the network.
func TestDowngradeSameKeyIsOriginBehaviour(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	primary := modernEndpoint()
	legacy := legacyProbe{
		Attempted: true, Accepted: true,
		SPKI: primary.SPKI, Issuer: primary.Issuer,
		Verified: true, RootSubject: primary.RootSubject,
	}

	if split := reportLegacy(m, legacy, primary, "www.google.com:443"); split {
		t.Error("an identical key was reported as a split responder")
	}
	if ids := findingIDs(m); len(ids) != 0 {
		t.Errorf("findings = %v, want none", ids)
	}
}

// A refused downgrade is the healthy outcome and stays clean.
func TestDowngradeRefusedIsClean(t *testing.T) {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)
	legacy := legacyProbe{Attempted: true, Accepted: false}

	if split := reportLegacy(m, legacy, modernEndpoint(), "www.google.com:443"); split {
		t.Error("a refused downgrade was reported as a split responder")
	}
	if len(m.Sections) == 0 || m.Sections[0].Rows[0].Status != report.StatusOK {
		t.Error("a refused downgrade should record an ok row")
	}
}
