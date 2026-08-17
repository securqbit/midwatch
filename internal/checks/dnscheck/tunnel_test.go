// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnscheck

import (
	"strings"
	"testing"

	"github.com/securqbit/midwatch/internal/report"
)

func newState(tunneled bool) *state {
	s := &state{m: report.NewModule("dns", "DNS interception", report.KindInterception)}
	if tunneled {
		s.tunneled, s.pathName = true, "utun9"
	}
	return s
}

// Port 53 answered by a tunnel means the queries never reached the network, so
// the module cannot judge it either way: not D2, and not clean either.
func TestRedirectThroughTunnelIsInconclusive(t *testing.T) {
	s := newState(true)
	s.redirected = true
	s.deriveLevel()

	if s.m.Level == nil || s.m.Level.Code != "D?" {
		t.Fatalf("level = %+v, want D?", s.m.Level)
	}
	if s.m.Level.Score != 0 {
		t.Errorf("level score = %d, want 0 so an inconclusive module cannot drive the verdict", s.m.Level.Score)
	}
	if !strings.Contains(s.m.Level.Summary, "utun9") {
		t.Errorf("summary does not name the tunnel: %q", s.m.Level.Summary)
	}
}

// The same evidence without a tunnel is exactly what D2 is for. This is the
// regression that matters: the tunnel carve-out must not swallow real
// interception.
func TestRedirectWithoutTunnelStaysD2(t *testing.T) {
	s := newState(false)
	s.redirected = true
	s.deriveLevel()

	if s.m.Level == nil || s.m.Level.Code != "D2" {
		t.Fatalf("level = %+v, want D2", s.m.Level)
	}
	if s.m.Level.Score != 2 {
		t.Errorf("level score = %d, want 2", s.m.Level.Score)
	}
}

// Forged answers are attributable to whoever produced them, tunnel or not, so
// the escalation must survive.
func TestForgeryStillEscalatesThroughTunnel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*state)
		want  string
	}{
		{"forged", func(s *state) { s.forged = true }, "D4"},
		{"encrypted MITM", func(s *state) { s.encryptedMTM = true }, "D4"},
		{"hijacked", func(s *state) { s.hijacked = true }, "D3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newState(true)
			s.redirected = true
			tc.setup(s)
			s.deriveLevel()

			if s.m.Level == nil || s.m.Level.Code != tc.want {
				t.Fatalf("level = %+v, want %s even behind a tunnel", s.m.Level, tc.want)
			}
		})
	}
}

// A tunnel plus an independent lock-in signal is still lock-in worth reporting,
// so D1 must win over the inconclusive case.
func TestTunnelWithLockInStaysD1(t *testing.T) {
	s := newState(true)
	s.redirected = true
	s.noDNSSEC = true
	s.deriveLevel()

	if s.m.Level == nil || s.m.Level.Code != "D1" {
		t.Fatalf("level = %+v, want D1", s.m.Level)
	}
}

func TestPolicySeverityDowngradesOnlyBehindTunnel(t *testing.T) {
	if got := newState(false).policySeverity(report.SevMedium); got != report.SevMedium {
		t.Errorf("policySeverity off-tunnel = %v, want medium", got)
	}
	if got := newState(true).policySeverity(report.SevMedium); got != report.SevInfo {
		t.Errorf("policySeverity behind tunnel = %v, want info", got)
	}
}

func TestAttributeNamesTheTunnel(t *testing.T) {
	const detail = "Encrypted DNS is unreachable."
	if got := newState(false).attribute(detail); got != detail {
		t.Errorf("attribute off-tunnel rewrote the detail: %q", got)
	}
	got := newState(true).attribute(detail)
	if !strings.HasPrefix(got, detail) {
		t.Errorf("attribute dropped the original detail: %q", got)
	}
	if !strings.Contains(got, "utun9") {
		t.Errorf("attribute does not name the tunnel: %q", got)
	}
}
