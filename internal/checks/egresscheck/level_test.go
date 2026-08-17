// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package egresscheck

import (
	"strings"
	"testing"

	"github.com/securqbit/midwatch/internal/report"
)

// A closed udp/443 on a path that otherwise carries QUIC is a transport
// preference, so the level must stay E0 and say why.
func TestDeriveLevelHTTP3FallbackStaysOpen(t *testing.T) {
	m := report.NewModule("egress", "Egress policy", report.KindPosture)
	deriveLevel(m, 9, 0, 0, nil, true, true)

	if m.Level == nil || m.Level.Code != "E0" {
		t.Fatalf("level = %+v, want E0", m.Level)
	}
	if !strings.Contains(m.Level.Summary, "HTTP/3") {
		t.Errorf("E0 summary does not explain the HTTP/3 fallback: %q", m.Level.Summary)
	}
	if len(m.Findings) != 0 {
		t.Errorf("deriveLevel raised %d findings on an open network, want 0", len(m.Findings))
	}
}

// QUIC dropped on every port is a different claim, and it still reaches E2
// through the privacy counter.
func TestDeriveLevelPrivacyBlockedReachesE2(t *testing.T) {
	m := report.NewModule("egress", "Egress policy", report.KindPosture)
	deriveLevel(m, 8, 1, 1, []string{"QUIC / HTTP3"}, false, false)

	if m.Level == nil || m.Level.Code != "E2" {
		t.Fatalf("level = %+v, want E2", m.Level)
	}
}
