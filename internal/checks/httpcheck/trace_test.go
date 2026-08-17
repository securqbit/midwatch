// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package httpcheck

import (
	"crypto/tls"
	"testing"
)

func TestParseTrace(t *testing.T) {
	body := "fl=123abc\nh=cloudflare.com\nip=203.0.113.7\nts=1766000000.1\n" +
		"visit_scheme=https\nuag=midwatch\ncolo=LHR\nsliver=none\nhttp=http/2\n" +
		"loc=GB\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\n"

	got := parseTrace(body)
	if got == nil {
		t.Fatal("parseTrace returned nil for a valid trace body")
	}
	for key, want := range map[string]string{
		"ip": "203.0.113.7", "tls": "TLSv1.3", "http": "http/2",
		"sni": "plaintext", "loc": "GB", "warp": "off",
	} {
		if got[key] != want {
			t.Errorf("trace[%q] = %q, want %q", key, got[key], want)
		}
	}
}

func TestParseTraceRejectsForeignBody(t *testing.T) {
	// A captive portal answering the trace URL with HTML must not be parsed
	// into a half-populated map that later checks would treat as authoritative.
	if got := parseTrace("<html><body>Login required</body></html>"); got != nil {
		t.Errorf("parseTrace accepted a non-trace body: %v", got)
	}
	if got := parseTrace(""); got != nil {
		t.Errorf("parseTrace accepted an empty body: %v", got)
	}
	if got := parseTrace("tls=TLSv1.3\nhttp=http/2\n"); got != nil {
		t.Error("parseTrace accepted a body with no ip field")
	}
}

func TestNormalizeTLS(t *testing.T) {
	// The edge and the local stack spell versions differently; comparison must
	// not report a mismatch merely because of formatting. Getting this wrong
	// fires a critical "your TLS session ends before it reaches the site"
	// finding on a perfectly healthy connection, so each spelling pair is
	// asserted explicitly rather than against itself.
	for _, spelling := range []string{"TLSv1.3", "tlsv1.3", "TLS1.3", "TLS 1.3", " TLSv1.3 "} {
		if normalizeTLS(spelling) != normalizeTLS("TLSv1.3") {
			t.Errorf("normalizeTLS(%q) = %q, want it to match TLSv1.3 (%q)",
				spelling, normalizeTLS(spelling), normalizeTLS("TLSv1.3"))
		}
	}
	if normalizeTLS("TLSv1.3") == normalizeTLS("TLSv1.2") {
		t.Error("different versions compared equal")
	}
	if normalizeTLS("TLSv1.2") != "1.2" {
		t.Errorf("normalizeTLS(TLSv1.2) = %q, want %q", normalizeTLS("TLSv1.2"), "1.2")
	}
}

func TestTLSVersionNameMatchesEdgeSpelling(t *testing.T) {
	// tlsVersionName renders what this machine negotiated; the trace endpoint
	// renders what the far end saw. The split-TLS check compares the two, so
	// an unbroken connection must compare equal after normalisation.
	for _, tc := range []struct {
		version uint16
		edge    string
	}{
		{tls.VersionTLS13, "TLSv1.3"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS10, "TLSv1.0"},
	} {
		local := tlsVersionName(tc.version)
		if normalizeTLS(local) != normalizeTLS(tc.edge) {
			t.Errorf("tlsVersionName(0x%04x) = %q, does not match edge spelling %q",
				tc.version, local, tc.edge)
		}
	}
}
