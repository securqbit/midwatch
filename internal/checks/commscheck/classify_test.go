// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package commscheck

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/securqbit/midwatch/internal/report"
)

func TestIsBlackhole(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
		{"0.0.0.0", true},
		{"127.0.0.1", true},
		{"10.10.34.36", true}, // a sinkhole address used by real censors
		{"192.168.1.1", true},
		{"172.20.0.5", true},
		{"100.64.0.1", true},
		{"169.254.1.1", true},
		{"192.0.2.1", true},
		{"198.51.100.7", true},
		{"203.0.113.9", true},
		{"::1", true},
		{"fd00::1", true},
		{"fe80::1", true},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test fixture %q is not an address", tc.ip)
		}
		if got := isBlackhole(ip); got != tc.want {
			t.Errorf("isBlackhole(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if !isBlackhole(nil) {
		t.Error("a missing address must not be treated as reachable")
	}
}

func TestAllBlackholeNeedsEveryAnswerRedirected(t *testing.T) {
	poisoned := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")}
	if !allBlackhole(poisoned) {
		t.Error("an answer made entirely of unreachable addresses is a redirection")
	}
	// One usable address is enough for the app to connect, so a mixed answer
	// must not be reported as a block.
	mixed := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("93.184.216.34")}
	if allBlackhole(mixed) {
		t.Error("an answer containing a usable address is not a redirection")
	}
	if allBlackhole(nil) {
		t.Error("an empty answer is a resolution failure, not a redirection")
	}
}

func TestFirstUsablePrefersRoutableIPv4(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("2606:4700::1111"),
		net.ParseIP("93.184.216.34"),
	}
	got := firstUsable(ips)
	if got == nil || got.String() != "93.184.216.34" {
		t.Errorf("firstUsable = %v, want 93.184.216.34", got)
	}
	// With no IPv4 left, the routable IPv6 answer is still usable.
	got = firstUsable([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("2606:4700::1111")})
	if got == nil || got.String() != "2606:4700::1111" {
		t.Errorf("firstUsable = %v, want the routable IPv6 address", got)
	}
	if firstUsable([]net.IP{net.ParseIP("10.0.0.1")}) != nil {
		t.Error("firstUsable returned an address no public service can be at")
	}
}

func TestClassifyDialErrNamesTheFailure(t *testing.T) {
	tests := []struct {
		err  string
		want verdict
	}{
		{"dial tcp 1.2.3.4:443: connect: connection refused", vRefused},
		{"dial tcp 1.2.3.4:443: i/o timeout", vDropped},
		{"context deadline exceeded", vDropped},
		{"dial tcp 1.2.3.4:443: connect: no route to host", vDropped},
		{"dial tcp 1.2.3.4:443: connect: network is unreachable", vDropped},
		{"read tcp 1.2.3.4:443: read: connection reset by peer", vReset},
		{"write tcp 1.2.3.4:443: write: broken pipe", vReset},
		{"unexpected EOF", vReset},
	}
	for _, tc := range tests {
		if got := classifyDialErr(errors.New(tc.err)); got != tc.want {
			t.Errorf("classifyDialErr(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
	if classifyDialErr(nil) != vOK {
		t.Error("no error means the connection worked")
	}
}

func TestIsPeerAlertSeparatesTheServerFromTheMiddlebox(t *testing.T) {
	// A TLS alert means the far end answered in the protocol, so the path is
	// intact and nothing was blocked.
	if !isPeerAlert(errors.New("remote error: tls: unrecognized name")) {
		t.Error("a peer alert must be recognised as the server speaking")
	}
	if isPeerAlert(errors.New("read tcp: connection reset by peer")) {
		t.Error("a reset is not the server speaking")
	}
	if isPeerAlert(nil) {
		t.Error("no error is not a peer alert")
	}
}

// stunReply builds a STUN response with the given type and transaction id.
func stunReply(msgType uint16, cookie uint32, txID []byte) []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], msgType)
	binary.BigEndian.PutUint32(buf[4:8], cookie)
	copy(buf[8:20], txID)
	return buf
}

func TestValidSTUNSuccess(t *testing.T) {
	tx := []byte("0123456789ab")
	if err := validSTUNSuccess(stunReply(0x0101, stunMagicCookie, tx), tx); err != nil {
		t.Errorf("a well-formed binding success response was rejected: %v", err)
	}
	if err := validSTUNSuccess(stunReply(0x0111, stunMagicCookie, tx), tx); err == nil {
		t.Error("a binding error response must not count as an open media path")
	}
	if err := validSTUNSuccess(stunReply(0x0101, 0xdeadbeef, tx), tx); err == nil {
		t.Error("a reply without the magic cookie is not a STUN response")
	}
	other := []byte("ba9876543210")
	if err := validSTUNSuccess(stunReply(0x0101, stunMagicCookie, other), tx); err == nil {
		t.Error("a reply for another transaction must not be accepted")
	}
	if err := validSTUNSuccess([]byte{1, 2, 3}, tx); err == nil {
		t.Error("a short datagram must not be accepted")
	}
}

func TestVerdictBlocked(t *testing.T) {
	usable := map[verdict]bool{vOK: true, vSkipped: true}
	for v := vOK; v <= vSkipped; v++ {
		if got := v.blocked(); got == usable[v] {
			t.Errorf("verdict %v: blocked() = %v", v, got)
		}
		if v.String() == "unknown" {
			t.Errorf("verdict %d has no name", int(v))
		}
	}
}

func TestServiceTableIsWellFormed(t *testing.T) {
	seen := map[string]string{}
	for _, svc := range services {
		if svc.Name == "" {
			t.Error("a service has no name")
		}
		if len(svc.Endpoints) == 0 {
			t.Errorf("%s has no endpoints, so it can never be judged", svc.Name)
		}
		for _, ep := range svc.Endpoints {
			if ep.Host == "" || ep.Port <= 0 || ep.Port > 65535 {
				t.Errorf("%s has a malformed endpoint %+v", svc.Name, ep)
			}
			if ep.Role == "" {
				t.Errorf("%s endpoint %s has no role, so its row would be unreadable",
					svc.Name, ep.Addr())
			}
			// A shared host would make one outage look like two, and would let
			// a single vendor decide two services' verdicts.
			if prev, dup := seen[ep.Addr()]; dup {
				t.Errorf("%s reuses the endpoint %s already claimed by %s", svc.Name, ep.Addr(), prev)
			}
			seen[ep.Addr()] = svc.Name
		}
	}
	// The end-to-end split is what the C3 level and comms.e2ee-blocked are
	// derived from, so both sides of it have to be populated.
	e2ee, plain := 0, 0
	for _, svc := range services {
		if svc.E2EE {
			e2ee++
		} else {
			plain++
		}
	}
	if e2ee == 0 || plain == 0 {
		t.Fatalf("the service table needs both kinds to compare: %d end-to-end, %d not", e2ee, plain)
	}
	if _, _, err := net.SplitHostPort(control.Addr()); err != nil {
		t.Errorf("the control endpoint is malformed: %v", err)
	}
}

// resultsFor builds a full result matrix, giving every endpoint of a named
// service the same verdict and leaving every other service reachable.
func resultsFor(t *testing.T, state map[string]verdict) [][]result {
	t.Helper()
	known := map[string]bool{}
	for _, svc := range services {
		known[svc.Name] = true
	}
	for name := range state {
		if !known[name] {
			t.Fatalf("test refers to %q, which is not in the service table", name)
		}
	}
	out := make([][]result, len(services))
	for i, svc := range services {
		v, ok := state[svc.Name]
		if !ok {
			v = vOK
		}
		out[i] = make([]result, len(svc.Endpoints))
		for j, ep := range svc.Endpoints {
			out[i][j] = result{Svc: svc.Name, EP: ep, V: v, Detail: v.String()}
		}
	}
	return out
}

func e2eeNames() []string {
	var out []string
	for _, svc := range services {
		if svc.E2EE {
			out = append(out, svc.Name)
		}
	}
	return out
}

func plainNames() []string {
	var out []string
	for _, svc := range services {
		if !svc.E2EE {
			out = append(out, svc.Name)
		}
	}
	return out
}

func findingIDs(m *report.Module) map[string]report.Severity {
	out := map[string]report.Severity{}
	for _, f := range m.Findings {
		out[f.ID] = f.Severity
	}
	return out
}

// run puts a result matrix through the same two calls Run makes, so the tally
// the level sees is the one the rendering actually produced.
func run(t *testing.T, state map[string]verdict, mediaOK, tunneled bool) (*report.Module, tally) {
	t.Helper()
	m := report.NewModule("comms", "Communication reachability", report.KindCensorship)
	results := resultsFor(t, state)
	tl := renderServices(m, results, false)
	tl.MediaOK, tl.MediaTested = mediaOK, true
	renderMethod(m, results, false)
	findings(m, results, tl, tunneled, "utun0", false)
	deriveLevel(m, tl, tunneled)
	return m, tl
}

func TestCleanNetworkIsUnrestricted(t *testing.T) {
	m, tl := run(t, nil, true, false)
	if m.Level == nil || m.Level.Code != "C0" {
		t.Fatalf("level = %+v, want C0", m.Level)
	}
	if len(m.Findings) != 0 {
		t.Errorf("a clean run produced findings: %v", findingIDs(m))
	}
	if tl.Reachable != len(services) || tl.Blocked != 0 {
		t.Errorf("tally = %+v, want every service reachable", tl)
	}
}

func TestClosedMediaPathDegradesCallsOnly(t *testing.T) {
	m, _ := run(t, nil, false, false)
	if m.Level == nil || m.Level.Code != "C1" {
		t.Fatalf("level = %+v, want C1", m.Level)
	}
	if _, ok := findingIDs(m)["comms.calls-blocked"]; !ok {
		t.Errorf("a closed media path raised %v, want comms.calls-blocked", findingIDs(m))
	}
}

func TestOneBlockedServiceIsSelective(t *testing.T) {
	m, tl := run(t, map[string]verdict{"Discord": vDropped}, true, false)
	if m.Level == nil || m.Level.Code != "C2" {
		t.Fatalf("level = %+v, want C2", m.Level)
	}
	if tl.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", tl.Blocked)
	}
	got := findingIDs(m)
	if got["comms.blocked"] != report.SevMedium {
		t.Errorf("findings = %v, want comms.blocked at medium", got)
	}
	if _, ok := got["comms.e2ee-blocked"]; ok {
		t.Error("blocking a service that keeps server-readable history is not a confidentiality block")
	}
}

func TestBlockingExactlyTheEncryptedMessengers(t *testing.T) {
	state := map[string]verdict{}
	for _, name := range e2eeNames() {
		state[name] = vSNIFiltered
	}
	m, tl := run(t, state, true, false)
	if m.Level == nil || m.Level.Code != "C3" || !strings.Contains(m.Level.Name, "Private") {
		t.Fatalf("level = %+v, want C3 Private messengers blocked", m.Level)
	}
	if tl.E2EEBlocked != tl.E2EETotal || tl.PlainOpen == 0 {
		t.Fatalf("tally = %+v, want every end-to-end service blocked and others open", tl)
	}
	got := findingIDs(m)
	if got["comms.e2ee-blocked"] != report.SevHigh {
		t.Errorf("findings = %v, want comms.e2ee-blocked at high", got)
	}
	if got["comms.sni-filtered"] != report.SevHigh {
		t.Errorf("findings = %v, want comms.sni-filtered at high", got)
	}
	if _, ok := got["comms.blocked"]; ok {
		t.Error("the shaped finding and the generic one must not both be raised")
	}
}

func TestHalfTheServicesBlockedIsHeavyRestriction(t *testing.T) {
	// Deliberately no end-to-end encrypted service among them: this is the
	// branch for blocking that is broad rather than aimed at confidentiality,
	// and it must be reachable without the private-messaging branch catching
	// it first.
	state := map[string]verdict{}
	for _, name := range plainNames() {
		state[name] = vDropped
	}
	m, tl := run(t, state, true, false)
	if tl.E2EEBlocked != 0 {
		t.Fatalf("fixture blocked an end-to-end encrypted service, so it tests the wrong branch")
	}
	if tl.Blocked*2 < tl.Total {
		t.Fatalf("fixture blocked %d of %d services, which is not half", tl.Blocked, tl.Total)
	}
	if m.Level == nil || m.Level.Code != "C3" || !strings.Contains(m.Level.Name, "heavily") {
		t.Fatalf("level = %+v, want C3 Communication heavily restricted", m.Level)
	}
	if findingIDs(m)["comms.blocked"] != report.SevHigh {
		t.Errorf("findings = %v, want comms.blocked at high", findingIDs(m))
	}
}

// TestBlockingAPrivateMessengerIsSerious covers the case this grading exists
// for: a network that takes away Signal while leaving other services up. Losing
// a channel people move to on purpose is not a mild restriction, and it has to
// reach the score and the verdict rather than being filed under policy.
func TestBlockingAPrivateMessengerIsSerious(t *testing.T) {
	m, tl := run(t, map[string]verdict{"Signal": vDropped, "Telegram": vDropped}, true, false)

	if tl.E2EEBlocked != 1 || tl.Blocked != 2 {
		t.Fatalf("tally = %+v, want two services blocked, one of them end to end", tl)
	}
	if m.Level == nil || m.Level.Code != "C3" {
		t.Fatalf("level = %+v, want C3", m.Level)
	}
	if got := findingIDs(m)["comms.blocked"]; got != report.SevHigh {
		t.Errorf("comms.blocked = %v, want high", got)
	}
	// The title has to name them, so --quiet and the finding list say which
	// services are gone rather than how many.
	var title string
	for _, f := range m.Findings {
		if f.ID == "comms.blocked" {
			title = f.Title
		}
	}
	for _, want := range []string{"Signal", "Telegram"} {
		if !strings.Contains(title, want) {
			t.Errorf("finding title %q does not name %s", title, want)
		}
	}
}

func TestListPhrase(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{nil, "No service"},
		{[]string{"Signal"}, "Signal"},
		{[]string{"Signal", "Telegram"}, "Signal and Telegram"},
		{[]string{"Signal", "Telegram", "Matrix"}, "Signal, Telegram and Matrix"},
		{[]string{"Signal", "Telegram", "Matrix", "Zoom"}, "Signal, Telegram and 2 other services"},
		{[]string{"a", "b", "c"}, "a, b and c"},
	}
	for _, tc := range tests {
		if got := listPhrase(tc.in); got != tc.want {
			t.Errorf("listPhrase(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The singular has to read as one.
	if got := listPhrase([]string{"a", "b", "c", "d"}); !strings.Contains(got, "2 other services") {
		t.Errorf("listPhrase = %q", got)
	}
}

func TestInterceptionOutranksBlocking(t *testing.T) {
	m, tl := run(t, map[string]verdict{"Signal": vIntercepted, "Discord": vDropped}, true, false)
	if tl.Intercepted != 1 {
		t.Fatalf("tally = %+v, want one intercepted service", tl)
	}
	if m.Level == nil || m.Level.Code != "C4" {
		t.Fatalf("level = %+v, want C4", m.Level)
	}
	if findingIDs(m)["comms.intercepted"] != report.SevCritical {
		t.Errorf("findings = %v, want comms.intercepted at critical", findingIDs(m))
	}
}

func TestTunnelDowngradesBlockingButNotInterception(t *testing.T) {
	state := map[string]verdict{"Signal": vIntercepted, "Discord": vDropped, "Zoom": vDNSPoisoned}
	m, _ := run(t, state, false, true)
	got := findingIDs(m)

	// A tunnel forwards what its operator chose to forward, so its blocking is
	// policy attributable to software the user installed.
	for _, id := range []string{"comms.blocked", "comms.dns-poisoned", "comms.calls-blocked"} {
		if sev, ok := got[id]; ok && sev != report.SevInfo {
			t.Errorf("%s = %v behind a tunnel, want info", id, sev)
		}
	}
	// A certificate that does not belong to Signal does not belong to Signal
	// whoever is carrying the packets.
	if got["comms.intercepted"] != report.SevCritical {
		t.Errorf("comms.intercepted = %v behind a tunnel, want critical", got["comms.intercepted"])
	}
	for _, f := range m.Findings {
		if f.ID == "comms.blocked" && !strings.Contains(f.Detail, "utun0") {
			t.Error("a downgraded finding must name the tunnel it is attributed to")
		}
	}
}

func TestNetworkWideDNSRedirectionIsNotBlamedOnMessengers(t *testing.T) {
	// Every name on this network resolves to a local address, control included.
	// That belongs to the dns module; reporting it once per messenger would
	// claim they were singled out when they were not.
	state := map[string]verdict{}
	for _, svc := range services {
		state[svc.Name] = vDNSPoisoned
	}
	m := report.NewModule("comms", "Communication reachability", report.KindCensorship)
	results := resultsFor(t, state)
	tl := renderServices(m, results, true)
	tl.MediaOK, tl.MediaTested = true, true
	findings(m, results, tl, false, "", true)
	deriveLevel(m, tl, false)

	if tl.Blocked != 0 || tl.Poisoned != 0 {
		t.Errorf("tally = %+v, want no service held responsible for network-wide redirection", tl)
	}
	if _, ok := findingIDs(m)["comms.dns-poisoned"]; ok {
		t.Errorf("findings = %v, want no per-service redirection finding", findingIDs(m))
	}
	if m.Level == nil || m.Level.Code != "C0" {
		t.Fatalf("level = %+v, want C0", m.Level)
	}
}

func TestPartiallyBlockedServiceIsNotFullyBlocked(t *testing.T) {
	// Telegram's data centre is probed by address, so a DNS-level block leaves
	// it reachable. That is the difference between "Telegram is blocked" and
	// "Telegram's names are blocked but the app would still connect".
	m := report.NewModule("comms", "Communication reachability", report.KindCensorship)
	results := resultsFor(t, nil)
	for i, svc := range services {
		if svc.Name != "Telegram" {
			continue
		}
		for j, ep := range svc.Endpoints {
			if ep.TLS {
				results[i][j].V = vDNSPoisoned
				results[i][j].Detail = "answered with 10.10.34.36"
			}
		}
	}
	tl := renderServices(m, results, false)
	tl.MediaOK, tl.MediaTested = true, true
	findings(m, results, tl, false, "", false)
	deriveLevel(m, tl, false)

	if tl.Partial != 1 || tl.Blocked != 0 {
		t.Fatalf("tally = %+v, want one partly blocked service and none fully blocked", tl)
	}
	if m.Level == nil || m.Level.Code != "C2" {
		t.Fatalf("level = %+v, want C2", m.Level)
	}
	if _, ok := findingIDs(m)["comms.blocked"]; ok {
		t.Error("a service still reachable by address must not be reported as unreachable")
	}
	if findingIDs(m)["comms.dns-poisoned"] != report.SevHigh {
		t.Errorf("findings = %v, want comms.dns-poisoned at high", findingIDs(m))
	}
}

func TestBlockingMethodRowsExplainEveryFailure(t *testing.T) {
	m, _ := run(t, map[string]verdict{"Signal": vSNIFiltered, "Zoom": vRefused}, true, false)
	var rows int
	for _, s := range m.Sections {
		if s.Title != "blocking method" {
			continue
		}
		for _, r := range s.Rows {
			rows++
			if r.Value == "" || r.Note == "" {
				t.Errorf("blocking method row %+v does not say what happened", r)
			}
		}
	}
	// One row per failed endpoint: Signal has two, Zoom has one.
	if rows != 3 {
		t.Errorf("blocking method rows = %d, want 3", rows)
	}
	// Nothing that worked belongs in that table.
	for _, s := range m.Sections {
		if s.Title == "services" && len(s.Rows) != len(services) {
			t.Errorf("services rows = %d, want one per service (%d)", len(s.Rows), len(services))
		}
	}
}

// stateIssuedBy builds a connection state carrying a single leaf with the given
// issuer. It is enough to exercise the pinned-authority path, which is decided
// on the issuer alone and never reaches chain verification.
func stateIssuedBy(cn, org string) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Issuer: pkix.Name{CommonName: cn, Organization: []string{org}},
	}}}
}

func TestIdentifyRejectsAnEmptyChain(t *testing.T) {
	if ok, _ := identify(nil, control); ok {
		t.Error("no connection state cannot prove a service is itself")
	}
	empty := &tls.ConnectionState{}
	if ok, _ := identify(empty, control); ok {
		t.Error("a handshake with no certificate cannot prove a service is itself")
	}
}

func TestIdentifyAcceptsAPinnedAuthority(t *testing.T) {
	// Signal runs its own CA and pins it. The chain validates against no
	// browser trust store and appears in no CT log, which is what "forged"
	// looks like everywhere else — so the expected issuer is what decides it.
	pinned := endpoint{Host: "chat.signal.org", Port: 443, TLS: true, Issuer: "Signal Messenger"}
	ok, issuer := identify(stateIssuedBy("Signal Messenger", "Signal Messenger, LLC"), pinned)
	if !ok {
		t.Errorf("Signal's own authority was reported as interception (issuer %q)", issuer)
	}
	// Case is not what distinguishes an interceptor from a CA.
	if ok, _ := identify(stateIssuedBy("signal messenger", "x"), pinned); !ok {
		t.Error("issuer matching must not depend on capitalisation")
	}
	// Anything else answering for a pinned endpoint is an interceptor, however
	// respectable its certificate looks elsewhere.
	for _, other := range []string{"Zscaler Root CA", "DigiCert Global Root G3", "Corporate Proxy"} {
		if ok, _ := identify(stateIssuedBy(other, other), pinned); ok {
			t.Errorf("%q was accepted for an endpoint that pins Signal Messenger", other)
		}
	}
}

func TestExpectationNamesWhatWasMissing(t *testing.T) {
	pinned := endpoint{Host: "chat.signal.org", Issuer: "Signal Messenger"}
	if got := expectation(pinned); !strings.Contains(got, "Signal Messenger") {
		t.Errorf("expectation(%v) = %q, want it to name the pinned authority", pinned, got)
	}
	public := endpoint{Host: "matrix.org"}
	if got := expectation(public); !strings.Contains(got, "matrix.org") {
		t.Errorf("expectation(%v) = %q, want it to name the host", public, got)
	}
}

func TestPinnedEndpointsSpeakTLS(t *testing.T) {
	// An expected issuer is only meaningful for an endpoint whose certificate
	// is actually inspected.
	for _, svc := range services {
		for _, ep := range svc.Endpoints {
			if ep.Issuer != "" && !ep.TLS {
				t.Errorf("%s %s names an expected issuer but is never handshaked with",
					svc.Name, ep.Addr())
			}
		}
	}
}

func TestCompactErr(t *testing.T) {
	tests := []struct{ in, want string }{
		{"dial tcp 1.2.3.4:443: i/o timeout", "silently dropped (timeout)"},
		{"dial tcp 1.2.3.4:443: connect: connection refused", "actively refused"},
		{"read tcp: read: connection reset by peer", "connection reset"},
		{"lookup chat.signal.org: no such host", "no such host"},
	}
	for _, tc := range tests {
		if got := compactErr(errors.New(tc.in)); got != tc.want {
			t.Errorf("compactErr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if compactErr(nil) != "" {
		t.Error("no error compacts to nothing")
	}
	long := strings.Repeat("x", 200)
	if got := compactErr(errors.New(long)); len(got) > 72 {
		t.Errorf("compactErr returned %d characters, which would break the table", len(got))
	}
}
