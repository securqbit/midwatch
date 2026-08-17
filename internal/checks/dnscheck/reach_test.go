// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnscheck

import (
	"testing"

	"github.com/securqbit/midwatch/internal/dnsx"
)

func sys(addr string) dnsx.Resolver {
	return dnsx.Resolver{Name: "system", Transport: dnsx.UDP, Addr: addr + ":53"}
}

func pub(name, addr string) dnsx.Resolver {
	return dnsx.Resolver{Name: name, Transport: dnsx.UDP, Addr: addr + ":53"}
}

// The ordinary case: everything answers, nothing is reported.
func TestClassifyReachAllOpen(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: sys("192.168.1.1"), udpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1"), udpOK: true},
		{resolver: pub("Google", "8.8.8.8"), udpOK: true},
	}, 1)

	if !sum.systemWorks {
		t.Error("systemWorks should be true when the system resolver answers")
	}
	if !sum.hasControl {
		t.Fatal("hasControl should be true when a public resolver answers")
	}
	if got := sum.control.Host(); got != "1.1.1.1" {
		t.Errorf("control = %q, want the first answering public resolver 1.1.1.1", got)
	}
	if len(sum.unreachable) != 0 || len(sum.tcpOnly) != 0 {
		t.Errorf("clean network produced unreachable=%v tcpOnly=%v", sum.unreachable, sum.tcpOnly)
	}
	if len(sum.usable) != 3 {
		t.Errorf("usable = %d resolvers, want 3", len(sum.usable))
	}
	if sum.publicTotal != 2 {
		t.Errorf("publicTotal = %d, want 2", sum.publicTotal)
	}
}

// The network's own resolver works and no independent one can be reached over
// any transport. Nothing is forged, so every answer-integrity check passes;
// the finding is that none of them could be corroborated.
func TestClassifyReachForcedResolver(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: sys("192.168.1.1"), udpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1")},
		{resolver: pub("Google", "8.8.8.8")},
		{resolver: pub("Quad9", "9.9.9.9")},
	}, 1)

	if !sum.systemWorks {
		t.Error("systemWorks should be true")
	}
	if sum.hasControl {
		t.Error("hasControl should be false when no public resolver answers")
	}
	if len(sum.unreachable) != 3 {
		t.Errorf("unreachable = %v, want all three public resolvers", sum.unreachable)
	}
	if len(sum.tcpOnly) != 0 {
		t.Errorf("tcpOnly = %v, want none", sum.tcpOnly)
	}
	// This combination is what fires dns.forced-resolver.
	if !(sum.publicTotal > 0 && !sum.hasControl && sum.systemWorks) {
		t.Error("the forced-resolver condition did not hold for a forced-resolver network")
	}
}

// UDP/53 dropped while TCP/53 answers. The resolver is still usable, so it
// must remain a control — reporting "no second opinion" here would overstate
// what was observed.
func TestClassifyReachUDPFilteredKeepsControl(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: sys("192.168.1.1"), udpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1"), tcpOK: true},
		{resolver: pub("Google", "8.8.8.8"), tcpOK: true},
	}, 1)

	if len(sum.tcpOnly) != 2 {
		t.Errorf("tcpOnly = %v, want both public resolvers", sum.tcpOnly)
	}
	if len(sum.unreachable) != 0 {
		t.Errorf("unreachable = %v, want none: TCP answered", sum.unreachable)
	}
	if !sum.hasControl {
		t.Fatal("a TCP-reachable public resolver is still a control")
	}
	if sum.control.Transport != dnsx.TCP {
		t.Errorf("control transport = %q, want tcp so later probes do not retry blocked UDP",
			sum.control.Transport)
	}
	// forced-resolver must NOT fire: a second opinion is available over TCP.
	if sum.publicTotal > 0 && !sum.hasControl && sum.systemWorks {
		t.Error("forced-resolver fired even though TCP gave an independent vantage point")
	}
	// Every usable resolver that was TCP-rescued must carry the TCP transport,
	// or downstream probes would go back to timing out on UDP.
	for _, r := range sum.usable[1:] {
		if r.Transport != dnsx.TCP {
			t.Errorf("usable resolver %s kept transport %q, want tcp", r.Host(), r.Transport)
		}
	}
}

// A system resolver reachable only over TCP is still a working system
// resolver; treating it as broken would suppress the forced-resolver finding.
func TestClassifyReachSystemResolverOverTCPCounts(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: sys("192.168.1.1"), tcpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1")},
	}, 1)

	if !sum.systemWorks {
		t.Error("a system resolver answering over TCP must count as working")
	}
	if !(sum.publicTotal > 0 && !sum.hasControl && sum.systemWorks) {
		t.Error("forced-resolver should fire: the system resolver works and no public one does")
	}
}

// Partial blocking is a weaker signal and must not be inflated into
// forced-resolver while a working control remains.
func TestClassifyReachPartialBlock(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: sys("192.168.1.1"), udpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1")},
		{resolver: pub("Google", "8.8.8.8"), udpOK: true},
	}, 1)

	if len(sum.unreachable) != 1 || sum.unreachable[0] != "1.1.1.1" {
		t.Errorf("unreachable = %v, want just 1.1.1.1", sum.unreachable)
	}
	if !sum.hasControl || sum.control.Host() != "8.8.8.8" {
		t.Errorf("control = %v, want 8.8.8.8 to be picked as the working control", sum.control)
	}
	if sum.publicTotal > 0 && !sum.hasControl && sum.systemWorks {
		t.Error("forced-resolver fired while a public resolver was still reachable")
	}
}

// With no /etc/resolv.conf there are no system resolvers at all. Nothing
// should claim the system resolver works, and forced-resolver must not fire.
func TestClassifyReachNoSystemResolvers(t *testing.T) {
	sum := classifyReach([]reach{
		{resolver: pub("Cloudflare", "1.1.1.1")},
		{resolver: pub("Google", "8.8.8.8")},
	}, 0)

	if sum.systemWorks {
		t.Error("systemWorks should be false when there are no system resolvers")
	}
	if sum.publicTotal != 2 {
		t.Errorf("publicTotal = %d, want 2", sum.publicTotal)
	}
	if sum.publicTotal > 0 && !sum.hasControl && sum.systemWorks {
		t.Error("forced-resolver requires a working system resolver to contrast against")
	}
}

func TestClassifyReachVerdictsAlignWithResults(t *testing.T) {
	results := []reach{
		{resolver: sys("192.168.1.1"), udpOK: true},
		{resolver: pub("Cloudflare", "1.1.1.1"), tcpOK: true},
		{resolver: pub("Google", "8.8.8.8")},
	}
	sum := classifyReach(results, 1)

	// The renderer indexes verdicts by result position, so a length or order
	// mismatch would mislabel rows.
	if len(sum.verdicts) != len(results) {
		t.Fatalf("verdicts length %d, want %d", len(sum.verdicts), len(results))
	}
	for i, want := range []reachVerdict{reachUDP, reachTCPOnly, reachDead} {
		if sum.verdicts[i] != want {
			t.Errorf("verdicts[%d] = %v, want %v", i, sum.verdicts[i], want)
		}
	}
}
