// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package dnscheck detects DNS interception, redirection and answer forgery.
//
// The module never trusts a single vantage point. It asks the same questions
// through the resolver this machine is configured to use and through public
// resolvers reached directly, compares the answers, and probes the transport
// itself:
//
//   - does a resolver that cannot exist still answer? (transparent redirection)
//   - can any independent resolver be reached at all? (resolver lock-in)
//   - do fixed anycast hostnames resolve to their real addresses? (forgery)
//   - does a name that does not exist return an address? (NXDOMAIN hijacking)
//   - is the question echoed back byte for byte? (0x20, rewriting middlebox)
//   - is DNSSEC validated, and can encrypted DNS leave the network at all?
//
// The reachability question comes first, because it decides what the rest of
// the module is able to conclude. A network that permits no second opinion can
// return perfectly consistent answers that nothing is in a position to check.
package dnscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/securqbit/midwatch/internal/dnsx"
	"github.com/securqbit/midwatch/internal/netpath"
	"github.com/securqbit/midwatch/internal/report"
)

// Options configures a DNS scan.
type Options struct {
	Timeout time.Duration
	Deep    bool
}

type state struct {
	m      *report.Module
	c      *dnsx.Client
	system []dnsx.Resolver
	opts   Options

	// usable holds the resolvers that actually answered during the
	// reachability sweep. Probing through a resolver already known to be
	// unreachable only buys another full timeout and no information.
	usable     []dnsx.Resolver
	control    dnsx.Resolver // a public resolver that answers, for comparison
	hasControl bool

	// pathName is the interface carrying the default route, and tunneled
	// reports whether it is a VPN. A tunnel that offers its own resolver
	// answers port 53 itself, which is indistinguishable from a hostile
	// middlebox to a probe that cannot see the tunnel, so findings that
	// describe the path's policy are attributed to it rather than the network.
	pathName string
	tunneled bool

	redirected   bool // port 53 answered by something that cannot be the real server
	forged       bool // a canary hostname resolved to the wrong address
	forgeLogged  bool // a forgery finding has already been recorded
	hijacked     bool // NXDOMAIN turned into an address
	rewritten    bool // query itself was modified in flight
	lockedIn     bool // encrypted DNS blocked, or off-network DNS is unreachable
	noDNSSEC     bool // resolver does not validate
	encryptedMTM bool // DoT endpoint presented a forged certificate
}

// Run executes the DNS module.
func Run(ctx context.Context, opts Options) *report.Module {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	s := &state{
		m:      report.NewModule("dns", "DNS interception", report.KindInterception),
		c:      dnsx.NewClient(timeout),
		system: SystemResolvers(),
		opts:   opts,
	}

	s.reportPath()
	s.reportConfiguration()
	s.checkBlackhole(ctx)
	s.checkReachability(ctx)
	s.checkAnchors(ctx)
	s.checkNXDomain(ctx)
	s.checkCaseEcho(ctx)
	s.checkControlDivergence(ctx)
	s.checkDNSSEC(ctx)
	s.checkEncrypted(ctx)
	s.deriveLevel()
	return s.m
}

// reach records whether one resolver could be reached, and over which
// transport. The UDP/TCP split is the interesting part: a network with no
// route to a resolver blocks both, whereas a network that wants your lookups
// to stay on the path it controls blocks only the datagram port.
type reach struct {
	resolver dnsx.Resolver
	udpOK    bool
	tcpOK    bool
	err      error
}

// reachVerdict is how one resolver ended up being classified.
type reachVerdict int

const (
	reachUDP     reachVerdict = iota // answers on UDP 53, the ordinary case
	reachTCPOnly                     // UDP dropped, TCP 53 answers
	reachDead                        // no answer over either transport
)

// reachSummary is what the reachability sweep concluded. It is kept separate
// from the probing so the conclusions are decided by a pure function: the
// distinction it draws — between a resolver that cannot be consulted at all
// and one that can only be consulted over TCP — decides which finding is
// reported, and that should not depend on the network a test happens to run on.
type reachSummary struct {
	verdicts    []reachVerdict
	systemWorks bool
	unreachable []string // public resolvers dead over both transports
	tcpOnly     []string // public resolvers reachable only over TCP
	publicTotal int
	usable      []dnsx.Resolver
	control     dnsx.Resolver
	hasControl  bool
}

// classifyReach interprets the sweep. results[:systemCount] are this host's
// configured resolvers; the rest are the public control group.
func classifyReach(results []reach, systemCount int) reachSummary {
	sum := reachSummary{verdicts: make([]reachVerdict, len(results))}
	for i, res := range results {
		isSystem := i < systemCount
		if !isSystem {
			sum.publicTotal++
		}
		switch {
		case res.udpOK:
			sum.verdicts[i] = reachUDP
			sum.systemWorks = sum.systemWorks || isSystem
			sum.usable = append(sum.usable, res.resolver)
			if !isSystem && !sum.hasControl {
				sum.control, sum.hasControl = res.resolver, true
			}
		case res.tcpOK:
			// Still a working resolver, just not over the port this network
			// filters, so keep it in play over TCP.
			sum.verdicts[i] = reachTCPOnly
			sum.systemWorks = sum.systemWorks || isSystem
			overTCP := res.resolver
			overTCP.Transport = dnsx.TCP
			sum.usable = append(sum.usable, overTCP)
			if !isSystem {
				sum.tcpOnly = append(sum.tcpOnly, res.resolver.Host())
				if !sum.hasControl {
					sum.control, sum.hasControl = overTCP, true
				}
			}
		default:
			sum.verdicts[i] = reachDead
			if !isSystem {
				sum.unreachable = append(sum.unreachable, res.resolver.Host())
			}
		}
	}
	return sum
}

// checkReachability establishes which resolvers this network will actually let
// you talk to. A network that answers through its own resolver while silently
// dropping every off-network one has taken your choice of resolver away, and
// that is a finding in its own right even when the answers it returns are
// truthful.
func (s *state) checkReachability(ctx context.Context) {
	probes := append(append([]dnsx.Resolver{}, s.system...), PublicResolvers...)
	results := make([]reach, len(probes))

	var wg sync.WaitGroup
	for i, r := range probes {
		wg.Add(1)
		go func(i int, r dnsx.Resolver) {
			defer wg.Done()
			out := reach{resolver: r}
			if _, _, err := s.c.Query(ctx, r, reachabilityProbe, dnsx.TypeA); err == nil {
				out.udpOK = true
			} else {
				out.err = err
				// Only a deliberately shaped filter blocks one transport and
				// not the other, so the retry is evidence, not just a rescue.
				overTCP := r
				overTCP.Transport = dnsx.TCP
				if _, _, err := s.c.Query(ctx, overTCP, reachabilityProbe, dnsx.TypeA); err == nil {
					out.tcpOK = true
				}
			}
			results[i] = out
		}(i, r)
	}
	wg.Wait()

	sum := classifyReach(results, len(s.system))
	s.usable, s.control, s.hasControl = sum.usable, sum.control, sum.hasControl
	systemWorks, unreachable, tcpOnly, publicTotal :=
		sum.systemWorks, sum.unreachable, sum.tcpOnly, sum.publicTotal

	for i, res := range results {
		label := res.resolver.Host()
		if i < len(s.system) {
			label += " (system)"
		}
		switch sum.verdicts[i] {
		case reachUDP:
			s.m.Row("resolver reachability", report.StatusOK, label, "reachable", "answers on UDP port 53")
		case reachTCPOnly:
			s.m.Row("resolver reachability", report.StatusBad, label, "UDP blocked, TCP open",
				"port 53 is filtered by transport, which no capacity limit would do")
		default:
			s.m.Row("resolver reachability", report.StatusWarn, label, "unreachable",
				compactErr(res.err))
		}
	}

	if len(tcpOnly) > 0 {
		s.lockedIn = true
		s.m.Add("dns.udp53-filtered", "Plain DNS is blocked over UDP but allowed over TCP",
			s.policySeverity(report.SevMedium),
			s.attribute("The same resolvers that ignore a UDP query on port 53 answer the identical question "+
				"over TCP. Nothing about bandwidth or abuse distinguishes those two packets, so the filter "+
				"was shaped deliberately. Blocking the transport every operating system reaches for by "+
				"default is how a network keeps your lookups on the resolver it chose for you, without ever "+
				"having to forge an answer."),
			"UDP blocked, TCP open: "+strings.Join(tcpOnly, ", "))
	}

	switch {
	// No independent resolver answered over any transport, so there is no
	// second opinion to be had. The condition is hasControl rather than a
	// count of blocked resolvers because one reachable over TCP is still a
	// corroborating vantage point; counting it as blocked would overstate the
	// finding.
	case publicTotal > 0 && !s.hasControl && systemWorks:
		s.lockedIn = true
		s.m.Add("dns.forced-resolver", "You cannot use any resolver but this network's",
			s.policySeverity(report.SevMedium),
			s.attribute("Every independent resolver tested was unreachable, over UDP and TCP alike, while the "+
				"resolver this network handed you answers normally. Your lookups are not being forged, but "+
				"they have nowhere else to go: whoever runs this resolver sees every name you ask for, and "+
				"is the only party in a position to tell you the truth about them. midwatch cannot "+
				"independently corroborate the answers below, because no second opinion is permitted."),
			fmt.Sprintf("%d of %d public resolvers unreachable", len(unreachable), publicTotal),
			"blocked: "+strings.Join(unreachable, ", "))
	case len(unreachable) > 0:
		s.m.Add("dns.public-resolvers-blocked", "Some public resolvers are unreachable", report.SevLow,
			"Part of the independent resolver ecosystem cannot be reached from this network. That narrows "+
				"the set of vantage points available to cross-check an answer against, which is the only "+
				"defence you have against a resolver that lies.",
			"blocked: "+strings.Join(unreachable, ", "))
	}
}

// controlResolver returns a public resolver known to answer, for use as the
// independent vantage point. The second return reports whether one exists at
// all: on a network that blocks every off-network resolver, there is no
// control group and checks that need one must say so rather than guess.
func (s *state) controlResolver() (dnsx.Resolver, bool) {
	return s.control, s.hasControl
}

// primaryResolver returns the resolver a normal application on this host would
// end up using: the configured one when it works, otherwise anything reachable.
func (s *state) primaryResolver() (dnsx.Resolver, bool) {
	for _, r := range s.usable {
		if r.Name == "system" {
			return r, true
		}
	}
	if len(s.usable) > 0 {
		return s.usable[0], true
	}
	return dnsx.Resolver{}, false
}

func (s *state) reportConfiguration() {
	if len(s.system) == 0 {
		s.m.Row("configuration", report.StatusInfo, "system resolvers", "not readable",
			"could not read /etc/resolv.conf; comparing against public resolvers only")
		return
	}
	for _, r := range s.system {
		host := r.Host()
		note := "configured for this host"
		if ip := net.ParseIP(host); ip != nil {
			switch {
			case ip.IsLoopback():
				note = "loopback — a local resolver or filtering daemon is in the path"
			case ip.IsPrivate():
				note = "on the local network — the operator of this LAN sees every lookup"
			}
		}
		s.m.Row("configuration", report.StatusInfo, "system resolver", host, note)
	}
}

// reportPath establishes who owns the resolver path before anything is
// concluded about it. Everything this module measures describes whatever
// forwards this machine's queries, and when that is a VPN rather than the local
// network, the report has to say so.
func (s *state) reportPath() {
	p := netpath.Detect()
	s.pathName, s.tunneled = p.Describe(), p.Tunneled
	switch {
	case s.tunneled:
		s.m.Row("path", report.StatusInfo, "default route", s.pathName,
			"a tunnel owns the default route, so DNS policy measured here belongs to the tunnel, "+
				"not the network this machine is attached to")
	case p.Interface != "":
		s.m.Row("path", report.StatusOK, "default route", s.pathName,
			"no tunnel in the path, so these results describe the network itself")
	}
}

// policySeverity grades a finding that describes the path's filtering or
// resolution policy rather than the integrity of an answer. Behind a tunnel
// such a finding describes software the user installed on purpose, so it is
// recorded as informational: the observation is still true and still printed,
// but it is not evidence about the network and must not be scored as if it
// were. Answer-integrity findings — forgery, hijack, sinkholing, a forged DoT
// certificate — are deliberately not routed through here, because fabricated
// answers matter whoever produces them.
func (s *state) policySeverity(network report.Severity) report.Severity {
	if s.tunneled {
		return report.SevInfo
	}
	return network
}

// attribute appends the tunnel caveat to a policy finding's detail.
func (s *state) attribute(detail string) string {
	if !s.tunneled {
		return detail
	}
	return detail + " The default route belongs to " + s.pathName + ", a tunnel, so this describes the " +
		"tunnel operator's policy rather than the network's. Re-run with the tunnel disconnected to " +
		"judge the network itself."
}

// checkBlackhole asks a documentation-range address for a record. Nothing
// there can answer, so a reply means the query never left the network.
func (s *state) checkBlackhole(ctx context.Context) {
	// Probe concurrently and with a short deadline: an interceptor replies in
	// milliseconds, so only an honest network waits, and it should not wait
	// three times over.
	client := dnsx.NewClient(blackholeTimeout(s.opts.Timeout))
	replies := make([]*dnsx.Msg, len(BlackholeProbes))
	var wg sync.WaitGroup
	for i, addr := range BlackholeProbes {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			r := dnsx.Resolver{Name: "blackhole", Transport: dnsx.UDP, Addr: addr}
			if msg, _, err := client.Query(ctx, r, reachabilityProbe, dnsx.TypeA); err == nil {
				replies[i] = msg
			}
		}(i, addr)
	}
	wg.Wait()

	answered := 0
	for i, addr := range BlackholeProbes {
		msg := replies[i]
		if msg == nil {
			s.m.Row("transparent redirection", report.StatusOK, addr, "silent",
				"unroutable address stayed unroutable")
			continue
		}
		answered++
		// The interception is the same event either way, but behind a tunnel it
		// is the tunnel's resolver doing its job, so the row is not painted as
		// an attack on the network.
		status, by := report.StatusBad, "a local device"
		if s.tunneled {
			status, by = report.StatusInfo, s.pathName
		}
		s.m.Row("transparent redirection", status, addr,
			dnsx.RcodeString(msg.Rcode),
			"answered by "+by+describeAnswerSuffix(msg))
	}
	if answered > 0 {
		s.redirected = true
		evidence := fmt.Sprintf("%d of %d unroutable probes answered", answered, len(BlackholeProbes))
		if s.tunneled {
			// A tunnel answering port 53 itself is how a private resolver is
			// meant to work. It is worth stating, because every lookup is
			// visible to the tunnel operator, but it is not an ambush.
			s.m.Add("dns.transparent-redirect", "DNS is resolved by the tunnel, not the resolvers you configured",
				report.SevInfo,
				s.attribute("A query addressed to an unroutable documentation address received a reply, so "+
					"every packet sent to port 53 is being intercepted and answered locally regardless of "+
					"the resolver configured for this host. Every lookup is therefore visible to whoever "+
					"operates that path."),
				evidence, "path: "+s.pathName)
		} else {
			s.m.Add("dns.transparent-redirect", "All DNS traffic is being transparently redirected",
				report.SevHigh,
				"A query addressed to an unroutable documentation address received a reply, which is only "+
					"possible if a device on this network is intercepting every packet sent to port 53 and "+
					"answering on its behalf. Changing your DNS settings will not move your lookups: whatever "+
					"server you configure, this device answers instead.",
				evidence)
		}
	}
}

// queryResult pairs a reply with the resolver that produced it, so a fan-out
// can be collected concurrently and then interpreted in a fixed order. Probing
// in parallel but reporting in sequence keeps a run reproducible: two scans of
// the same network must produce the same rows in the same order.
type queryResult struct {
	msg *dnsx.Msg
	err error
}

// fanOut sends queries[i] to resolvers[i] concurrently and returns the replies
// in the same order. Both slices must be the same length, and every query must
// be built before the fan-out starts so that nothing is shared across the
// goroutines.
func (s *state) fanOut(ctx context.Context, resolvers []dnsx.Resolver, queries []*dnsx.Msg) []queryResult {
	out := make([]queryResult, len(resolvers))
	var wg sync.WaitGroup
	for i := range resolvers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg, _, err := s.c.Exchange(ctx, resolvers[i], queries[i])
			out[i] = queryResult{msg: msg, err: err}
		}(i)
	}
	wg.Wait()
	return out
}

// checkAnchors resolves hostnames whose addresses are fixed constants.
func (s *state) checkAnchors(ctx context.Context) {
	type pair struct {
		anchor int
		r      dnsx.Resolver
	}
	var pairs []pair
	var resolvers []dnsx.Resolver
	var queries []*dnsx.Msg
	for i := range anchors {
		for _, r := range s.usable {
			pairs = append(pairs, pair{i, r})
			resolvers = append(resolvers, r)
			queries = append(queries, dnsx.NewQuery(anchors[i].Name, dnsx.TypeA, dnsx.ClassIN))
		}
	}
	if len(pairs) == 0 {
		s.m.Row("answer integrity", report.StatusSkip, "forgery canaries", "no resolver reachable",
			"nothing on this network answered a DNS query")
		return
	}
	results := s.fanOut(ctx, resolvers, queries)

	for i, p := range pairs {
		a := anchors[p.anchor]
		res := results[i]
		label := fmt.Sprintf("%s via %s", a.Name, p.r.Host())
		if res.err != nil {
			s.m.Row("answer integrity", report.StatusSkip, label, "no answer", compactErr(res.err))
			continue
		}
		got := res.msg.IPStrings()
		switch {
		case len(got) == 0:
			s.m.Row("answer integrity", report.StatusWarn, label,
				dnsx.RcodeString(res.msg.Rcode), "no address returned for a name that always resolves")
		case anyContained(got, a.IPs):
			s.m.Row("answer integrity", report.StatusOK, label, strings.Join(got, " "), "")
		default:
			s.forged = true
			note := "expected " + strings.Join(a.IPs, " or ")
			if b := bogonsIn(res.msg.IPs()); len(b) > 0 {
				note = "sinkholed to " + strings.Join(b, " ")
			}
			s.m.Row("answer integrity", report.StatusBad, label, strings.Join(got, " "), note)
			if s.forgeLogged {
				continue
			}
			s.forgeLogged = true
			s.m.Add("dns.forged-answer", "DNS answers are being forged", report.SevCritical,
				fmt.Sprintf("%s has a fixed, well-known address, but %s returned something else. "+
					"Somebody is rewriting DNS responses in flight, which lets them silently point any "+
					"hostname you look up at infrastructure they control.", a.Name, p.r.Host()),
				fmt.Sprintf("%s → %s (expected %s)", a.Name, strings.Join(got, " "), strings.Join(a.IPs, " or ")))
		}
	}
}

// probeResolvers returns the resolvers used for the single-question probes:
// every configured resolver, plus one working public control if there is one.
func (s *state) probeResolvers() []dnsx.Resolver {
	var out []dnsx.Resolver
	for _, r := range s.usable {
		if r.Name == "system" {
			out = append(out, r)
		}
	}
	if c, ok := s.controlResolver(); ok {
		out = append(out, c)
	}
	if len(out) == 0 && len(s.usable) > 0 {
		out = append(out, s.usable[0])
	}
	return out
}

// checkNXDomain looks for wildcard rewriting of names that do not exist.
func (s *state) checkNXDomain(ctx context.Context) {
	name := dnsx.RandomLabel(20) + ".com"
	resolvers := s.probeResolvers()
	queries := make([]*dnsx.Msg, len(resolvers))
	for i := range resolvers {
		queries[i] = dnsx.NewQuery(name, dnsx.TypeA, dnsx.ClassIN)
	}
	results := s.fanOut(ctx, resolvers, queries)

	for i, r := range resolvers {
		res := results[i]
		label := "nonexistent name via " + r.Host()
		if res.err != nil {
			s.m.Row("answer integrity", report.StatusSkip, label, "no answer", compactErr(res.err))
			continue
		}
		got := res.msg.IPStrings()
		switch {
		case res.msg.Rcode == dnsx.RcodeNXDomain && len(got) == 0:
			s.m.Row("answer integrity", report.StatusOK, label, "NXDOMAIN", "correct")
		case len(got) > 0:
			s.m.Row("answer integrity", report.StatusBad, label, strings.Join(got, " "),
				"a name that does not exist was given an address")
			if s.hijacked {
				continue
			}
			s.hijacked = true
			s.m.Add("dns.nxdomain-hijack", "Nonexistent domains are redirected to a server",
				report.SevHigh,
				"A randomly generated hostname that cannot exist resolved to a real address. The resolver "+
					"is fabricating answers, typically to serve advertising or a search page. The same "+
					"mechanism can silently capture traffic meant for hosts that are merely typo'd or "+
					"temporarily unregistered.",
				fmt.Sprintf("%s → %s via %s", name, strings.Join(got, " "), r.Host()))
		default:
			s.m.Row("answer integrity", report.StatusInfo, label, dnsx.RcodeString(res.msg.Rcode), "")
		}
	}
}

// checkCaseEcho applies DNS 0x20 encoding. A conforming resolver copies the
// question section verbatim; a middlebox that reconstructs the query does not.
func (s *state) checkCaseEcho(ctx context.Context) {
	resolvers := s.probeResolvers()
	asked := make([]string, len(resolvers))
	queries := make([]*dnsx.Msg, len(resolvers))
	for i := range resolvers {
		asked[i] = dnsx.RandomizeCase(caseEchoProbe)
		queries[i] = dnsx.NewQuery(asked[i], dnsx.TypeA, dnsx.ClassIN)
	}
	results := s.fanOut(ctx, resolvers, queries)

	for i, r := range resolvers {
		res := results[i]
		label := "question echo via " + r.Host()
		if res.err != nil || res.msg == nil {
			s.m.Row("query integrity", report.StatusSkip, label, "no answer", compactErr(res.err))
			continue
		}
		echoed := strings.TrimSuffix(res.msg.QuestionName(), ".")
		if echoed == asked[i] {
			s.m.Row("query integrity", report.StatusOK, label, "verbatim", "0x20 encoding preserved")
			continue
		}
		if strings.EqualFold(echoed, asked[i]) {
			s.m.Row("query integrity", report.StatusWarn, label, "case normalised",
				"asked "+asked[i]+", got "+echoed)
			if s.rewritten {
				continue
			}
			s.rewritten = true
			s.m.Add("dns.query-rewritten", "Your DNS queries are rewritten in transit", report.SevMedium,
				"The question was returned with different capitalisation than it was sent with. A resolver "+
					"copies the question section byte for byte, so the query was parsed and regenerated by "+
					"something in between. That device is in a position to read, log and alter every lookup, "+
					"and its rewriting also strips the 0x20 entropy that protects you from cache poisoning.",
				"sent "+asked[i]+", received "+echoed+" via "+r.Host())
		}
	}
}

// checkControlDivergence compares system answers against an independent
// resolver. Both sides of each comparison are fetched concurrently.
func (s *state) checkControlDivergence(ctx context.Context) {
	sys, ok := s.primaryResolver()
	if !ok || sys.Name != "system" {
		return
	}
	control, haveControl := s.controlResolver()

	resolvers := make([]dnsx.Resolver, 0, len(controlDomains)*2)
	queries := make([]*dnsx.Msg, 0, len(controlDomains)*2)
	for _, domain := range controlDomains {
		resolvers = append(resolvers, sys)
		queries = append(queries, dnsx.NewQuery(domain, dnsx.TypeA, dnsx.ClassIN))
		if haveControl {
			resolvers = append(resolvers, control)
			queries = append(queries, dnsx.NewQuery(domain, dnsx.TypeA, dnsx.ClassIN))
		}
	}
	results := s.fanOut(ctx, resolvers, queries)

	stride := 1
	if haveControl {
		stride = 2
	}
	for i, domain := range controlDomains {
		sysRes := results[i*stride]
		if sysRes.err != nil {
			s.m.Row("cross-resolver comparison", report.StatusSkip, domain, "system resolver failed",
				compactErr(sysRes.err))
			continue
		}
		sysIPs := sysRes.msg.IPStrings()
		sort.Strings(sysIPs)

		if b := bogonsIn(sysRes.msg.IPs()); len(b) > 0 {
			s.forged = true
			s.m.Row("cross-resolver comparison", report.StatusBad, domain, strings.Join(sysIPs, " "),
				"resolved to a non-routable address")
			s.m.Add("dns.sinkholed", "A public site resolves to a local address", report.SevHigh,
				fmt.Sprintf("%s resolved to %s, which is not a public address. This name is being "+
					"sinkholed: your requests for it are directed at a machine on this network instead of "+
					"the real site, which is how both content filters and credential-harvesting portals work.",
					domain, strings.Join(b, " ")))
			continue
		}

		if !haveControl {
			s.m.Row("cross-resolver comparison", report.StatusInfo, domain, strings.Join(sysIPs, " "),
				"no independent resolver is reachable to compare against")
			continue
		}
		pubRes := results[i*stride+1]
		if pubRes.err != nil {
			s.m.Row("cross-resolver comparison", report.StatusInfo, domain, strings.Join(sysIPs, " "),
				"no public control answer to compare against")
			continue
		}
		pubIPs := pubRes.msg.IPStrings()
		if anyContained(sysIPs, pubIPs) || len(pubIPs) == 0 {
			s.m.Row("cross-resolver comparison", report.StatusOK, domain, strings.Join(sysIPs, " "),
				"agrees with public resolvers")
			continue
		}
		// Large sites are served from many edges, so disagreement alone is
		// normal; it is only reported as an observation.
		s.m.Row("cross-resolver comparison", report.StatusInfo, domain, strings.Join(sysIPs, " "),
			fmt.Sprintf("differs from %s (%s), normal for anycast CDNs",
				control.Host(), strings.Join(pubIPs, " ")))
	}
}

// checkDNSSEC establishes whether bad signatures are actually rejected.
func (s *state) checkDNSSEC(ctx context.Context) {
	resolver, ok := s.primaryResolver()
	if !ok {
		s.m.Row("dnssec", report.StatusSkip, "bad-signature domain", "no resolver reachable", "")
		return
	}

	// Both questions go out at once: they are independent, and the broken
	// domain often answers slowly precisely because it fails validation.
	broken := dnsx.NewQuery(dnssecFailedProbe, dnsx.TypeA, dnsx.ClassIN)
	signed := dnsx.NewQuery(dnssecValidProbe, dnsx.TypeA, dnsx.ClassIN)
	signed.DO = true
	res := s.fanOut(ctx, []dnsx.Resolver{resolver, resolver}, []*dnsx.Msg{broken, signed})

	// A deliberately broken signature must be refused with SERVFAIL.
	msg, err := res[0].msg, res[0].err
	switch {
	case err != nil:
		s.m.Row("dnssec", report.StatusSkip, "bad-signature domain", "no answer", compactErr(err))
	case msg.Rcode == dnsx.RcodeServFail:
		s.m.Row("dnssec", report.StatusOK, "bad-signature domain", "SERVFAIL", "signatures are validated")
	case len(msg.IPs()) > 0:
		s.noDNSSEC = true
		s.m.Row("dnssec", report.StatusWarn, "bad-signature domain", strings.Join(msg.IPStrings(), " "),
			"a domain with broken DNSSEC still resolved")
		s.m.Add("dns.no-dnssec", "Your resolver does not validate DNSSEC", report.SevMedium,
			"A domain published with deliberately invalid signatures resolved successfully, so this "+
				"resolver is not checking them. Nothing downstream will notice if answers are tampered "+
				"with, which is the precondition every DNS spoofing attack relies on.",
			dnssecFailedProbe+" resolved via "+resolver.Host())
	default:
		s.m.Row("dnssec", report.StatusInfo, "bad-signature domain", dnsx.RcodeString(msg.Rcode), "")
	}

	// A signed, valid domain should come back with the AD bit set.
	if ad, err := res[1].msg, res[1].err; err == nil && ad != nil {
		if ad.AD {
			s.m.Row("dnssec", report.StatusOK, "authenticated data flag", "set",
				"resolver asserts it validated the answer")
		} else {
			s.m.Row("dnssec", report.StatusWarn, "authenticated data flag", "absent",
				"answers arrive unauthenticated")
		}
	}
}

// checkEncrypted measures whether DNS can leave this network privately, and
// whether the encrypted endpoints themselves are being impersonated.
func (s *state) checkEncrypted(ctx context.Context) {
	type encResult struct {
		msg   *dnsx.Msg
		rtt   time.Duration
		err   error
		state *tls.ConnectionState
		dotOK bool
	}
	results := make([]encResult, len(EncryptedResolvers))

	var wg sync.WaitGroup
	for i, r := range EncryptedResolvers {
		wg.Add(1)
		go func(i int, r dnsx.Resolver) {
			defer wg.Done()
			var out encResult
			out.msg, out.rtt, out.err = s.c.Query(ctx, r, encryptedProbe, dnsx.TypeA)
			// Inspect the certificate a DoT endpoint presents. A forged one
			// means the interceptor is willing to attack encrypted DNS, not
			// merely block it.
			if r.Transport == dnsx.DoT {
				if st, err := s.c.ProbeDoT(ctx, r.Addr, r.ServerName); err == nil && st != nil {
					out.state, out.dotOK = st, true
				}
			}
			results[i] = out
		}(i, r)
	}
	wg.Wait()

	blocked := 0
	for i, r := range EncryptedResolvers {
		res := results[i]
		switch {
		case res.err != nil:
			blocked++
			s.m.Row("encrypted dns", report.StatusWarn, r.Name, "blocked", compactErr(res.err))
		case len(res.msg.IPs()) == 0:
			s.m.Row("encrypted dns", report.StatusWarn, r.Name, dnsx.RcodeString(res.msg.Rcode),
				"reachable but returned no answer")
		default:
			s.m.Row("encrypted dns", report.StatusOK, r.Name,
				fmt.Sprintf("working (%dms)", res.rtt.Milliseconds()), "")
		}
	}

	for i, r := range EncryptedResolvers {
		res := results[i]
		if !res.dotOK || len(res.state.PeerCertificates) == 0 {
			continue
		}
		leaf := res.state.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range res.state.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, verr := leaf.Verify(x509.VerifyOptions{
			DNSName:       r.ServerName,
			Intermediates: inter,
		}); verr != nil {
			s.encryptedMTM = true
			s.m.Row("encrypted dns", report.StatusBad, r.Name+" certificate", "invalid", compactErr(verr))
			s.m.Add("dns.dot-intercepted", "Encrypted DNS is being impersonated", report.SevCritical,
				fmt.Sprintf("The DNS-over-TLS endpoint at %s presented a certificate that does not validate "+
					"for %s. Someone is not merely watching your DNS, they are actively terminating the "+
					"encrypted channel you used to escape that watching.", r.Addr, r.ServerName),
				"issuer: "+leaf.Issuer.String())
		}
	}

	if blocked >= len(EncryptedResolvers) {
		s.lockedIn = true
		s.m.Add("dns.encrypted-blocked", "Encrypted DNS is blocked on this network",
			s.policySeverity(report.SevMedium),
			s.attribute("Every DNS-over-TLS and DNS-over-HTTPS endpoint tested was unreachable while "+
				"plaintext port 53 works. Blocking the private option while permitting the readable one is "+
				"a deliberate configuration: it requires your lookups to stay visible."),
			fmt.Sprintf("%d of %d encrypted resolvers unreachable", blocked, len(EncryptedResolvers)))
	} else if blocked > 0 {
		s.m.Add("dns.encrypted-partial", "Some encrypted DNS endpoints are blocked", report.SevLow,
			"Part of the encrypted DNS ecosystem is unreachable here. That is often filtering by address "+
				"rather than a general policy, but it does narrow your private options.",
			fmt.Sprintf("%d of %d encrypted resolvers unreachable", blocked, len(EncryptedResolvers)))
	}
}

func (s *state) deriveLevel() {
	switch {
	case s.forged || s.encryptedMTM:
		s.m.SetLevel(4, "D4", "Answer forgery",
			"DNS responses on this network are being fabricated. Names with fixed, verifiable addresses "+
				"came back pointing somewhere else, so any hostname you resolve can be silently redirected.")
	case s.hijacked:
		s.m.SetLevel(3, "D3", "Answer manipulation",
			"Responses are being edited rather than merely observed. Nonexistent or filtered names are "+
				"answered with addresses chosen by the network operator.")
	case s.redirected && !s.tunneled:
		s.m.SetLevel(2, "D2", "Transparent redirection",
			"Port 53 is intercepted and answered locally regardless of which resolver you configure. "+
				"Answers still look correct, but every lookup is read and logged by this network, and "+
				"the operator can change any of them at will.")
	case s.rewritten || s.lockedIn || s.noDNSSEC:
		s.m.SetLevel(1, "D1", "Resolver lock-in",
			"Answers are intact, but you have little choice about who gives them to you. Independent "+
				"resolvers are unreachable, encrypted DNS is unavailable, queries are regenerated in "+
				"flight, or nothing validates the signatures that would reveal tampering.")
	case s.redirected:
		// Redirection through a tunnel. The answers checked out, but the
		// network's own DNS behaviour is invisible from inside the tunnel:
		// its resolver answered everything before the network ever saw it.
		// Claiming the network is clean would be as wrong as claiming it
		// intercepts, so this is the inconclusive case, scored at zero.
		s.m.SetLevel(0, "D?", "Inconclusive",
			"Port 53 is answered by "+s.pathName+", the tunnel carrying this machine's traffic, so the "+
				"queries never reached the network being audited and its DNS behaviour could not be "+
				"judged. The answers that came back were themselves consistent and correctly signed. "+
				"Re-run with the tunnel disconnected to measure the network.")
	default:
		s.m.SetLevel(0, "D0", "No DNS interception detected",
			"Lookups reach the resolvers you chose, answers match independent vantage points, and "+
				"encrypted DNS is available if you want it.")
	}
}

// blackholeTimeout bounds a probe whose expected outcome is silence: a device
// intercepting port 53 answers immediately, so a long wait only penalises the
// networks that are behaving.
func blackholeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 3*time.Second {
		return 3 * time.Second
	}
	return timeout
}

// describeAnswerSuffix renders the addresses an interceptor handed back, for
// appending to whatever the caller has named as the responder.
func describeAnswerSuffix(msg *dnsx.Msg) string {
	if ips := msg.IPStrings(); len(ips) > 0 {
		return " returning " + strings.Join(ips, " ")
	}
	return ""
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = strings.TrimPrefix(s, "dnsx: ")
	if i := strings.LastIndex(s, ": "); i > 0 && len(s)-i < 40 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
