// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package commscheck measures whether this network lets you talk to people.
//
// Every other module in midwatch asks what the network does to your traffic.
// This one asks what it does to your contact with other human beings: whether
// Signal, WhatsApp, Telegram, iMessage and FaceTime, Matrix, XMPP and the
// conferencing services can be reached at all, and when they cannot, which
// layer stopped them.
//
// That last part is what makes the answer worth having. "WhatsApp does not
// work here" is something the user already knew. The module separates:
//
//   - the resolver handing back an address the service cannot be at,
//   - the address being unreachable while the name resolves fine,
//   - a device reading the hostname out of the TLS handshake and killing the
//     connection only when it names a messenger,
//   - a certificate that answers for the service without belonging to it,
//   - and the UDP path that voice and video calls negotiate over being closed
//     while the text side works.
//
// It also watches the shape of the blocking rather than only its extent. A
// network where Zoom, Meet and Discord work and Signal, WhatsApp and Matrix do
// not has not run out of bandwidth. It has singled out the services whose
// contents nobody else can read.
//
// This is a censorship module, not a posture one, and the difference is
// deliberate. A closed SMTP port is policy. Taking away the messenger somebody
// reaches for when a conversation matters is not: the conversation does not
// stop, it moves somewhere readable. So blocking findings here deduct from the
// score and speak in the verdict, and the only thing that softens them is a
// tunnel owning the default route — because then the policy being measured
// belongs to software the user installed on purpose.
package commscheck

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/securqbit/midwatch/internal/netpath"
	"github.com/securqbit/midwatch/internal/report"
)

// Options configures the communication scan.
type Options struct {
	Timeout time.Duration
	Deep    bool
}

// maxParallelProbes bounds concurrent connections. The service list is fixed
// and modest, but each entry opens up to three sockets and the module runs
// alongside every other one in a scan.
const maxParallelProbes = 12

// Run executes the communication module.
func Run(ctx context.Context, opts Options) *report.Module {
	m := report.NewModule("comms", "Communication reachability", report.KindCensorship)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	// Whoever forwards this machine's packets is whoever these results describe,
	// so establish that before measuring anything.
	path := netpath.Detect()
	pathName, tunneled := path.Describe(), path.Tunneled
	switch {
	case tunneled:
		m.Row("path", report.StatusInfo, "default route", pathName,
			"a tunnel owns the default route, so what is reachable here is the tunnel operator's "+
				"policy, not the network this machine is attached to")
	case pathName != "":
		m.Row("path", report.StatusOK, "default route", pathName,
			"no tunnel in the path, so these results describe the network itself")
	}

	// Nothing below is interpreted until an ordinary endpoint works. Without
	// that control, a machine that is simply offline reports every messenger in
	// the world as censored.
	ctrl := probe(ctx, control, timeout)
	if ctrl.V.blocked() && ctrl.V != vDNSPoisoned {
		m.Row("services", report.StatusSkip, "control", control.Addr(),
			ctrl.V.String()+" — "+ctrl.Detail)
		m.Fail("the control endpoint %s is unreachable, so nothing can be attributed to this network",
			control.Addr())
		m.SetLevel(0, "C?", "Inconclusive",
			"An ordinary, unfiltered endpoint could not be reached either, so there is no baseline to "+
				"compare the messaging services against. This machine may simply be offline.")
		return m
	}

	// A control that resolves into a blackhole means every name on this network
	// is being redirected, not just the messengers. Saying so once is honest;
	// saying it ten times would blame the messengers for it.
	proxiedDNS := ctrl.V == vDNSPoisoned
	if proxiedDNS {
		m.Row("services", report.StatusInfo, "control", control.Addr(),
			"even "+control.Host+" resolves to a local address, so DNS redirection here is "+
				"network-wide rather than aimed at any messenger — see the dns module")
	}

	results := runProbes(ctx, opts, timeout)
	media, mediaTested := runMedia(ctx, m, timeout)

	t := renderServices(m, results, proxiedDNS)
	t.MediaOK, t.MediaTested = media, mediaTested
	renderMethod(m, results, proxiedDNS)

	findings(m, results, t, tunneled, pathName, proxiedDNS)
	deriveLevel(m, t, tunneled)
	return m
}

// runProbes measures every endpoint of every service concurrently, and under
// --deep looks for an alternate port for the ones that failed.
func runProbes(ctx context.Context, opts Options, timeout time.Duration) [][]result {
	out := make([][]result, len(services))
	sem := make(chan struct{}, maxParallelProbes)
	var wg sync.WaitGroup

	for i := range services {
		out[i] = make([]result, len(services[i].Endpoints))
		for j := range services[i].Endpoints {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				svc := services[i]
				r := probe(ctx, svc.Endpoints[j], timeout)
				r.Svc = svc.Name
				if opts.Deep && r.V.blocked() && ctx.Err() == nil {
					r.Alt = probeAlt(ctx, svc.Endpoints[j], timeout)
				}
				out[i][j] = r
			}(i, j)
		}
	}
	wg.Wait()
	return out
}

// runMedia tests the path calls are negotiated over and reports whether any
// server answered. Two independent operators are tried, so one of them having a
// bad day is not reported as this network blocking voice calls.
func runMedia(ctx context.Context, m *report.Module, timeout time.Duration) (ok, tested bool) {
	errs := make([]error, len(mediaProbes))
	var wg sync.WaitGroup
	for i, p := range mediaProbes {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			errs[i] = stunReachable(ctx, addr, timeout)
		}(i, p.Addr)
	}
	wg.Wait()

	for i, p := range mediaProbes {
		if errs[i] == nil {
			ok = true
			m.Row("call media", report.StatusOK, p.Label, p.Addr,
				"the UDP path voice and video calls negotiate over is open")
			continue
		}
		m.Row("call media", report.StatusWarn, p.Label, p.Addr, compactErr(errs[i]))
	}
	return ok, true
}

// tally is the shape of the result set, kept separate from the results so the
// level and the findings reason about the same summary.
type tally struct {
	Total       int
	Reachable   int
	Partial     int
	Blocked     int
	Intercepted int

	E2EEBlocked  int
	E2EETotal    int
	PlainOpen    int
	SNIFiltered  int
	Poisoned     int
	ResetInject  int
	PortScoped   int
	BlockedNames []string

	MediaOK     bool
	MediaTested bool
}

// renderServices writes the per-service roll-up and summarises the run.
func renderServices(m *report.Module, results [][]result, proxiedDNS bool) tally {
	var t tally
	for i, svc := range services {
		rs := results[i]
		blocked, total := 0, len(rs)
		var reasons []string
		intercepted := false
		for _, r := range rs {
			if !r.V.blocked() {
				continue
			}
			// Network-wide DNS redirection is reported once, at the top; it is
			// not evidence that this particular service was targeted.
			if r.V == vDNSPoisoned && proxiedDNS {
				continue
			}
			blocked++
			if r.V == vIntercepted {
				intercepted = true
			}
			reasons = append(reasons, r.EP.Role+" "+r.V.String())
		}

		st, value, note := report.StatusOK,
			fmt.Sprintf("%d/%d endpoints reachable", total-blocked, total),
			svc.Note
		switch {
		case intercepted:
			st, note = report.StatusBad, "answered by something that is not "+svc.Name
			t.Intercepted++
		case blocked == total:
			st, note = report.StatusBad, strings.Join(reasons, "; ")
			t.Blocked++
			t.BlockedNames = append(t.BlockedNames, svc.Name)
		case blocked > 0:
			st, note = report.StatusWarn, strings.Join(reasons, "; ")
			t.Partial++
		default:
			t.Reachable++
			if note == "" {
				note = "all endpoints answered as themselves"
			}
		}
		m.Row("services", st, svc.Name, value, note)

		t.Total++
		if svc.E2EE {
			t.E2EETotal++
			if blocked > 0 || intercepted {
				t.E2EEBlocked++
			}
		} else if blocked == 0 && !intercepted {
			t.PlainOpen++
		}
	}

	for _, rs := range results {
		for _, r := range rs {
			switch r.V {
			case vSNIFiltered:
				t.SNIFiltered++
			case vDNSPoisoned:
				if !proxiedDNS {
					t.Poisoned++
				}
			case vReset:
				t.ResetInject++
			}
			if r.Alt != "" {
				t.PortScoped++
			}
		}
	}
	return t
}

// renderMethod writes the per-endpoint detail, but only for endpoints that
// failed. A table of everything that worked is noise; the interesting rows are
// the ones that say where a connection died.
func renderMethod(m *report.Module, results [][]result, proxiedDNS bool) {
	for _, rs := range results {
		for _, r := range rs {
			if !r.V.blocked() || (r.V == vDNSPoisoned && proxiedDNS) {
				continue
			}
			st := report.StatusWarn
			switch r.V {
			case vIntercepted, vSNIFiltered, vDNSPoisoned:
				st = report.StatusBad
			}
			note := r.Detail
			if r.Alt != "" {
				note += "; the same host answers on " + r.Alt + ", so the block follows the port"
			}
			m.Row("blocking method", st, r.Svc+" "+r.EP.Role, r.EP.Addr(), note)
		}
	}
}

// findings turns the measurements into things the operator can act on.
//
// Blocking findings are downgraded to informational when a tunnel owns the
// default route, for the reason the egress module gives: what was measured is
// then the tunnel operator's forwarding policy, and reporting it as this
// network's censorship blames the wrong party. Interception is never downgraded
// — a certificate that does not belong to Signal does not belong to Signal
// whoever is carrying the packets.
func findings(m *report.Module, results [][]result, t tally, tunneled bool, pathName string, proxiedDNS bool) {
	sev := func(network report.Severity) report.Severity {
		if tunneled {
			return report.SevInfo
		}
		return network
	}
	attribute := func(detail string) string {
		if !tunneled {
			return detail
		}
		return detail + " The default route belongs to " + pathName +
			", a tunnel, so this describes its forwarding policy rather than the network's. " +
			"Re-run without the tunnel to judge the network itself."
	}

	if t.Intercepted > 0 {
		var evidence []string
		for _, rs := range results {
			for _, r := range rs {
				if r.V == vIntercepted {
					evidence = append(evidence, r.Svc+" "+r.EP.Addr()+": issued by "+r.Issuer)
				}
			}
		}
		// Interception, not censorship: this module tripped over it while
		// establishing reachability, but a forged certificate is an attack on
		// what the conversation says, and it is scored and described as one.
		m.AddOfKind(report.KindInterception,
			"comms.intercepted", "A messaging service is answered by a certificate that is not its own",
			report.SevCritical,
			"An endpoint belonging to a messaging service completed a TLS handshake with a certificate "+
				"that is not the one it identifies itself with. Something on this path is terminating "+
				"conversations that were supposed to end at the service, which means it can read them. "+
				"Run `midwatch tls --targets <host>` for the full forensic breakdown of who.",
			evidence...)
	}

	if t.SNIFiltered > 0 {
		var evidence []string
		for _, rs := range results {
			for _, r := range rs {
				if r.V == vSNIFiltered {
					where := "the same address"
					if r.Dialed != "" {
						where = r.Dialed
					}
					evidence = append(evidence,
						r.Svc+" "+r.EP.Host+" — "+where+" accepts "+benignSNI)
				}
			}
		}
		m.Add("comms.sni-filtered", "Messaging hostnames are being filtered out of the TLS handshake",
			sev(report.SevHigh),
			attribute("A handshake to these services is destroyed only when their hostname appears in it. "+
				"The identical connection to the identical address succeeds under a different name, so "+
				"nothing about the route is broken: a device is reading the server name out of every "+
				"ClientHello that leaves this network and deciding, per name, whether to let it live. "+
				"That device sees which services every person here contacts."),
			evidence...)
	}

	if t.Poisoned > 0 && !proxiedDNS {
		var evidence []string
		for _, rs := range results {
			for _, r := range rs {
				if r.V == vDNSPoisoned {
					evidence = append(evidence, r.Svc+" "+r.EP.Host+" → "+r.Detail)
				}
			}
		}
		m.Add("comms.dns-poisoned", "Messaging hostnames are redirected in DNS", sev(report.SevHigh),
			attribute("Names belonging to messaging services resolve to addresses no public service can be "+
				"reached at, while ordinary names resolve correctly. The redirection is aimed at these "+
				"services specifically. Anything that trusts this network's resolver will connect to "+
				"whatever is at that address, or to nothing at all."),
			evidence...)
	}

	if t.ResetInject > 0 {
		var evidence []string
		for _, rs := range results {
			for _, r := range rs {
				if r.V == vReset {
					evidence = append(evidence, r.Svc+" "+r.EP.Addr()+": "+r.Detail)
				}
			}
		}
		m.Add("comms.reset-injected", "Connections to messaging services are being torn down mid-stream",
			sev(report.SevMedium),
			attribute("These connections were established and then reset rather than refused or dropped. A "+
				"server that does not want a connection refuses it at the start; a reset partway through "+
				"is characteristic of a device on the path injecting one after inspecting what the "+
				"connection was for."),
			evidence...)
	}

	// The shape of the blocking, not merely its extent. This is the finding
	// worth having: a set of blocks that lands exactly on the services with no
	// server-side copy of the messages is a decision about readability.
	if t.E2EEBlocked > 0 && t.E2EEBlocked == t.Blocked+t.Partial+t.Intercepted && t.PlainOpen > 0 {
		var e2ee, plain []string
		for i, svc := range services {
			open := true
			for _, r := range results[i] {
				if r.V.blocked() && !(r.V == vDNSPoisoned && proxiedDNS) {
					open = false
				}
			}
			switch {
			case svc.E2EE && !open:
				e2ee = append(e2ee, svc.Name)
			case !svc.E2EE && open:
				plain = append(plain, svc.Name)
			}
		}
		sort.Strings(e2ee)
		sort.Strings(plain)
		m.Add("comms.e2ee-blocked", "Only the end-to-end encrypted messengers are blocked",
			sev(report.SevHigh),
			attribute("Every messaging service blocked here encrypts its messages end to end, and every one "+
				"left working keeps a copy the operator can read. Filtering that lands precisely on that "+
				"line was not chosen for bandwidth or for distraction — it was chosen so that the "+
				"conversations that still happen are ones somebody else can obtain."),
			"blocked: "+strings.Join(e2ee, ", "),
			"still working: "+strings.Join(plain, ", "))
	} else if t.Blocked > 0 {
		names := append([]string(nil), t.BlockedNames...)
		sort.Strings(names)

		// Losing a messenger is not a uniform event. Losing one that encrypts
		// end to end takes away the channel people move to when a conversation
		// matters, and losing half of everything tested is not a bad day at one
		// vendor. Both are graded above an ordinary block.
		severity, because := report.SevMedium, ""
		switch {
		case t.E2EEBlocked > 0:
			severity = report.SevHigh
			because = " At least one of them encrypts messages end to end, which is the channel people " +
				"move to precisely when a conversation matters. Taking it away does not stop the " +
				"conversation; it moves it somewhere readable."
		case (t.Blocked+t.Partial)*2 >= t.Total:
			severity = report.SevHigh
			because = " That is half or more of every service tested, which is not one vendor having a " +
				"bad day."
		}

		m.Add("comms.blocked", listPhrase(names)+" cannot be reached on this network", sev(severity),
			attribute("These services could not be reached on any of their endpoints while an ordinary "+
				"control endpoint worked, so the failure belongs to this path rather than to them."+because),
			"blocked: "+strings.Join(names, ", "))
	}

	if t.MediaTested && !t.MediaOK {
		m.Add("comms.calls-blocked", "The direct path for voice and video calls is closed",
			sev(report.SevMedium),
			attribute("No STUN binding request completed, so the UDP path every one of these apps uses to "+
				"negotiate media is unavailable. Calls will either fail or be pushed onto a TCP relay run "+
				"by the vendor — slower, more fragile, and one more party positioned to see that the call "+
				"took place and between whom."))
	}

	if t.PortScoped > 0 {
		m.Add("comms.port-scoped-block", "Some blocking follows the port rather than the service",
			report.SevInfo,
			"Endpoints unreachable on their normal port answered on another one, so what is being "+
				"filtered there is the port number. A client configurable onto that port would still "+
				"connect.")
	}
}

// deriveLevel places the module on the 0-4 ladder.
func deriveLevel(m *report.Module, t tally, tunneled bool) {
	restricted := t.Blocked + t.Partial
	switch {
	case t.Intercepted > 0:
		m.SetLevel(4, "C4", "Communication intercepted",
			fmt.Sprintf("%d messaging %s answered by a certificate that does not belong to it. Messages "+
				"and calls arranged over these services are not ending where they were addressed.",
				t.Intercepted, plural(t.Intercepted, "service is", "services are")))

	case t.E2EEBlocked > 0 && t.E2EEBlocked == restricted+t.Intercepted && t.PlainOpen > 0:
		m.SetLevel(3, "C3", "Private messengers blocked",
			fmt.Sprintf("%d of %d end-to-end encrypted services are unreachable while %d services that "+
				"keep server-readable history work normally. The filtering follows confidentiality, not "+
				"traffic.", t.E2EEBlocked, t.E2EETotal, t.PlainOpen))

	// Losing private messaging is the serious case even when the blocking is
	// not shaped that neatly. It does not become a mild one because something
	// with server-readable history was blocked alongside it.
	case t.E2EEBlocked > 0:
		m.SetLevel(3, "C3", "Private messaging blocked",
			fmt.Sprintf("%d of %d end-to-end encrypted services are unreachable here. Whatever else this "+
				"network permits, the conversations people deliberately move somewhere private are not "+
				"among them.", t.E2EEBlocked, t.E2EETotal))

	case restricted*2 >= t.Total && restricted > 0:
		m.SetLevel(3, "C3", "Communication heavily restricted",
			fmt.Sprintf("%d of %d communication services are wholly or partly unreachable. Whatever is "+
				"left is the set somebody chose to leave you.", restricted, t.Total))

	case restricted > 0:
		m.SetLevel(2, "C2", "Selective blocking",
			fmt.Sprintf("%d of %d communication services are wholly or partly unreachable while the rest "+
				"work. %s", restricted, t.Total, tunnelNote(tunneled)))

	case t.MediaTested && !t.MediaOK:
		m.SetLevel(1, "C1", "Calls degraded",
			"Every messaging service is reachable, but the UDP path calls negotiate media over is not. "+
				"Text will work; voice and video will fall back to vendor relays or fail outright.")

	default:
		m.SetLevel(0, "C0", "Communication unrestricted",
			fmt.Sprintf("All %d communication services answered as themselves, and the media path calls "+
				"depend on is open. Nothing on this path is choosing who you may talk to.", t.Total))
	}
}

func tunnelNote(tunneled bool) string {
	if tunneled {
		return "A tunnel owns the default route, so this is its forwarding policy rather than the network's."
	}
	return "Something on this path is making that choice per service."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// listPhrase renders names as prose, so a finding title says *which* services
// are gone. "Signal and Telegram cannot be reached" is a sentence somebody can
// act on; "2 communication services are unreachable" is one they have to go
// looking for the meaning of.
func listPhrase(names []string) string {
	switch len(names) {
	case 0:
		return "No service"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	case 3:
		return names[0] + ", " + names[1] + " and " + names[2]
	default:
		return fmt.Sprintf("%s, %s and %d other %s", names[0], names[1],
			len(names)-2, plural(len(names)-2, "service", "services"))
	}
}
