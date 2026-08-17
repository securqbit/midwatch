// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tlscheck detects TLS interception and grades how deep it goes.
//
// The module opens real handshakes to a set of endpoints that are known to
// support TLS 1.3, HTTP/2 and Certificate Transparency, captures the chain the
// network actually delivered, and then reasons about it:
//
//   - does the chain validate against this machine's trust store?
//   - is it anchored in a root that belongs to the public web PKI?
//   - does the leaf carry Signed Certificate Timestamps, which only a public
//     CA can produce?
//   - do two unrelated hostnames share one public key, which only an
//     interceptor produces?
//   - was the protocol itself degraded (TLS 1.3 blocked, ALPN stripped,
//     legacy versions suddenly accepted)?
//
// Those signals separate "nobody is looking", "somebody is reading the
// envelope", and "somebody is opening the letter".
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/securqbit/midwatch/internal/report"
)

// DefaultTargets are large, stable endpoints that all support TLS 1.3, ALPN
// h2 and CT. Deviation from that baseline is a property of the path, not of
// the server.
var DefaultTargets = []string{
	"www.google.com:443",
	"cloudflare.com:443",
	"github.com:443",
	"www.mozilla.org:443",
	"en.wikipedia.org:443",
	"www.apple.com:443",
}

// maxParallelProbes bounds concurrent handshakes. The built-in target list is
// smaller than this, so it only ever constrains a user-supplied --targets list.
const maxParallelProbes = 16

// Options configures a TLS interception scan.
type Options struct {
	Targets []string
	Timeout time.Duration
	Deep    bool
}

type endpoint struct {
	Target string
	Host   string
	Err    error

	Version   uint16
	Cipher    uint16
	ALPN      string
	Leaf      *x509.Certificate
	Presented []*x509.Certificate

	VerifyErr    error
	RootSubject  string
	SelfSigned   bool
	NameMismatch bool

	SCTs       int
	OCSP       bool
	SPKI       string
	Issuer     string
	KeyDesc    string
	KeyWeak    bool
	SigWeak    bool
	CipherWeak string
	Lifetime   int

	Vendor      interceptor
	VendorHit   bool
	SuspectRoot bool // anchored outside the recognised public CA set

	ForcedDowngrade bool
	TLS13Blocked    bool
	ALPNStripped    bool
	LegacyAccepted  bool

	Intercepted bool
	Reasons     []string
}

// Run executes the TLS module and returns a finished report module.
func Run(ctx context.Context, opts Options) *report.Module {
	m := report.NewModule("tls", "TLS interception", report.KindInterception)

	targets := opts.Targets
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	// --targets is user supplied and may be long, so the fan-out is bounded.
	// Every probe opens up to three sockets, and a few hundred targets would
	// otherwise exhaust the file descriptor limit and be measured as a network
	// failure rather than a local one.
	eps := make([]*endpoint, len(targets))
	sem := make(chan struct{}, maxParallelProbes)
	var wg sync.WaitGroup

	// The downgrade probe runs alongside the main sweep rather than after it.
	// Protocol age alone proves nothing — several large providers still answer
	// TLS 1.0 for compatibility — so what matters is whether the *same
	// certificate* comes back. A different key on the downgraded connection
	// means a second responder took the call.
	legacyTarget := targets[0]
	var legacy legacyProbe
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		legacy = probeLegacy(ctx, legacyTarget, timeout)
	}()

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			eps[i] = probe(ctx, t, timeout)
		}(i, t)
	}
	wg.Wait()

	live := 0
	for _, ep := range eps {
		if ep != nil && ep.Err == nil {
			live++
			classify(ep)
		}
	}
	crossCheck(eps)

	renderEndpoints(m, eps)
	splitResponder := reportLegacy(m, legacy, eps[0], legacyTarget)

	if opts.Deep {
		deepProbes(ctx, m, targets[0], timeout)
	}

	if live == 0 {
		m.Fail("no endpoint completed a TLS handshake; results are inconclusive")
		m.SetLevel(0, "L?", "Inconclusive",
			"No TLS handshake completed. The network may be offline, or every probed endpoint is blocked.")
		return m
	}

	baseline := len(opts.Targets) == 0
	findings(m, eps, baseline)
	deriveLevel(m, eps, live, splitResponder, baseline)
	return m
}

// legacyProbe records what a deliberately downgraded handshake returned.
type legacyProbe struct {
	Attempted bool // this Go runtime could offer TLS 1.0 at all
	Accepted  bool
	SPKI      string
	Issuer    string
	Err       error

	// Verified and RootSubject describe the chain the downgraded connection
	// presented. They exist because a key that merely differs from the modern
	// one proves nothing: a large site mid-certificate-rotation serves several
	// valid leaves at once, so what separates rotation from a second responder
	// is whether the downgraded chain still validates for the hostname and
	// still anchors at the same root.
	Verified    bool
	RootSubject string
}

// reportLegacy interprets the downgrade probe and reports whether the
// downgraded connection was answered by a different party.
func reportLegacy(m *report.Module, l legacyProbe, primary *endpoint, target string) bool {
	if !l.Attempted {
		return false
	}
	if !l.Accepted {
		m.Row("downgrade", report.StatusOK, "TLS 1.0 handshake", "refused",
			target+" rejects obsolete protocol versions")
		return false
	}
	if primary == nil || primary.Leaf == nil {
		return false
	}
	if l.SPKI != primary.SPKI {
		// A different key is not by itself a second responder. Sites the size
		// of the built-in targets routinely serve two valid leaves from one
		// address while a certificate rotates, so two consecutive handshakes
		// legitimately disagree — including two modern ones. Accusing a network
		// of decrypting traffic on that evidence alone produces a critical
		// finding at random, which is worse than producing none: it teaches the
		// reader to disbelieve the tool.
		//
		// What an interceptor cannot fake is the anchor. If the downgraded chain
		// still validates for this hostname and still ends at the same root the
		// modern connection reached, both certificates belong to the same
		// operator and rotation is the explanation.
		sameOperator := l.Verified && primary.VerifyErr == nil &&
			l.RootSubject != "" && l.RootSubject == primary.RootSubject
		if sameOperator {
			m.Row("downgrade", report.StatusInfo, "TLS 1.0 handshake", "accepted, second valid certificate",
				"a different leaf that still validates for "+primary.Host+" and anchors at "+l.RootSubject+
					" — certificate rotation, not a second responder")
			return false
		}

		reason := "chain anchors at " + l.RootSubject + ", not " + primary.RootSubject
		if !l.Verified {
			reason = "chain does not validate for " + primary.Host
		}
		m.Row("downgrade", report.StatusBad, "TLS 1.0 handshake", "answered by a different key",
			"issuer "+l.Issuer+"; "+reason)
		m.Add("tls.downgrade-swap", "A downgraded handshake reaches a different server", report.SevCritical,
			"Asking for an obsolete protocol version returned a certificate that does not belong to the "+
				"origin: a different key, and a chain that does not lead back to the same trust anchor the "+
				"modern handshake reached. A device on this path is answering selectively, and it answers "+
				"the weakest request with the key it controls. Anything that falls back to older TLS on "+
				"this network is talking to it, not to the site.",
			fmt.Sprintf("modern: sha256:%s… (%s, anchored at %s)",
				shortFingerprint(primary.SPKI), primary.Issuer, primary.RootSubject),
			fmt.Sprintf("downgraded: sha256:%s… (%s, %s)",
				shortFingerprint(l.SPKI), l.Issuer, reason))
		return true
	}
	// Same key: the origin itself still supports TLS 1.0. That is a property
	// of the server, not of this network, and is reported as such.
	m.Row("downgrade", report.StatusInfo, "TLS 1.0 handshake", "accepted by the origin",
		"same certificate as the modern handshake — a server-side setting, not interception")
	return false
}

// probe performs the primary handshake and the follow-up protocol probes.
func probe(ctx context.Context, target string, timeout time.Duration) *endpoint {
	ep := &endpoint{Target: target}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		ep.Target = target + ":443"
	}
	ep.Host = host

	state, err := handshake(ctx, ep.Target, host, tls.VersionTLS12, tls.VersionTLS13,
		[]string{"h2", "http/1.1"}, timeout)
	if err != nil {
		// Distinguish "TLS 1.3 is being blocked outright" from "the endpoint
		// is unreachable" by retrying with 1.3 removed from the offer.
		if st2, err2 := handshake(ctx, ep.Target, host, tls.VersionTLS12, tls.VersionTLS12,
			[]string{"h2", "http/1.1"}, timeout); err2 == nil {
			ep.ForcedDowngrade = true
			ep.TLS13Blocked = true
			state = st2
		} else {
			ep.Err = err
			return ep
		}
	}

	ep.Version = state.Version
	ep.Cipher = state.CipherSuite
	ep.ALPN = state.NegotiatedProtocol
	ep.OCSP = len(state.OCSPResponse) > 0
	ep.Presented = state.PeerCertificates
	if len(state.PeerCertificates) == 0 {
		ep.Err = errors.New("server presented no certificate")
		return ep
	}
	ep.Leaf = state.PeerCertificates[0]
	ep.SCTs = countSCTs(ep.Leaf, state)
	ep.SPKI = spkiFingerprint(ep.Leaf)
	ep.Issuer = issuerName(ep.Leaf)
	ep.Lifetime = lifetimeDays(ep.Leaf)
	ep.KeyDesc, _, ep.KeyWeak = keyDescription(ep.Leaf)
	ep.SigWeak = weakSignature(ep.Leaf.SignatureAlgorithm)
	ep.NameMismatch = ep.Leaf.VerifyHostname(host) != nil
	ep.ALPNStripped = ep.ALPN != "h2"

	last := state.PeerCertificates[len(state.PeerCertificates)-1]
	ep.SelfSigned = last.Subject.String() == last.Issuer.String()
	ep.RootSubject = subjectName(last)

	// Validate against this machine's trust store, which is what a browser
	// would do. Success here does not mean the certificate is genuine: it
	// means the anchor is trusted locally, possibly because it was installed.
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	chains, verr := ep.Leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: inter,
	})
	ep.VerifyErr = verr
	if verr == nil && len(chains) > 0 {
		anchor := chains[0][len(chains[0])-1]
		ep.RootSubject = subjectName(anchor)
	}

	if v, ok := matchInterceptor(ep.Issuer, ep.RootSubject, subjectName(ep.Leaf)); ok {
		ep.Vendor, ep.VendorHit = v, true
	}

	// If 1.3 was not negotiated but was offered, confirm whether a 1.3-only
	// handshake is actively broken on this path.
	if ep.Version < tls.VersionTLS13 && !ep.TLS13Blocked {
		if _, err := handshake(ctx, ep.Target, host, tls.VersionTLS13, tls.VersionTLS13, nil, timeout); err != nil {
			ep.TLS13Blocked = true
		}
	}
	return ep
}

func handshake(ctx context.Context, addr, sni string, minVer, maxVer uint16, alpn []string, timeout time.Duration) (*tls.ConnectionState, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tc := tls.Client(conn, &tls.Config{
		ServerName: sni,
		// The presented chain is the evidence this module exists to collect,
		// so verification is performed explicitly afterwards rather than being
		// delegated to the handshake, which would discard it on failure.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         minVer,
		MaxVersion:         maxVer,
		NextProtos:         alpn,
	})
	if err := tc.HandshakeContext(dialCtx); err != nil {
		return nil, err
	}
	defer tc.Close()
	state := tc.ConnectionState()
	return &state, nil
}

// probeLegacy forces a TLS 1.0 handshake and captures whatever answers it.
func probeLegacy(ctx context.Context, target string, timeout time.Duration) legacyProbe {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		target += ":443"
	}
	st, err := handshake(ctx, target, host, tls.VersionTLS10, tls.VersionTLS10, nil, timeout)
	if err != nil {
		// Some builds refuse to offer TLS 1.0 at all; that is a local limit,
		// not a measurement of the network.
		if strings.Contains(err.Error(), "no supported versions") ||
			strings.Contains(err.Error(), "unsupported") {
			return legacyProbe{Attempted: false, Err: err}
		}
		return legacyProbe{Attempted: true, Accepted: false, Err: err}
	}
	l := legacyProbe{Attempted: true, Accepted: true}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		l.SPKI = spkiFingerprint(leaf)
		l.Issuer = issuerName(leaf)

		inter := x509.NewCertPool()
		for _, c := range st.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		chains, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
		l.Verified = verr == nil
		last := st.PeerCertificates[len(st.PeerCertificates)-1]
		l.RootSubject = subjectName(last)
		if verr == nil && len(chains) > 0 {
			l.RootSubject = subjectName(chains[0][len(chains[0])-1])
		}
	}
	return l
}

// classify decides whether one endpoint shows interception, and why.
func classify(ep *endpoint) {
	if ep.Leaf == nil {
		return
	}
	add := func(r string) { ep.Reasons = append(ep.Reasons, r) }

	if ep.VerifyErr != nil {
		add("chain does not validate: " + compactErr(ep.VerifyErr))
		ep.Intercepted = true
	}
	if ep.NameMismatch {
		add("certificate is not valid for " + ep.Host)
		ep.Intercepted = true
	}
	if ep.VendorHit {
		add(fmt.Sprintf("issuer identifies %s (%s interception)", ep.Vendor.vendor, ep.Vendor.kind))
		ep.Intercepted = true
	}
	if ep.SCTs == 0 {
		add("no Certificate Transparency SCTs — not issued by a public CA")
		ep.Intercepted = true
	}
	// An unrecognised root is corroborating evidence, never proof on its own.
	// The list of public CAs cannot be exhaustive, and wrongly accusing a
	// clean network of decrypting traffic is a worse failure than missing a
	// signal that Certificate Transparency already catches: a genuinely
	// forged certificate cannot carry SCTs, so it is flagged above regardless.
	if !isPublicCA(ep.RootSubject) {
		ep.SuspectRoot = true
		if ep.Intercepted {
			add("anchored in a non-public root: " + ep.RootSubject)
		}
	}
	if ep.SelfSigned && len(ep.Presented) == 1 {
		add("server presented a single self-signed certificate")
		ep.Intercepted = true
	}
	if ep.KeyWeak {
		add("weak public key: " + ep.KeyDesc)
	}
	if ep.SigWeak {
		add("weak signature algorithm: " + ep.Leaf.SignatureAlgorithm.String())
	}
	if reason, ok := weakCiphers[ep.Cipher]; ok {
		ep.CipherWeak = reason
		add("obsolete cipher suite negotiated: " + reason)
	}
	if ep.Lifetime > 398 && ep.Intercepted {
		add(fmt.Sprintf("certificate lifetime of %d days exceeds the public CA maximum", ep.Lifetime))
	}
}

// crossCheck looks for evidence that only becomes visible when endpoints are
// compared with one another.
func crossCheck(eps []*endpoint) {
	bySPKI := map[string][]string{}
	for _, ep := range eps {
		if ep == nil || ep.Leaf == nil {
			continue
		}
		bySPKI[ep.SPKI] = append(bySPKI[ep.SPKI], ep.Host)
	}
	for spki, hosts := range bySPKI {
		if len(hosts) < 2 {
			continue
		}
		for _, ep := range eps {
			if ep != nil && ep.SPKI == spki {
				ep.Intercepted = true
				ep.Reasons = append(ep.Reasons,
					"shares one public key with "+strings.Join(otherThan(hosts, ep.Host), ", "))
			}
		}
	}
}

func otherThan(all []string, self string) []string {
	var out []string
	for _, h := range all {
		if h != self {
			out = append(out, h)
		}
	}
	return out
}

func renderEndpoints(m *report.Module, eps []*endpoint) {
	for _, ep := range eps {
		if ep == nil {
			continue
		}
		if ep.Err != nil {
			m.Row("endpoints", report.StatusSkip, ep.Target, "unreachable", compactErr(ep.Err))
			continue
		}
		st := report.StatusOK
		note := ep.Issuer
		switch {
		case ep.Intercepted:
			st = report.StatusBad
		case ep.SuspectRoot:
			// CT proofs are present, so the certificate is genuine; the anchor
			// is simply one midwatch does not know by name.
			st = report.StatusWarn
			note = ep.Issuer + " — root not in the recognised public CA list"
		case ep.TLS13Blocked || ep.ALPNStripped:
			st = report.StatusWarn
		}
		alpn := ep.ALPN
		if alpn == "" {
			alpn = "no-alpn"
		}
		ct := fmt.Sprintf("ct:%d", ep.SCTs)
		value := fmt.Sprintf("%s %s %s %s", tlsVersionName(ep.Version), alpn, ep.KeyDesc, ct)
		m.Row("endpoints", st, ep.Target, value, note)
	}
}

func findings(m *report.Module, eps []*endpoint, baseline bool) {
	var intercepted, clean []*endpoint
	for _, ep := range eps {
		if ep == nil || ep.Err != nil {
			continue
		}
		if ep.Intercepted {
			intercepted = append(intercepted, ep)
		} else {
			clean = append(clean, ep)
		}
	}

	if len(intercepted) > 0 {
		// Group by the root doing the intercepting so the operator learns who
		// is responsible, not just that something happened.
		roots := map[string][]*endpoint{}
		for _, ep := range intercepted {
			roots[ep.RootSubject] = append(roots[ep.RootSubject], ep)
		}
		for root, group := range roots {
			var hosts, evidence []string
			for _, ep := range group {
				hosts = append(hosts, ep.Host)
			}
			sort.Strings(hosts)
			lead := group[0]
			for _, r := range lead.Reasons {
				evidence = append(evidence, r)
			}
			evidence = append(evidence,
				fmt.Sprintf("leaf SPKI sha256:%s…", shortFingerprint(lead.SPKI)),
				fmt.Sprintf("leaf validity %d days, %s", lead.Lifetime, expiresIn(lead.Leaf)),
				"affected: "+strings.Join(hosts, ", "))

			sev := report.SevHigh
			title := "TLS traffic is being decrypted and re-signed"
			detail := fmt.Sprintf(
				"Certificates for %d endpoint(s) were minted by %q rather than served by the real site. "+
					"Whoever controls that key sees the full plaintext of these connections, including "+
					"credentials, cookies and request bodies.", len(group), root)
			if lead.VerifyErr != nil || lead.NameMismatch {
				sev = report.SevCritical
				title = "TLS is being intercepted by an untrusted party"
				detail += " The chain does not even validate against your trust store, so this is not a " +
					"managed corporate deployment — treat this network as hostile."
			} else if lead.VendorHit {
				detail += fmt.Sprintf(" The issuer identifies %s.", lead.Vendor.vendor)
			}
			m.Add("tls.intercepted", title, sev, detail, evidence...)
		}

		if len(clean) > 0 {
			var bypass []string
			for _, ep := range clean {
				bypass = append(bypass, ep.Host)
			}
			sort.Strings(bypass)
			m.Add("tls.selective", "Interception is selective, not universal", report.SevMedium,
				"Some endpoints are decrypted while others pass through untouched. That is the signature of "+
					"a policy-driven inspection product with a bypass list, and it means the set of sites being "+
					"read is a decision somebody made, not a property of the network.",
				"passed through: "+strings.Join(bypass, ", "))
		}
	}

	var blocked13, stripped []string
	for _, ep := range eps {
		if ep == nil || ep.Err != nil || !baseline {
			continue
		}
		if ep.TLS13Blocked {
			blocked13 = append(blocked13, ep.Host)
		}
		if ep.ALPNStripped && !ep.Intercepted {
			stripped = append(stripped, ep.Host)
		}
	}
	if len(blocked13) > 0 {
		m.Add("tls.tls13-blocked", "TLS 1.3 is being blocked or downgraded", report.SevMedium,
			"These endpoints support TLS 1.3, but the handshake settled on an older version on this path. "+
				"A middlebox that forces TLS 1.2 is doing so because 1.3 encrypts the certificate exchange "+
				"and denies it visibility — it wants to keep watching.",
			"affected: "+strings.Join(blocked13, ", "))
	}
	if len(stripped) > 0 {
		m.Add("tls.alpn-stripped", "ALPN negotiation is being rewritten", report.SevLow,
			"HTTP/2 was offered but not negotiated on endpoints that support it, which means something on "+
				"the path is editing the handshake rather than forwarding it verbatim.",
			"affected: "+strings.Join(stripped, ", "))
	}

	for _, ep := range eps {
		if ep == nil || ep.Err != nil || !ep.Intercepted {
			continue
		}
		if ep.KeyWeak || ep.SigWeak || ep.CipherWeak != "" {
			evidence := fmt.Sprintf("%s: %s, %s", ep.Host, ep.KeyDesc, ep.Leaf.SignatureAlgorithm)
			if ep.CipherWeak != "" {
				evidence += ", " + ep.CipherWeak
			}
			m.Add("tls.weak-crypto", "The interceptor uses weak cryptography", report.SevHigh,
				"The device terminating your TLS connections uses primitives that are no longer considered "+
					"safe, so it is not merely reading your traffic, it is degrading its protection.",
				evidence)
			break
		}
	}

	seen := map[string]bool{}
	for _, ep := range eps {
		if ep == nil || ep.Leaf == nil {
			continue
		}
		if seen[ep.SPKI] {
			m.Add("tls.shared-key", "One key is being reused across unrelated sites", report.SevCritical,
				"Two different hostnames presented the same public key. No legitimate pair of unrelated "+
					"sites shares a private key, so a single device is impersonating both — and if that one "+
					"key leaks, every connection it has ever touched is retroactively readable.",
				fmt.Sprintf("shared SPKI sha256:%s…", shortFingerprint(ep.SPKI)))
			break
		}
		seen[ep.SPKI] = true
	}
}

// deriveLevel places the module on the interception ladder. Protocol
// degradation signals only count for the built-in endpoints, whose support for
// TLS 1.3 and HTTP/2 is a known constant; a user-supplied target that simply
// lacks them must not be read as evidence of a middlebox.
func deriveLevel(m *report.Module, eps []*endpoint, live int, splitResponder, baseline bool) {
	var intercepted, untrusted, metadata int
	for _, ep := range eps {
		if ep == nil || ep.Err != nil {
			continue
		}
		if ep.Intercepted {
			intercepted++
			if ep.VerifyErr != nil || ep.NameMismatch || ep.KeyWeak || ep.SigWeak ||
				ep.CipherWeak != "" || ep.Version < tls.VersionTLS12 {
				untrusted++
			}
		}
		if baseline && (ep.TLS13Blocked || ep.ALPNStripped) {
			metadata++
		}
	}

	sharedKey := false
	seen := map[string]bool{}
	for _, ep := range eps {
		if ep == nil || ep.Leaf == nil {
			continue
		}
		if seen[ep.SPKI] {
			sharedKey = true
		}
		seen[ep.SPKI] = true
	}

	switch {
	case untrusted > 0 || sharedKey || splitResponder:
		detail := fmt.Sprintf("%d of %d endpoints are affected.", intercepted, live)
		if intercepted == 0 && splitResponder {
			detail = "A downgraded handshake was answered by a key that does not belong to the origin."
		}
		m.SetLevel(4, "L4", "Untrusted interception",
			"Traffic is being decrypted by a party your system does not properly trust, or the "+
				"interceptor weakens the connection it terminates. "+detail+
				" Do not send credentials over this network.")
	case intercepted >= live:
		m.SetLevel(3, "L3", "Full decryption via an installed root",
			fmt.Sprintf("All %d %s were re-signed by a certificate authority that is trusted by this "+
				"machine but is not part of the public web PKI. Someone installed a root here and is reading "+
				"every TLS session in cleartext.", live, plural(live, "endpoint")))
	case intercepted > 0:
		m.SetLevel(2, "L2", "Selective decryption",
			fmt.Sprintf("%d of %d endpoints are decrypted and re-signed while the rest pass through. "+
				"An inspection policy is choosing which of your traffic to open.", intercepted, live))
	case metadata > 0:
		m.SetLevel(1, "L1", "Metadata visibility",
			fmt.Sprintf("No certificate was forged, so payloads are still confidential, but the handshake is "+
				"being manipulated on %d of %d endpoints. Something on this path is reading which sites you "+
				"visit and constraining how you may connect to them.", metadata, live))
	default:
		m.SetLevel(0, "L0", "No interception detected",
			fmt.Sprintf("All %d %s served publicly trusted, CT-logged certificates over a modern "+
				"negotiated protocol. Nothing on this path is opening or reshaping your TLS sessions.",
				live, plural(live, "endpoint")))
	}
}

// deepProbes runs optional, noisier checks.
func deepProbes(ctx context.Context, m *report.Module, target string, timeout time.Duration) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		target += ":443"
	}

	// A handshake with no SNI: middleboxes that route on SNI often cannot
	// cope, while the real endpoint answers with a default certificate.
	if _, err := handshake(ctx, target, "", tls.VersionTLS12, tls.VersionTLS13, nil, timeout); err != nil {
		m.Row("deep", report.StatusWarn, "SNI-less handshake", "failed", compactErr(err))
		m.Add("tls.sni-required", "Connections without SNI are rejected", report.SevLow,
			"A handshake that omitted the server name failed while the same endpoint accepts one with it. "+
				"That is characteristic of a device routing or filtering on the hostname you request.")
	} else {
		m.Row("deep", report.StatusOK, "SNI-less handshake", "accepted", "no hostname-based gating observed")
	}

	// Non-TLS bytes on 443: a protocol-aware filter usually kills the
	// connection instead of letting the server reject it.
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		m.Row("deep", report.StatusSkip, "non-TLS on 443", "unreachable", compactErr(err))
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")); err != nil {
		m.Row("deep", report.StatusWarn, "non-TLS on 443", "write failed", compactErr(err))
		return
	}
	buf := make([]byte, 256)
	n, rerr := conn.Read(buf)
	switch {
	case rerr != nil && strings.Contains(rerr.Error(), "reset"):
		m.Row("deep", report.StatusWarn, "non-TLS on 443", "connection reset",
			"port 443 is protocol-policed, not just forwarded")
	case n > 0:
		m.Row("deep", report.StatusInfo, "non-TLS on 443", fmt.Sprintf("%d bytes returned", n),
			strings.TrimSpace(firstLine(string(buf[:n]))))
	default:
		m.Row("deep", report.StatusOK, "non-TLS on 443", "no response", "server ignored plaintext, as expected")
	}
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 60 {
		return s[:60]
	}
	return s
}

// plural renders a count-appropriate noun so summaries read as sentences.
func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Strip the dial prefix noise so tables stay readable.
	for _, p := range []string{"tls: ", "x509: ", "dial tcp: ", "remote error: "} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.Index(s, ": connect:"); i > 0 {
		s = s[i+2:]
	}
	if len(s) > 96 {
		s = s[:93] + "..."
	}
	return s
}
