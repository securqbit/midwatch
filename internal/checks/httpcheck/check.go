// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package httpcheck inspects the HTTP path for transparent proxies, captive
// portals and downgrade attacks.
//
// Two ideas carry most of the weight here. The first is that unauthenticated
// HTTP is where interception is cheapest, so a network that tampers at all
// usually tampers here first — a rewritten body, an injected header, a
// redirect that never came from the server. The second is that Cloudflare's
// trace endpoint reports back what the far end actually saw: the TLS version,
// the HTTP version and your apparent address. Comparing that against what the
// local end of the very same connection negotiated catches a proxy that
// re-terminates the connection even when its certificate looks perfect.
package httpcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/securqbit/midwatch/internal/report"
)

// Options configures the HTTP path scan.
type Options struct {
	Timeout time.Duration
	Deep    bool
}

// captiveProbe is an endpoint with a precisely known, boring response. Any
// deviation means something answered instead of the origin.
type captiveProbe struct {
	Name       string
	URL        string
	WantStatus int
	WantBody   string // substring; empty means an empty body is expected
}

var captiveProbes = []captiveProbe{
	{"Google generate_204", "http://connectivitycheck.gstatic.com/generate_204", 204, ""},
	{"Apple hotspot detect", "http://captive.apple.com/hotspot-detect.html", 200, "Success"},
	{"Microsoft connect test", "http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"},
}

// proxyHeaders are response headers that only an intermediary inserts.
var proxyHeaders = []string{
	"Via", "X-Cache", "X-Cache-Lookup", "Proxy-Connection", "X-Proxy-ID",
	"X-Forwarded-For", "X-BlueCoat-Via", "X-Squid-Error", "X-Iinfo",
	"X-Sinkhole", "X-Zscaler", "X-Netskope",
}

// Run executes the HTTP module.
func Run(ctx context.Context, opts Options) *report.Module {
	m := report.NewModule("http", "HTTP path integrity", report.KindInterception)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	client := newClient(timeout)

	reportProxyEnv(m)
	portal := checkCaptivePortals(ctx, m, client)
	mismatch := checkEdgeView(ctx, m, client)
	injected := checkProxyHeaders(ctx, m, client)
	stripped := checkHSTS(ctx, m, client)

	deriveLevel(m, portal, mismatch, injected, stripped)
	return m
}

// newClient deliberately ignores proxy environment variables and does not
// follow redirects: both would hide exactly what this module is looking for.
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// reportProxyEnv surfaces a local proxy configuration, which is not an attack
// but does explain results and is worth stating plainly.
func reportProxyEnv(m *report.Module) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"} {
		if v := os.Getenv(key); v != "" {
			m.Row("local configuration", report.StatusWarn, key, v,
				"this shell routes traffic through a proxy; midwatch bypasses it and tests the network directly")
		}
	}
}

func checkCaptivePortals(ctx context.Context, m *report.Module, client *http.Client) bool {
	portal := false
	for _, p := range captiveProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "midwatch")
		resp, err := client.Do(req)
		if err != nil {
			m.Row("captive portal", report.StatusSkip, p.Name, "unreachable", compactErr(err))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		switch {
		case resp.StatusCode == p.WantStatus && (p.WantBody == "" || strings.Contains(string(body), p.WantBody)):
			m.Row("captive portal", report.StatusOK, p.Name,
				fmt.Sprintf("%d as expected", resp.StatusCode), "")
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			portal = true
			m.Row("captive portal", report.StatusBad, p.Name,
				fmt.Sprintf("%d redirect", resp.StatusCode), "to "+resp.Header.Get("Location"))
		default:
			portal = true
			m.Row("captive portal", report.StatusBad, p.Name,
				fmt.Sprintf("%d, %d bytes", resp.StatusCode, len(body)),
				"expected a fixed response, received substituted content")
		}
	}
	if portal {
		m.Add("http.portal", "Plain HTTP responses are being substituted", report.SevHigh,
			"Endpoints that exist purely to return one fixed, boring answer returned something else. "+
				"A device on this network is answering HTTP requests on behalf of the sites you asked for. "+
				"That is usually a captive portal or a filtering proxy, and either way your unencrypted "+
				"traffic is not reaching its destination unaltered.")
	}
	return portal
}

// checkEdgeView compares the connection this machine negotiated with what the
// far end reports receiving. A proxy that re-terminates TLS cannot keep both
// stories consistent.
//
// Both halves of the comparison must come from the *same* response, and the
// code below takes them from resp.TLS and resp.Proto for exactly that reason.
// Two independent connections to the same host are entitled to disagree — a
// different edge server, a resumed session, an HTTP/1.1 fallback on one and
// not the other — so comparing across connections would report interception on
// a healthy network. The claim this check makes is that a single connection
// contradicts itself, which is only evidence if it really is a single
// connection.
func checkEdgeView(ctx context.Context, m *report.Module, client *http.Client) bool {
	const traceURL = "https://cloudflare.com/cdn-cgi/trace"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "midwatch")
	resp, err := client.Do(req)
	if err != nil {
		m.Row("far-end view", report.StatusSkip, "edge trace", "unreachable", compactErr(err))
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.Row("far-end view", report.StatusWarn, "edge trace",
			fmt.Sprintf("HTTP %d", resp.StatusCode),
			"the trace endpoint did not answer normally; no comparison is possible")
		return false
	}

	trace := parseTrace(string(body))
	if len(trace) == 0 {
		m.Row("far-end view", report.StatusWarn, "edge trace", "unparseable",
			"the response did not come from the expected endpoint")
		return false
	}

	if ip := trace["ip"]; ip != "" {
		note := "the address the internet sees for you"
		if loc := trace["loc"]; loc != "" {
			note = "egress location " + loc
		}
		m.Row("far-end view", report.StatusInfo, "public address", ip, note)
	}
	if warp := trace["warp"]; warp != "" && warp != "off" {
		m.Row("far-end view", report.StatusInfo, "warp", warp, "Cloudflare WARP is active on this host")
	}
	if sni := trace["sni"]; sni != "" {
		st := report.StatusInfo
		note := "the hostname you request is visible on the wire"
		if sni == "encrypted" {
			st, note = report.StatusOK, "Encrypted Client Hello in use"
		}
		m.Row("far-end view", st, "server name", sni, note)
	}

	// What did *this* connection negotiate? resp.TLS and resp.Proto describe
	// the very connection whose far end wrote the trace body above, so any
	// disagreement between them is genuinely a connection contradicting itself.
	if resp.TLS == nil {
		return false
	}
	localVersion := tlsVersionName(resp.TLS.Version)
	localALPN := resp.TLS.NegotiatedProtocol
	if localALPN == "" {
		// Go reports no ALPN for HTTP/1.1 without it; fall back to the
		// protocol the response itself was framed in.
		localALPN = map[string]string{"HTTP/2.0": "h2", "HTTP/1.1": "http/1.1"}[resp.Proto]
	}
	edgeTLS := trace["tls"]
	edgeHTTP := trace["http"]

	mismatch := false
	if edgeTLS != "" {
		if normalizeTLS(edgeTLS) == normalizeTLS(localVersion) {
			m.Row("far-end view", report.StatusOK, "tls version", edgeTLS,
				"matches what this machine negotiated")
		} else {
			mismatch = true
			m.Row("far-end view", report.StatusBad, "tls version",
				fmt.Sprintf("edge saw %s, we negotiated %s", edgeTLS, localVersion),
				"the connection was terminated and remade in between")
		}
	}
	if edgeHTTP != "" && localALPN != "" {
		want := map[string]string{"h2": "HTTP/2", "http/1.1": "HTTP/1.1", "h3": "HTTP/3"}[localALPN]
		if want != "" && !strings.EqualFold(edgeHTTP, want) {
			mismatch = true
			m.Row("far-end view", report.StatusBad, "http version",
				fmt.Sprintf("edge saw %s, we negotiated %s", edgeHTTP, want),
				"protocol was rewritten in transit")
		} else {
			m.Row("far-end view", report.StatusOK, "http version", edgeHTTP, "consistent end to end")
		}
	}

	if mismatch {
		m.Add("http.split-tls", "Your TLS session ends before it reaches the site", report.SevCritical,
			"The far end reports a different protocol than the one this machine negotiated. A single "+
				"unbroken TLS connection cannot disagree with itself about its own version, so there are "+
				"two connections: yours to a middlebox, and the middlebox's to the site. Everything you "+
				"send is in cleartext at the join.",
			fmt.Sprintf("local: %s/%s, far end: %s/%s", localVersion, localALPN, edgeTLS, edgeHTTP))
	}
	return mismatch
}

func checkProxyHeaders(ctx context.Context, m *report.Module, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "midwatch")
	resp, err := client.Do(req)
	if err != nil {
		m.Row("intermediaries", report.StatusSkip, "plain HTTP fetch", "unreachable", compactErr(err))
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))

	found := false
	for _, h := range proxyHeaders {
		if v := resp.Header.Get(h); v != "" {
			found = true
			m.Row("intermediaries", report.StatusWarn, h, v, "inserted by a device on the path")
		}
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		m.Row("intermediaries", report.StatusInfo, "Server", srv, "as reported for example.com")
	}
	if !found {
		m.Row("intermediaries", report.StatusOK, "proxy headers", "none",
			"no intermediary announced itself")
		return false
	}
	m.Add("http.proxy-headers", "A transparent HTTP proxy is on the path", report.SevMedium,
		"The response carried headers that only a forwarding intermediary adds. Your plain HTTP requests "+
			"are being relayed through equipment that can read and modify them, and which is keeping its "+
			"own record of where you go.")
	return true
}

// checkHSTS looks for a stripped upgrade: a preloaded host that answers plain
// HTTP with content instead of a redirect means somebody is serving it locally.
func checkHSTS(ctx context.Context, m *report.Module, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://github.com/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "midwatch")
	resp, err := client.Do(req)
	if err != nil {
		m.Row("downgrade", report.StatusSkip, "http upgrade", "unreachable", compactErr(err))
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	loc := resp.Header.Get("Location")
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(loc, "https://"):
		m.Row("downgrade", report.StatusOK, "http upgrade", fmt.Sprintf("%d → %s", resp.StatusCode, loc),
			"plain HTTP is redirected to TLS as expected")
		return false
	case resp.StatusCode == 200 && len(body) > 0:
		m.Row("downgrade", report.StatusBad, "http upgrade", "200 with content",
			"an HSTS-preloaded host served plaintext content")
		m.Add("http.ssl-strip", "A site that must redirect to HTTPS served plaintext", report.SevHigh,
			"github.com is on the HSTS preload list and always redirects plain HTTP to TLS. Receiving "+
				"content over plain HTTP instead means the response was manufactured locally. This is the "+
				"mechanism behind SSL stripping: you believe you reached the site, but the encrypted leg "+
				"never happened.")
		return true
	default:
		m.Row("downgrade", report.StatusInfo, "http upgrade",
			fmt.Sprintf("%d", resp.StatusCode), loc)
		return false
	}
}

func deriveLevel(m *report.Module, portal, mismatch, injected, stripped bool) {
	switch {
	case mismatch || stripped:
		m.SetLevel(3, "H3", "Content interception",
			"Traffic is being terminated and reissued on this path. What arrives at your machine is not "+
				"what the site sent, and what the site receives is not what you sent.")
	case portal:
		m.SetLevel(2, "H2", "Response substitution",
			"Plain HTTP requests are answered locally instead of being forwarded. Unencrypted traffic "+
				"does not leave this network intact.")
	case injected:
		m.SetLevel(1, "H1", "Transparent proxying",
			"Your HTTP requests are relayed through an intermediary that announces itself. Content is "+
				"reaching you, but a third party is reading and recording the exchange.")
	default:
		m.SetLevel(0, "H0", "No HTTP tampering detected",
			"Fixed-response endpoints returned exactly what they should, no intermediary inserted itself, "+
				"and the far end agrees with this machine about the connection between them.")
	}
}

// tlsVersionName renders a negotiated version the way the trace endpoint does,
// so the two sides of the comparison are directly comparable.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// parseTrace reads the key=value body served by /cdn-cgi/trace.
func parseTrace(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k != "" {
			out[k] = v
		}
	}
	// A body without these keys did not come from the trace endpoint.
	if _, ok := out["ip"]; !ok {
		return nil
	}
	return out
}

func normalizeTLS(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "tlsv", "")
	s = strings.ReplaceAll(s, "tls", "")
	return strings.TrimSpace(s)
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.Index(s, ": "); i > 0 && strings.Contains(s[:i], "http") {
		s = s[i+2:]
	}
	if len(s) > 88 {
		s = s[:85] + "..."
	}
	return s
}
