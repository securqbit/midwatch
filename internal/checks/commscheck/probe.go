// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package commscheck

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// verdict is what happened to one endpoint, and — where the evidence supports
// it — where in the path it happened. The distinction is the whole value of
// this module: "Signal does not work here" is a complaint, "Signal is stopped
// by a device reading the hostname out of your handshake" is a finding.
type verdict int

const (
	vOK          verdict = iota // the endpoint answered as itself
	vDNSFail                    // the name does not resolve
	vDNSPoisoned                // the name resolves somewhere it cannot be
	vRefused                    // TCP actively refused
	vDropped                    // TCP silently dropped
	vReset                      // the connection was torn down mid-stream
	vSNIFiltered                // only the name is blocked; the address is not
	vIntercepted                // the endpoint answered, but not as itself
	vSkipped                    // the probe could not run
)

var verdictNames = map[verdict]string{
	vOK:          "reachable",
	vDNSFail:     "name does not resolve",
	vDNSPoisoned: "DNS redirected",
	vRefused:     "refused",
	vDropped:     "silently dropped",
	vReset:       "connection reset",
	vSNIFiltered: "blocked by hostname",
	vIntercepted: "certificate is not the service's own",
	vSkipped:     "not tested",
}

func (v verdict) String() string {
	if n, ok := verdictNames[v]; ok {
		return n
	}
	return "unknown"
}

// blocked reports whether this verdict means the endpoint is unusable.
func (v verdict) blocked() bool {
	switch v {
	case vOK, vSkipped:
		return false
	}
	return true
}

// result is one probed endpoint.
type result struct {
	Svc    string
	EP     endpoint
	V      verdict
	IPs    []net.IP
	Dialed string
	Detail string
	Issuer string
	Alt    string // an alternate port that worked, from --deep
}

// probe measures one endpoint end to end: resolution, then the TCP path, then
// — for endpoints that speak TLS — the handshake and the certificate behind it.
// Each stage only runs when the one before it succeeded, so the verdict names
// the first thing that actually stopped the connection rather than the last
// symptom of it.
func probe(ctx context.Context, ep endpoint, timeout time.Duration) result {
	r := result{EP: ep}

	ip := net.ParseIP(ep.Host)
	if ip == nil {
		ips, err := resolve(ctx, ep.Host, timeout)
		switch {
		case err != nil:
			r.V, r.Detail = vDNSFail, compactErr(err)
			return r
		case allBlackhole(ips):
			r.IPs = ips
			r.V = vDNSPoisoned
			r.Detail = "answered with " + ips[0].String() + ", where no public service can be"
			return r
		}
		r.IPs = ips
		ip = firstUsable(ips)
		if ip == nil {
			r.V, r.Detail = vDNSFail, "no usable address in the answer"
			return r
		}
	} else {
		r.IPs = []net.IP{ip}
	}
	r.Dialed = net.JoinHostPort(ip.String(), strconv.Itoa(ep.Port))

	conn, err := dial(ctx, r.Dialed, timeout)
	if err != nil {
		r.V, r.Detail = classifyDialErr(err), compactErr(err)
		return r
	}

	// Endpoints that do not speak TLS have told us everything they can: the
	// port is open and something is listening.
	if !ep.TLS {
		_ = conn.Close()
		r.V, r.Detail = vOK, "TCP connection established"
		return r
	}

	state, herr := handshake(ctx, conn, ep.Host, timeout)
	if herr == nil {
		var ok bool
		ok, r.Issuer = identify(state, ep)
		switch {
		case ok && ep.Issuer != "":
			r.V, r.Detail = vOK, "served the pinned certificate of "+ep.Issuer
		case ok:
			r.V, r.Detail = vOK, "publicly trusted, CT-logged certificate for "+ep.Host
		default:
			r.V = vIntercepted
			r.Detail = "certificate issued by " + r.Issuer + ", " + expectation(ep)
		}
		return r
	}

	// A TLS alert means the server itself replied. The path is intact and the
	// endpoint simply did not like the handshake, which is not a block.
	if isPeerAlert(herr) {
		r.V, r.Detail = vOK, "server answered with a TLS alert: "+compactErr(herr)
		return r
	}

	// The TCP connection was established and then died during the handshake.
	// That is where hostname filtering lives, so ask the same address for a
	// hostname nobody objects to. If that gets through, nothing about the
	// address was ever the problem — the name was.
	if reachesTLS(ctx, r.Dialed, benignSNI, timeout) {
		r.V = vSNIFiltered
		r.Detail = "the handshake dies only when " + ep.Host +
			" appears in it; the same address accepts " + benignSNI
		return r
	}
	r.V, r.Detail = classifyDialErr(herr), compactErr(herr)
	return r
}

// resolve asks the system resolver, because that is the one the apps
// themselves will use. A poisoned answer here is the answer they would get.
func resolve(ctx context.Context, host string, timeout time.Duration) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("empty answer")
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// handshake completes TLS on an already-open connection, so that a failure is
// unambiguously a handshake failure rather than a second dial that might have
// landed somewhere else.
func handshake(ctx context.Context, conn net.Conn, sni string, timeout time.Duration) (*tls.ConnectionState, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, &tls.Config{
		ServerName: sni,
		// The chain is the evidence, so it is captured and judged below rather
		// than discarded by a failed handshake.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer tc.Close()
	state := tc.ConnectionState()
	return &state, nil
}

// reachesTLS reports whether a handshake to addr under the given name got as
// far as a server. A completed handshake and a TLS alert both count: either
// way the bytes crossed the network and something on the far side answered in
// the protocol. Only silence or a reset means they did not.
func reachesTLS(ctx context.Context, addr, sni string, timeout time.Duration) bool {
	conn, err := dial(ctx, addr, timeout)
	if err != nil {
		return false
	}
	_, err = handshake(ctx, conn, sni, timeout)
	return err == nil || isPeerAlert(err)
}

// oidSCTList is the certificate extension carrying embedded Signed Certificate
// Timestamps (RFC 6962).
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// identify reports whether the endpoint proved it is itself, and names the
// issuer it presented either way.
//
// For an endpoint that pins its own authority, being itself means presenting
// that authority; nothing else is expected to hold, and nothing else is
// checked. For everything else it means looking like the public web PKI: a
// chain that validates for this hostname against the machine's trust store,
// carrying Certificate Transparency proofs. The proofs are the part an
// appliance cannot manufacture — SCTs are signed by public logs — which is why
// an installed corporate root does not quietly pass here.
//
// This is deliberately a yes-or-no test. Working out *who* is intercepting, and
// how deeply, is the tls module's job; all this module needs to know is whether
// the thing answering for Signal is Signal.
func identify(state *tls.ConnectionState, ep endpoint) (bool, string) {
	issuer := issuerOf(state)
	if state == nil || len(state.PeerCertificates) == 0 {
		return false, issuer
	}
	if ep.Issuer != "" {
		return strings.Contains(strings.ToLower(issuer), strings.ToLower(ep.Issuer)), issuer
	}

	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ep.Host, Intermediates: inter}); err != nil {
		return false, issuer
	}
	if len(state.SignedCertificateTimestamps) > 0 {
		return true, issuer
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidSCTList) {
			return true, issuer
		}
	}
	return false, issuer
}

// expectation renders what the endpoint should have presented, so a finding
// says what is wrong rather than only that something is.
func expectation(ep endpoint) string {
	if ep.Issuer != "" {
		return "but " + ep.Host + " pins " + ep.Issuer + " and presents nothing else"
	}
	return "which is not a publicly logged certificate for " + ep.Host
}

func issuerOf(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return "an unnamed issuer"
	}
	iss := state.PeerCertificates[0].Issuer
	switch {
	case iss.CommonName != "":
		return iss.CommonName
	case len(iss.Organization) > 0:
		return strings.Join(iss.Organization, ", ")
	default:
		return iss.String()
	}
}

// classifyDialErr names the way a connection failed. The three outcomes are not
// interchangeable: a refusal is a machine saying no, a reset mid-connection is
// a third party saying no on its behalf, and silence is a filter that would
// rather you blamed the service.
func classifyDialErr(err error) verdict {
	if err == nil {
		return vOK
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "reset"), strings.Contains(s, "broken pipe"),
		strings.Contains(s, "eof"):
		return vReset
	case strings.Contains(s, "refused"):
		return vRefused
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"),
		strings.Contains(s, "context canceled"):
		return vDropped
	case strings.Contains(s, "no route"), strings.Contains(s, "unreachable"):
		return vDropped
	}
	return vReset
}

// isPeerAlert reports whether the far side spoke TLS back to us. Go surfaces an
// alert sent by the peer with this prefix, and nothing else produces it.
func isPeerAlert(err error) bool {
	return err != nil && strings.Contains(err.Error(), "remote error: tls:")
}

// altPorts are tried under --deep for an endpoint that was blocked on its own
// port. Every one of these apps can be configured onto them, so an endpoint
// that answers here says the block follows the port rather than the service.
var altPorts = []int{80, 5222}

// probeAlt looks for a way through on another port and returns the first that
// works. It only runs for endpoints already found blocked.
func probeAlt(ctx context.Context, ep endpoint, timeout time.Duration) string {
	for _, p := range altPorts {
		if p == ep.Port {
			continue
		}
		alt := endpoint{Host: ep.Host, Port: p}
		if probe(ctx, alt, timeout).V == vOK {
			return alt.Addr()
		}
		if ctx.Err() != nil {
			break
		}
	}
	return ""
}

const stunMagicCookie = 0x2112A442

// stunReachable performs an RFC 5389 binding request and reports whether a
// well-formed success response came back.
//
// It stops at "did the exchange complete", without decoding the mapped address
// the egress module goes on to read. The question here is only whether the path
// voice and video calls negotiate over is open; the address on the far side of
// it belongs to a different report.
func stunReachable(ctx context.Context, server string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // binding request
	binary.BigEndian.PutUint16(req[2:4], 0)      // no attributes
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	return validSTUNSuccess(buf[:n], req[8:20])
}

// validSTUNSuccess checks that a reply is a binding success response for the
// transaction we opened, so that an unrelated datagram cannot be mistaken for
// an open media path.
func validSTUNSuccess(buf, txID []byte) error {
	if len(buf) < 20 {
		return errors.New("stun: short response")
	}
	if binary.BigEndian.Uint16(buf[0:2]) != 0x0101 {
		return fmt.Errorf("stun: reply type 0x%04x is not a binding success response",
			binary.BigEndian.Uint16(buf[0:2]))
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
		return errors.New("stun: bad magic cookie")
	}
	if string(buf[8:20]) != string(txID) {
		return errors.New("stun: transaction id mismatch")
	}
	return nil
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"):
		return "silently dropped (timeout)"
	case strings.Contains(s, "connection refused"):
		return "actively refused"
	case strings.Contains(s, "reset by peer"):
		return "connection reset"
	case strings.Contains(s, "no such host"):
		return "no such host"
	case strings.Contains(s, "no route"):
		return "no route to host"
	}
	for _, p := range []string{"tls: ", "x509: ", "remote error: "} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.LastIndex(s, ": "); i > 0 {
		s = s[i+2:]
	}
	if len(s) > 72 {
		s = s[:69] + "..."
	}
	return s
}
