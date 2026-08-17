// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package egresscheck maps what this network will actually let out.
//
// Interception and filtering are two faces of the same policy. A network that
// permits only ports 80 and 443 is forcing every protocol through the two it
// can inspect; one that blocks 853 and 443/UDP is specifically closing the
// escape hatches that would deny it visibility. This module measures the
// shape of that policy rather than guessing at it, including a real STUN
// exchange to establish whether UDP leaves at all.
package egresscheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/securqbit/midwatch/internal/netpath"
	"github.com/securqbit/midwatch/internal/report"
)

// Options configures the egress scan.
type Options struct {
	Timeout time.Duration
	Deep    bool
}

type port struct {
	Label    string
	Addr     string
	Protocol string
	Privacy  bool // blocking this specifically removes a private option
}

var tcpPorts = []port{
	{"HTTP", "example.com:80", "tcp", false},
	{"HTTPS", "example.com:443", "tcp", false},
	{"SSH", "github.com:22", "tcp", false},
	{"SMTP", "smtp.gmail.com:25", "tcp", false},
	{"SMTP submission", "smtp.gmail.com:587", "tcp", false},
	{"IMAPS", "imap.gmail.com:993", "tcp", false},
	{"DNS over TCP", "1.1.1.1:53", "tcp", false},
	{"DNS over TLS", "1.1.1.1:853", "tcp", true},
	{"NTS key exchange", "time.cloudflare.com:4460", "tcp", true},
}

// Run executes the egress module.
func Run(ctx context.Context, opts Options) *report.Module {
	m := report.NewModule("egress", "Egress policy", report.KindPosture)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Establish who owns the path before measuring it. Everything below
	// describes whatever forwards this machine's packets, and when that is a
	// VPN rather than the local network the report has to say so.
	path := netpath.Detect()
	pathName, tunneled := path.Describe(), path.Tunneled
	if tunneled {
		m.Row("path", report.StatusInfo, "default route", pathName,
			"a tunnel owns the default route, so these results describe the tunnel's policy, "+
				"not the network this machine is attached to")
	} else if pathName != "" {
		m.Row("path", report.StatusOK, "default route", pathName,
			"no tunnel in the path, so these results describe the network itself")
	}

	results := make([]bool, len(tcpPorts))
	errs := make([]error, len(tcpPorts))
	var wg sync.WaitGroup
	for i, p := range tcpPorts {
		wg.Add(1)
		go func(i int, p port) {
			defer wg.Done()
			results[i], errs[i] = dialable(ctx, p.Addr, timeout)
		}(i, p)
	}
	wg.Wait()

	open, blocked, privacyBlocked := 0, 0, 0
	var blockedLabels, privacyLabels []string
	for i, p := range tcpPorts {
		if results[i] {
			open++
			m.Row("tcp egress", report.StatusOK, p.Label, p.Addr, "reachable")
			continue
		}
		blocked++
		blockedLabels = append(blockedLabels, p.Label)
		st := report.StatusWarn
		if p.Privacy {
			privacyBlocked++
			privacyLabels = append(privacyLabels, p.Label)
			st = report.StatusBad
		}
		m.Row("tcp egress", st, p.Label, p.Addr, compactErr(errs[i]))
	}

	// These three are independent and each can burn a full timeout, so they
	// run together and report in a fixed order afterwards.
	var (
		udpAddr           *net.UDPAddr
		udpErr, quicErr   error
		v6Err             error
		udpOK, quicOK, v6 bool
	)
	var probes sync.WaitGroup
	probes.Add(3)
	go func() { defer probes.Done(); udpAddr, udpErr = firstSTUN(ctx, timeout) }()
	go func() { defer probes.Done(); quicErr = quicVersionNegotiation(ctx, quicTarget, timeout) }()
	go func() { defer probes.Done(); v6Err = dialIPv6(ctx, timeout) }()
	probes.Wait()

	if udpErr != nil {
		m.Row("udp egress", report.StatusWarn, "STUN binding", "failed", compactErr(udpErr))
	} else {
		udpOK = true
		m.Row("udp egress", report.StatusOK, "STUN binding", udpAddr.String(),
			"UDP leaves this network; this is your mapped address")
	}
	// Silence on udp/443 is ambiguous on its own, so it is never reported on
	// its own: the same packet goes to a QUIC port nothing bothers to filter,
	// and only if that is silent too has QUIC itself been singled out.
	quicAltOK := false
	if quicErr != nil && udpOK && ctx.Err() == nil {
		quicAltOK = quicVersionNegotiation(ctx, quicAltTarget, timeout) == nil
	}
	switch {
	case quicErr == nil:
		quicOK = true
		m.Row("udp egress", report.StatusOK, "QUIC / HTTP3", "reachable",
			"HTTP/3 is available, so browsers are not forced onto inspectable TCP")
	case quicAltOK:
		m.Row("udp egress", report.StatusInfo, "QUIC / HTTP3", "udp/443 closed",
			"QUIC is not filtered — the same packet is answered on udp/8443, so only this port is closed")
		m.Row("udp egress", report.StatusOK, "QUIC on udp/8443", "reachable",
			"proves QUIC traverses this path; HTTP/3 falls back to HTTP/2 over TCP")
	default:
		m.Row("udp egress", report.StatusWarn, "QUIC / HTTP3", "no response", compactErr(quicErr))
		if udpOK {
			m.Row("udp egress", report.StatusWarn, "QUIC on udp/8443", "no response",
				"QUIC is dropped on every port tested, not just 443")
		}
	}
	if v6Err != nil {
		m.Row("ipv6", report.StatusInfo, "IPv6 egress", "unavailable", compactErr(v6Err))
	} else {
		v6 = true
		m.Row("ipv6", report.StatusOK, "IPv6 egress", "reachable",
			"a second path exists; policy applied to IPv4 may not apply here")
	}

	switch {
	case quicOK || !udpOK:
		// Either HTTP/3 works, or UDP is blocked wholesale and
		// egress.udp-blocked below is the accurate way to say so.

	case quicAltOK:
		// The protocol is fine and one port is not. Preferring HTTP/2 is a
		// routine transport decision — many tunnels and networks make it
		// because they carry their own traffic over TCP — so this is recorded
		// for completeness and deliberately costs nothing.
		detail := "HTTP/3 is unavailable because udp/443 does not carry traffic here, but QUIC itself is " +
			"not being filtered: the identical packet is answered on udp/8443. Browsers fall back to " +
			"HTTP/2 over TCP, which is a transport preference rather than a visibility measure."
		if tunneled {
			detail += " The default route belongs to " + pathName + ", so this is the tunnel's forwarding " +
				"policy and not a property of the network this machine is attached to."
		}
		m.Add("egress.http3-unavailable", "HTTP/3 is unavailable; QUIC itself is not filtered",
			report.SevInfo, detail)

	case tunneled:
		// QUIC is dropped everywhere, but a tunnel owns the path, so the
		// finding belongs to whoever operates the tunnel. Reporting it as
		// network filtering would be wrong, and scoring it would be worse.
		m.Add("egress.quic-blocked", "QUIC is not carried by the tunnel in use", report.SevInfo,
			"QUIC did not reach any port tested while other UDP did. The default route belongs to "+
				pathName+", a tunnel, so what this measures is the tunnel's forwarding policy rather "+
				"than the network's. Re-run without the tunnel to judge the network itself.")

	default:
		privacyBlocked++
		privacyLabels = append(privacyLabels, "QUIC / HTTP3")
		m.Add("egress.quic-blocked", "QUIC is blocked while other UDP is allowed", report.SevMedium,
			"General UDP traffic leaves this network but QUIC does not, on every port tested, so the "+
				"block follows the protocol rather than a port. QUIC encrypts the parts of the handshake "+
				"that middleboxes read, and blocking it forces browsers onto TCP where they can be "+
				"watched. Filtering shaped this precisely is a decision about visibility, not capacity.")
	}

	if privacyBlocked > 0 {
		m.Add("egress.privacy-blocked", "Private protocols are selectively blocked", report.SevMedium,
			"Ports that carry encrypted versions of services which also exist in plaintext are unreachable, "+
				"while the plaintext versions work. Filtering shaped that way is not about bandwidth or "+
				"malware, it is about keeping traffic readable.",
			"blocked: "+strings.Join(privacyLabels, ", "))
	}
	if !udpOK {
		m.Add("egress.udp-blocked", "Outbound UDP is blocked", report.SevLow,
			"A STUN request could not complete, so general UDP traffic does not leave this network. "+
				"That rules out QUIC, HTTP/3, WireGuard and most VPN transports, leaving you with the TCP "+
				"ports this network is able to inspect.")
	}

	deriveLevel(m, open, blocked, privacyBlocked, blockedLabels, v6, quicAltOK)
	return m
}

func dialable(ctx context.Context, addr string, timeout time.Duration) (bool, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

// stunServers are independent operators. Concluding "outbound UDP is blocked"
// from one unreachable host would turn that operator having a bad day into a
// finding about the user's network, so agreement across vendors is required
// before UDP is called blocked.
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.nextcloud.com:443",
}

// quicTarget is the endpoint used for the QUIC reachability probe.
const quicTarget = "cloudflare.com:443"

// quicAltTarget carries QUIC on a port no filter singles out. It is only
// probed when quicTarget is silent, and it is what separates the two very
// different reasons for that silence: a network that fingerprints QUIC and
// drops it wherever it appears, versus one that simply does not carry udp/443
// so HTTP/3 falls back to HTTP/2 over TCP. Cloudflare answers version
// negotiation on this port exactly as it does on 443.
const quicAltTarget = "cloudflare.com:8443"

// firstSTUN performs a real RFC 5389 binding request against each server in
// turn and returns the first mapped address obtained. It proves UDP egress and
// reveals the address the outside world maps this host to.
func firstSTUN(ctx context.Context, timeout time.Duration) (*net.UDPAddr, error) {
	var firstErr error
	for _, server := range stunServers {
		addr, err := stunBinding(ctx, server, timeout)
		if err == nil {
			return addr, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}

// quicVersionNegotiation establishes whether QUIC can leave this network,
// without implementing QUIC. A long-header packet carrying a version no server
// supports must be answered with a Version Negotiation packet (RFC 9000 §6.1),
// which is identifiable by a zero version field. Getting one back proves the
// protocol reaches a real QUIC server and returns.

func quicVersionNegotiation(ctx context.Context, server string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Long header, fixed bit set, a reserved version, random connection ids,
	// padded to the 1200 byte minimum an Initial packet must reach.
	pkt := make([]byte, 1200)
	pkt[0] = 0xc0
	binary.BigEndian.PutUint32(pkt[1:5], 0x0a0a0a0a)
	pkt[5] = 8
	if _, err := rand.Read(pkt[6:14]); err != nil {
		return err
	}
	pkt[14] = 8
	if _, err := rand.Read(pkt[15:23]); err != nil {
		return err
	}
	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 5 {
		return errors.New("quic: short reply")
	}
	if buf[0]&0x80 == 0 {
		return errors.New("quic: reply was not a long header packet")
	}
	if binary.BigEndian.Uint32(buf[1:5]) != 0 {
		return errors.New("quic: reply was not a version negotiation packet")
	}
	return nil
}

const stunMagicCookie = 0x2112A442

func stunBinding(ctx context.Context, server string, timeout time.Duration) (*net.UDPAddr, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Binding request: type 0x0001, zero length, magic cookie, random id.
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseSTUNResponse(buf[:n], req[8:20])
}

func parseSTUNResponse(buf, txID []byte) (*net.UDPAddr, error) {
	if len(buf) < 20 {
		return nil, errors.New("stun: short response")
	}
	if binary.BigEndian.Uint16(buf[0:2]) != 0x0101 {
		return nil, errors.New("stun: not a binding success response")
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
		return nil, errors.New("stun: bad magic cookie")
	}
	if string(buf[8:20]) != string(txID) {
		return nil, errors.New("stun: transaction id mismatch")
	}

	body := buf[20:]
	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[0:2])
		length := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+length > len(body) {
			break
		}
		value := body[4 : 4+length]
		// 0x0020 XOR-MAPPED-ADDRESS, 0x0001 MAPPED-ADDRESS.
		if (typ == 0x0020 || typ == 0x0001) && len(value) >= 8 {
			xorred := typ == 0x0020
			family := value[1]
			portBytes := binary.BigEndian.Uint16(value[2:4])
			ipBytes := append([]byte{}, value[4:]...)
			if xorred {
				portBytes ^= uint16(stunMagicCookie >> 16)
				cookie := make([]byte, 4)
				binary.BigEndian.PutUint32(cookie, stunMagicCookie)
				for i := range ipBytes {
					if i < 4 {
						ipBytes[i] ^= cookie[i]
					} else {
						ipBytes[i] ^= txID[i-4]
					}
				}
			}
			switch {
			case family == 0x01 && len(ipBytes) >= 4:
				return &net.UDPAddr{IP: net.IP(ipBytes[:4]), Port: int(portBytes)}, nil
			case family == 0x02 && len(ipBytes) >= 16:
				return &net.UDPAddr{IP: net.IP(ipBytes[:16]), Port: int(portBytes)}, nil
			}
		}
		// Attributes are padded to a four byte boundary.
		advance := 4 + length
		if pad := advance % 4; pad != 0 {
			advance += 4 - pad
		}
		body = body[advance:]
	}
	return nil, errors.New("stun: no mapped address attribute")
}

// dialIPv6 records whether a second, often less policed, path exists.
func dialIPv6(ctx context.Context, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp6", "[2606:4700:4700::1111]:443")
	if err != nil {
		return err
	}
	return conn.Close()
}

func deriveLevel(m *report.Module, open, blocked, privacyBlocked int, blockedLabels []string, v6, http3Fallback bool) {
	total := open + blocked
	if v6 && blocked > 0 {
		m.Add("egress.v6-asymmetry", "IPv6 is unfiltered while IPv4 is not", report.SevLow,
			"Destinations blocked over IPv4 sit behind a network that still routes IPv6 freely. Filtering "+
				"applied to only one address family is usually an oversight rather than a policy, and it "+
				"means the controls here can be sidestepped by anything that prefers IPv6 — including "+
				"software you did not intend to let out.")
	}
	switch {
	case open <= 2 && blocked > 0:
		m.SetLevel(3, "E3", "Web-only egress",
			fmt.Sprintf("Only %d of %d tested destinations are reachable. Everything you do has to be "+
				"tunnelled through the few ports this network permits, which are also the ports it is "+
				"positioned to inspect.", open, total))
	case privacyBlocked > 0:
		m.SetLevel(2, "E2", "Privacy protocols filtered",
			"General traffic flows, but the encrypted alternatives to plaintext services are blocked. "+
				"The filtering is targeted at your ability to hide, not at your ability to connect.")
	case blocked > 0:
		m.SetLevel(1, "E1", "Partially filtered",
			fmt.Sprintf("%d of %d destinations were unreachable (%s). Some of this is ordinary anti-abuse "+
				"policy rather than surveillance.", blocked, total, strings.Join(blockedLabels, ", ")))
	default:
		summary := fmt.Sprintf("All %d tested destinations are reachable. This network is not steering "+
			"your traffic into a narrow, inspectable channel.", total)
		if http3Fallback {
			summary += " HTTP/3 is unavailable because udp/443 is closed, but QUIC traverses this path on " +
				"another port, so the fallback to HTTP/2 is a transport preference and not filtering."
		}
		m.SetLevel(0, "E0", "Open egress", summary)
	}
}

func compactErr(err error) string {
	if err == nil {
		return "blocked"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"):
		return "silently dropped (timeout)"
	case strings.Contains(s, "connection refused"):
		return "actively refused"
	case strings.Contains(s, "reset"):
		return "connection reset"
	case strings.Contains(s, "no route"):
		return "no route to host"
	}
	if i := strings.LastIndex(s, ": "); i > 0 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}
