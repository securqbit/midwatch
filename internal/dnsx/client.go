// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnsx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Transport identifies how a query reaches a resolver.
type Transport string

const (
	UDP Transport = "udp" // classic plaintext port 53
	TCP Transport = "tcp" // plaintext over TCP 53
	DoT Transport = "dot" // RFC 7858, TLS on 853
	DoH Transport = "doh" // RFC 8484, HTTPS
)

// Resolver describes one queryable endpoint.
type Resolver struct {
	Name       string    // display name, e.g. "Cloudflare"
	Transport  Transport // udp, tcp, dot, doh
	Addr       string    // host:port for udp/tcp/dot; absolute URL for doh
	ServerName string    // TLS certificate name for dot
}

// Label renders the resolver for terminal output.
func (r Resolver) Label() string {
	if r.Name == "" {
		return r.Addr
	}
	return r.Name
}

// String renders name and address together.
func (r Resolver) String() string {
	if r.Name == "" {
		return r.Addr
	}
	return fmt.Sprintf("%s (%s)", r.Name, r.Addr)
}

// Host returns the address without the port, for udp/tcp/dot resolvers.
func (r Resolver) Host() string {
	if h, _, err := net.SplitHostPort(r.Addr); err == nil {
		return h
	}
	return r.Addr
}

// Client exchanges DNS messages over any supported transport.
type Client struct {
	Timeout time.Duration
	Dialer  *net.Dialer
	HTTP    *http.Client
	// InsecureTLS disables certificate verification for DoT/DoH. It exists so
	// the DoT interception check can capture a forged chain rather than being
	// stopped by it; the check reports what it saw.
	InsecureTLS bool
}

// NewClient returns a client with sane defaults for probing.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	return &Client{
		Timeout: timeout,
		Dialer:  d,
		HTTP: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext:           d.DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
				// Deliberately ignore proxy environment variables: a probe
				// must measure the network, not an operator's shell config.
				Proxy: nil,
			},
		},
	}
}

// Exchange sends q to r and returns the reply plus round trip time.
//
// A UDP answer that arrives with the TC bit set is retried over TCP, as RFC
// 1035 §4.2.1 requires: the header flags of a truncated reply are still
// meaningful, but its record sections are not, and a check that reasons about
// rdata must not reason about half of it.
func (c *Client) Exchange(ctx context.Context, r Resolver, q *Msg) (*Msg, time.Duration, error) {
	start := time.Now()
	msg, err := c.exchange(ctx, r, q)
	if err != nil {
		return nil, time.Since(start), err
	}
	if msg.TC && (r.Transport == UDP || r.Transport == "") {
		overTCP := r
		overTCP.Transport = TCP
		if full, terr := c.exchange(ctx, overTCP, q); terr == nil {
			msg = full
		}
	}
	return msg, time.Since(start), nil
}

func (c *Client) exchange(ctx context.Context, r Resolver, q *Msg) (*Msg, error) {
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	var raw []byte
	switch r.Transport {
	case UDP, "":
		raw, err = c.exchangeUDP(ctx, r.Addr, wire, q.ID)
	case TCP:
		raw, err = c.exchangeStream(ctx, r, wire, false)
	case DoT:
		raw, err = c.exchangeStream(ctx, r, wire, true)
	case DoH:
		raw, err = c.exchangeHTTPS(ctx, r.Addr, wire)
	default:
		return nil, fmt.Errorf("dnsx: unknown transport %q", r.Transport)
	}
	if err != nil {
		return nil, err
	}
	msg, err := Unpack(raw)
	if err != nil {
		return nil, err
	}
	if msg.ID != q.ID {
		return msg, fmt.Errorf("dnsx: response id %d does not match query id %d", msg.ID, q.ID)
	}
	return msg, nil
}

func (c *Client) exchangeUDP(ctx context.Context, addr string, wire []byte, id uint16) ([]byte, error) {
	conn, err := c.dialer().DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	// Off-path answers and stale datagrams are common on intercepted
	// networks; keep reading until the transaction id matches or time runs out.
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) == id {
			return append([]byte{}, buf[:n]...), nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("dnsx: no matching response before deadline")
		}
	}
}

func (c *Client) exchangeStream(ctx context.Context, r Resolver, wire []byte, useTLS bool) ([]byte, error) {
	conn, err := c.dialer().DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if useTLS {
		name := r.ServerName
		if name == "" {
			name = r.Host()
		}
		tc := tls.Client(conn, &tls.Config{
			ServerName:         name,
			InsecureSkipVerify: c.InsecureTLS, //nolint:gosec // opt-in, reported
			MinVersion:         tls.VersionTLS12,
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		defer tc.Close()
		_ = tc.SetDeadline(deadline)
		conn = tc
	}

	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(wire)))
	copy(framed[2:], wire)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, errors.New("dnsx: invalid stream length prefix")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Client) exchangeHTTPS(ctx context.Context, url string, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "midwatch")

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsx: doh status %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/dns-message") {
		return nil, fmt.Errorf("dnsx: doh returned content-type %q (expected application/dns-message)", ct)
	}
	return body, nil
}

func (c *Client) dialer() *net.Dialer {
	if c.Dialer != nil {
		return c.Dialer
	}
	return &net.Dialer{Timeout: c.Timeout}
}

// Query is a convenience wrapper for a single recursive lookup.
func (c *Client) Query(ctx context.Context, r Resolver, name string, t Type) (*Msg, time.Duration, error) {
	return c.Exchange(ctx, r, NewQuery(name, t, ClassIN))
}

// QueryClass performs a lookup in a specific class (CH for identity probes).
func (c *Client) QueryClass(ctx context.Context, r Resolver, name string, t Type, cl Class) (*Msg, time.Duration, error) {
	return c.Exchange(ctx, r, NewQuery(name, t, cl))
}

// ProbeDoT completes a DNS-over-TLS handshake and returns the negotiated
// state without verifying the chain, so callers can inspect a forged
// certificate instead of merely failing.
func (c *Client) ProbeDoT(ctx context.Context, addr, serverName string) (*tls.ConnectionState, error) {
	conn, err := c.dialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // the chain is the evidence
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer tc.Close()
	state := tc.ConnectionState()
	return &state, nil
}
