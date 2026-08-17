// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnsx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// answerFor builds a reply to q carrying one A record, with the TC bit set as
// asked. UDP and TCP servers below share it so both legs answer consistently.
func answerFor(t *testing.T, query []byte, ip string, truncated bool) []byte {
	t.Helper()
	q, err := Unpack(query)
	if err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	resp := &Msg{
		ID:        q.ID,
		Response:  true,
		RD:        true,
		RA:        true,
		Questions: q.Questions,
		TC:        truncated,
	}
	if !truncated {
		resp.Answers = []RR{{
			Name:  q.Questions[0].Name,
			Type:  TypeA,
			Class: ClassIN,
			TTL:   60,
			Data:  net.ParseIP(ip).To4(),
		}}
	}
	wire, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return wire
}

// dualStackResolver starts a UDP and a TCP listener on the same port and
// returns a Resolver addressed at both. The UDP side always answers with the
// TC bit set; the TCP side returns the full answer.
func dualStackResolver(t *testing.T, ip string) (Resolver, *int32Counter) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("could not bind TCP on the same port as UDP (%v); skipping", err)
	}
	t.Cleanup(func() { ln.Close() })

	tcpHits := &int32Counter{}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answerFor(t, buf[:n], ip, true), addr)
		}
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				tcpHits.inc()
				out := answerFor(t, body, ip, false)
				framed := make([]byte, 2+len(out))
				binary.BigEndian.PutUint16(framed[0:2], uint16(len(out)))
				copy(framed[2:], out)
				_, _ = conn.Write(framed)
			}(conn)
		}
	}()

	return Resolver{Name: "test", Transport: UDP, Addr: pc.LocalAddr().String()}, tcpHits
}

// A truncated UDP reply carries meaningful header flags but an unusable record
// section. Accepting it as-is would mean reasoning about half an answer, so it
// must be retried over TCP (RFC 1035 §4.2.1).
func TestExchangeRetriesTruncatedRepliesOverTCP(t *testing.T) {
	const want = "203.0.113.9"
	r, tcpHits := dualStackResolver(t, want)

	c := NewClient(3 * time.Second)
	msg, _, err := c.Query(context.Background(), r, "example.com", TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if msg.TC {
		t.Error("returned message still has the TC bit set; the retry did not replace it")
	}
	if got := msg.IPStrings(); len(got) != 1 || got[0] != want {
		t.Errorf("addresses = %v, want [%s] from the TCP answer", got, want)
	}
	if n := tcpHits.get(); n != 1 {
		t.Errorf("TCP server saw %d queries, want exactly 1", n)
	}
}

// An untruncated UDP reply must be used as-is; retrying every answer over TCP
// would double the traffic and defeat the point of the datagram path.
func TestExchangeDoesNotRetryUntruncatedReplies(t *testing.T) {
	const want = "203.0.113.10"

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answerFor(t, buf[:n], want, false), addr)
		}
	}()

	// Nothing is listening on TCP, so a retry would surface as an error or an
	// empty answer rather than silently succeeding.
	r := Resolver{Name: "test", Transport: UDP, Addr: pc.LocalAddr().String()}
	c := NewClient(2 * time.Second)
	msg, _, err := c.Query(context.Background(), r, "example.com", TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := msg.IPStrings(); len(got) != 1 || got[0] != want {
		t.Errorf("addresses = %v, want [%s]", got, want)
	}
}

// If the TCP retry fails, the truncated reply is better than nothing: header
// flags such as AD and the rcode are still meaningful.
func TestExchangeKeepsTruncatedReplyWhenTCPFails(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answerFor(t, buf[:n], "203.0.113.11", true), addr)
		}
	}()

	r := Resolver{Name: "test", Transport: UDP, Addr: pc.LocalAddr().String()}
	c := NewClient(time.Second)
	msg, _, err := c.Query(context.Background(), r, "example.com", TypeA)
	if err != nil {
		t.Fatalf("Query returned an error instead of the truncated reply: %v", err)
	}
	if !msg.TC {
		t.Error("expected the truncated reply to be preserved when TCP is unavailable")
	}
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) inc() {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *int32Counter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
