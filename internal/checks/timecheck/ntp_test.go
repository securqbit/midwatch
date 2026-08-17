// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package timecheck

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"
)

// reply builds a well formed SNTP server response echoing the given origin
// timestamp and reporting the given time.
func reply(origin []byte, at time.Time) []byte {
	b := make([]byte, 48)
	b[0] = 0x24 // LI 0, VN 4, mode 4 (server)
	b[1] = 2    // stratum 2
	copy(b[24:32], origin)
	secs, frac := ntpStamp(at)
	binary.BigEndian.PutUint32(b[40:44], secs)
	binary.BigEndian.PutUint32(b[44:48], frac)
	return b
}

func ntpStamp(t time.Time) (secs, frac uint32) {
	unix := t.Unix()
	secs = uint32(unix + ntpEpochOffset)
	frac = uint32(float64(t.Nanosecond()) / float64(time.Second) * math.MaxUint32)
	return secs, frac
}

// serveNTP runs a UDP responder that feeds each received packet to respond and
// writes back whatever it returns. A nil return sends nothing.
func serveNTP(t *testing.T, respond func(req []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := respond(append([]byte{}, buf[:n]...)); out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestNTPOffsetAcceptsMatchingNonce(t *testing.T) {
	want := time.Now().Add(90 * time.Second)
	addr := serveNTP(t, func(req []byte) []byte {
		return reply(req[40:48], want)
	})

	got, err := ntpOffset(context.Background(), addr, 2*time.Second)
	if err != nil {
		t.Fatalf("ntpOffset: %v", err)
	}
	// The offset is measured against a moving local clock, so allow slack for
	// the round trip rather than asserting an exact duration.
	if diff := (got - 90*time.Second).Abs(); diff > 2*time.Second {
		t.Errorf("offset = %v, want ~90s (off by %v)", got, diff)
	}
}

// A reply that echoes no nonce and simply asserts a time must be refused.
// Accepting one would let anything able to reach the client's port dictate
// what this module believes the time to be, which is precisely the tampering
// it exists to detect.
func TestNTPOffsetRejectsReplyWithoutNonce(t *testing.T) {
	forged := make([]byte, 8) // all zeros: not the nonce the request carried
	addr := serveNTP(t, func([]byte) []byte {
		return reply(forged, time.Now().Add(10*365*24*time.Hour))
	})

	if _, err := ntpOffset(context.Background(), addr, 500*time.Millisecond); err == nil {
		t.Fatal("accepted a reply that did not echo the request nonce")
	}
}

// A spoofed packet arriving ahead of the genuine one must not win. The
// responder writes a forgery claiming a wildly wrong time first, then the real
// reply; the client is expected to discard the first and keep reading.
func TestNTPOffsetSkipsSpoofAndAcceptsRealReply(t *testing.T) {
	want := time.Now().Add(30 * time.Second)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 48 {
			return
		}
		req := append([]byte{}, buf[:n]...)
		// The forgery echoes a nonce that was never sent, and claims a decade
		// of skew.
		_, _ = pc.WriteTo(reply(make([]byte, 8), time.Now().Add(10*365*24*time.Hour)), addr)
		// The genuine reply echoes the real nonce from bytes 40-47.
		_, _ = pc.WriteTo(reply(req[40:48], want), addr)
	}()

	got, err := ntpOffset(context.Background(), pc.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("ntpOffset: %v", err)
	}
	if diff := (got - 30*time.Second).Abs(); diff > 2*time.Second {
		t.Errorf("offset = %v, want ~30s — the spoofed reply was accepted", got)
	}
}

func TestNTPOffsetRejectsMalformedReplies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(req []byte) []byte
	}{
		{"short packet", func(req []byte) []byte { return make([]byte, 20) }},
		{"client mode", func(req []byte) []byte {
			b := reply(req[40:48], time.Now())
			b[0] = 0x23 // mode 3, a client packet reflected back
			return b
		}},
		{"unsynchronised", func(req []byte) []byte {
			b := reply(req[40:48], time.Now())
			b[0] |= 0xC0 // leap indicator 3
			return b
		}},
		{"kiss of death", func(req []byte) []byte {
			b := reply(req[40:48], time.Now())
			b[1] = 0 // stratum 0
			copy(b[12:16], "RATE")
			return b
		}},
		{"empty transmit timestamp", func(req []byte) []byte {
			b := reply(req[40:48], time.Now())
			binary.BigEndian.PutUint32(b[40:44], 0)
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := serveNTP(t, tc.respond)
			if _, err := ntpOffset(context.Background(), addr, 500*time.Millisecond); err == nil {
				t.Error("accepted a malformed reply")
			}
		})
	}
}

func TestNTPOffsetTimesOutOnSilence(t *testing.T) {
	addr := serveNTP(t, func([]byte) []byte { return nil })
	start := time.Now()
	if _, err := ntpOffset(context.Background(), addr, 300*time.Millisecond); err == nil {
		t.Fatal("expected a timeout when nothing answers")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("waited %v, far beyond the requested timeout", elapsed)
	}
}

func TestNTPTimeHandlesEraRollover(t *testing.T) {
	// Era 0: a timestamp inside the 1900-2036 window.
	era0 := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	secs, frac := ntpStamp(era0)
	if got := ntpTime(secs, frac); got.Sub(era0).Abs() > time.Second {
		t.Errorf("era 0: ntpTime = %v, want %v", got, era0)
	}

	// Era 1: after February 2036 the 32 bit seconds field wraps. A naive
	// conversion maps these onto the 1900s and reports a century of skew.
	const rollover = 1 << 32
	after := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	wrapped := uint32(after.Unix() + ntpEpochOffset - rollover)
	got := ntpTime(wrapped, 0)
	if got.Sub(after).Abs() > time.Second {
		t.Errorf("era 1: ntpTime = %v, want %v", got, after)
	}
	if got.Year() < 2036 {
		t.Errorf("era 1 timestamp decoded into the past: %v", got)
	}
}

func TestBlackholeTimeoutIsBounded(t *testing.T) {
	// A probe whose expected outcome is silence must not make an honest
	// network wait out the full user-supplied timeout.
	for _, tc := range []struct{ in, want time.Duration }{
		{0, 3 * time.Second},
		{-1, 3 * time.Second},
		{time.Second, time.Second},
		{30 * time.Second, 3 * time.Second},
	} {
		if got := blackholeTimeout(tc.in); got != tc.want {
			t.Errorf("blackholeTimeout(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
