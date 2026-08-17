// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package timecheck verifies that this host's clock, and the protocol it
// trusts to set it, have not been tampered with.
//
// Time is load-bearing for security and almost never checked. Certificate
// validity windows, TOTP codes, Kerberos tickets, JWT expiry and DNSSEC
// signature lifetimes are all decided by the local clock. An attacker who can
// move it forward can make revoked or expired certificates look current; one
// who can move it back can resurrect keys that were retired. NTP is
// unauthenticated by default, which makes it a soft target, so this module
// treats a redirected or disagreeing time source as a security finding rather
// than an inconvenience.
package timecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/securqbit/midwatch/internal/report"
)

// Options configures the time integrity scan.
type Options struct {
	Timeout time.Duration
	Deep    bool
}

// sample is one measured offset against one time source.
type sample struct {
	name   string
	offset time.Duration
	err    error
}

// servers are independently operated time sources. Four rather than three
// because pool.ntp.org rotates through volunteer machines and any given one
// may simply be down, and a median is only meaningful while enough sources
// answer to have a middle.
var servers = []struct{ Name, Addr string }{
	{"Cloudflare", "time.cloudflare.com:123"},
	{"Google", "time.google.com:123"},
	{"Apple", "time.apple.com:123"},
	{"NTP Pool", "pool.ntp.org:123"},
}

// blackholeNTP is an unroutable documentation address. A reply proves that
// port 123 is being transparently redirected to a local server.
const blackholeNTP = "192.0.2.123:123"

// Run executes the time module.
func Run(ctx context.Context, opts Options) *report.Module {
	m := report.NewModule("time", "Time source integrity", report.KindPosture)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Query every source concurrently. Sequential probing would let one
	// unreachable server add its whole timeout to the run, and simultaneous
	// samples also make the sources easier to compare against each other.
	samples := make([]sample, len(servers))
	var redirectErr error
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, name, addr string) {
			defer wg.Done()
			off, err := ntpOffset(ctx, addr, timeout)
			samples[i] = sample{name, off, err}
		}(i, s.Name, s.Addr)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// An interceptor answers immediately; only an honest network makes
		// this probe wait, so it does not need the full timeout.
		_, redirectErr = ntpOffset(ctx, blackholeNTP, blackholeTimeout(timeout))
	}()
	wg.Wait()

	for _, s := range samples {
		off, err := s.offset, s.err
		if err != nil {
			m.Row("time sources", report.StatusSkip, s.name, "unreachable", compactErr(err))
			continue
		}
		st := report.StatusOK
		note := "local clock agrees with this source"
		switch a := off.Abs(); {
		case a > 5*time.Minute:
			st, note = report.StatusBad, "local clock is badly wrong against this source"
		case a > 30*time.Second:
			st, note = report.StatusWarn, "local clock is drifting against this source"
		}
		m.Row("time sources", st, s.name, formatOffset(off), note)
	}

	var good []sample
	for _, s := range samples {
		if s.err == nil {
			good = append(good, s)
		}
	}

	redirected := reportRedirection(m, redirectErr)
	skewed, disagree := analyse(m, good)

	switch {
	case redirected || disagree:
		m.SetLevel(2, "T2", "Time source under network control",
			"The network is answering time queries itself or its sources contradict one another. "+
				"Whoever controls your clock controls whether an expired certificate looks valid.")
	case skewed:
		m.SetLevel(1, "T1", "Clock skew",
			"This machine's clock is far enough from real time to affect certificate validation and "+
				"one-time codes, though the time sources themselves appear honest.")
	case len(good) == 0:
		m.SetLevel(0, "T?", "Inconclusive",
			"No time source could be reached, so clock integrity could not be established.")
	default:
		m.SetLevel(0, "T0", "Time source intact",
			"Independent time sources agree with each other and with this machine's clock, so the "+
				"validity windows your security decisions depend on are being measured correctly.")
	}
	return m
}

// blackholeTimeout bounds the wait for a probe whose expected outcome is
// silence. A device that intercepts port 123 replies in milliseconds, so a
// long wait only slows down the honest case.
func blackholeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 3*time.Second {
		return 3 * time.Second
	}
	return timeout
}

func reportRedirection(m *report.Module, err error) bool {
	if err != nil {
		m.Row("transparent redirection", report.StatusOK, blackholeNTP, "silent",
			"unroutable address stayed unroutable")
		return false
	}
	m.Row("transparent redirection", report.StatusBad, blackholeNTP, "answered",
		"a local device is impersonating every NTP server")
	m.Add("time.redirected", "NTP traffic is being transparently redirected", report.SevMedium,
		"A time query sent to an unroutable documentation address was answered, so a device on this "+
			"network intercepts port 123 and replies on behalf of whatever server you configure. Because "+
			"classic NTP is unauthenticated, that device decides what time this machine believes, and "+
			"therefore which certificates and tokens this machine considers valid.")
	return true
}

func analyse(m *report.Module, good []sample) (skewed, disagree bool) {
	if len(good) == 0 {
		return false, false
	}
	minOff, maxOff := good[0].offset, good[0].offset
	for _, s := range good {
		if s.offset < minOff {
			minOff = s.offset
		}
		if s.offset > maxOff {
			maxOff = s.offset
		}
	}
	spread := maxOff - minOff
	if len(good) > 1 && spread.Abs() > 10*time.Second {
		disagree = true
		m.Add("time.disagreement", "Time sources disagree with each other", report.SevMedium,
			"Independent NTP servers returned times that differ by more than they ever should. Public "+
				"time sources are consistent to within milliseconds, so at least one of these answers was "+
				"manufactured before it reached this machine.",
			fmt.Sprintf("spread of %s across %d sources", spread.Round(time.Millisecond), len(good)))
	}

	// A true median, so one manipulated source cannot drag the verdict.
	offsets := make([]time.Duration, len(good))
	for i, s := range good {
		offsets[i] = s.offset
	}
	slices.Sort(offsets)
	median := offsets[len(offsets)/2]
	if median.Abs() > 60*time.Second {
		skewed = true
		sev := report.SevLow
		if median.Abs() > 24*time.Hour {
			sev = report.SevHigh
		}
		m.Add("time.skew", "This machine's clock is significantly wrong", sev,
			"Certificate validity, token expiry and signature lifetimes are all judged against the local "+
				"clock. At this offset, certificates that have expired or have not yet been issued can be "+
				"accepted as valid, and codes that should have lapsed still work.",
			"offset from real time: "+formatOffset(median))
	}
	return skewed, disagree
}

// ntpEpochOffset converts between the NTP epoch (1 January 1900) and the Unix
// epoch (1 January 1970).
const ntpEpochOffset = 2208988800

// ntpOffset performs an SNTP exchange and returns the difference between the
// server's time and this machine's clock.
//
// The request carries a random 64 bit nonce in its transmit timestamp, which a
// conforming server echoes verbatim in the origin timestamp of its reply (RFC
// 5905 §8). Requiring that echo is what makes the measurement trustworthy:
// without it any host able to guess the source port could inject a reply, and
// a module whose purpose is to detect a tampered clock would be the easiest
// thing on the network to tamper with. Replies that do not carry the nonce are
// discarded rather than accepted, and the read continues until one does or the
// deadline expires.
func ntpOffset(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// LI = 0, VN = 4, Mode = 3 (client).
	req := make([]byte, 48)
	req[0] = 0x23
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	copy(req[40:48], nonce[:])

	sent := time.Now()
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	resp := make([]byte, 68) // 48 byte header plus room for any extension
	for {
		n, err := conn.Read(resp)
		if err != nil {
			return 0, err
		}
		received := time.Now()
		if n < 48 {
			continue
		}
		if mode := resp[0] & 0x7; mode != 4 {
			continue
		}
		// A conforming server copies the request's transmit timestamp into the
		// origin field of its reply.
		if !bytes.Equal(resp[24:32], nonce[:]) {
			if time.Now().After(deadline) {
				return 0, errors.New("ntp: no reply carrying the request nonce before deadline")
			}
			continue
		}
		// Leap indicator 3 means the server knows it is not synchronised, and
		// stratum 0 is a kiss-of-death packet. Neither carries a usable time.
		if li := resp[0] >> 6; li == 3 {
			return 0, errors.New("ntp: server reports itself unsynchronised")
		}
		if stratum := resp[1]; stratum == 0 {
			return 0, fmt.Errorf("ntp: kiss-of-death packet (%q)", strings.TrimRight(string(resp[12:16]), "\x00"))
		}

		// Transmit timestamp, bytes 40-47, as seconds since 1900.
		secs := binary.BigEndian.Uint32(resp[40:44])
		frac := binary.BigEndian.Uint32(resp[44:48])
		if secs == 0 {
			return 0, errors.New("ntp: empty transmit timestamp")
		}
		serverTime := ntpTime(secs, frac)

		// Correct for the round trip so network latency is not read as skew.
		midpoint := sent.Add(received.Sub(sent) / 2)
		return serverTime.Sub(midpoint), nil
	}
}

// ntpTime converts an NTP timestamp to a Go time, handling the era rollover.
// The seconds field is 32 bits wide and wraps on 7 February 2036; values below
// the Unix epoch offset therefore belong to era 1, not to the 1900s. Handling
// this keeps the module from reporting a century of skew against every source
// once the field wraps.
func ntpTime(secs, frac uint32) time.Time {
	sec := int64(secs) - ntpEpochOffset
	if secs < ntpEpochOffset {
		sec = int64(secs) + (1 << 32) - ntpEpochOffset
	}
	nsec := int64(float64(frac) / math.MaxUint32 * float64(time.Second))
	return time.Unix(sec, nsec).UTC()
}

func formatOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign = "-"
	}
	a := d.Abs()
	switch {
	case a < time.Millisecond:
		return "in sync"
	case a < time.Second:
		return fmt.Sprintf("%s%dms", sign, a.Milliseconds())
	case a < time.Minute:
		return fmt.Sprintf("%s%.1fs", sign, a.Seconds())
	case a < time.Hour:
		return fmt.Sprintf("%s%.1fm", sign, a.Minutes())
	default:
		return fmt.Sprintf("%s%.1fh", sign, a.Hours())
	}
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "i/o timeout") {
		return "no reply"
	}
	if i := strings.LastIndex(s, ": "); i > 0 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}
