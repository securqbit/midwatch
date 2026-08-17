// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestPackUnpackRoundTrip(t *testing.T) {
	q := NewQuery("example.com", TypeA, ClassIN)
	q.ID = 0x1234

	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got.ID != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234", got.ID)
	}
	if !got.RD {
		t.Error("RD flag lost in round trip")
	}
	if len(got.Questions) != 1 {
		t.Fatalf("got %d questions, want 1", len(got.Questions))
	}
	if got.Questions[0].Name != "example.com." {
		t.Errorf("question name = %q, want %q", got.Questions[0].Name, "example.com.")
	}
	if got.Questions[0].Type != TypeA {
		t.Errorf("question type = %v, want A", got.Questions[0].Type)
	}
	// EDNS(0) must survive as an OPT record in the additional section.
	if !got.EDNS {
		t.Error("EDNS(0) OPT record missing after round trip")
	}
	if got.UDPSize != 1232 {
		t.Errorf("advertised UDP size = %d, want 1232", got.UDPSize)
	}
}

func TestUnpackFlagsAndRcode(t *testing.T) {
	q := NewQuery("example.com", TypeA, ClassIN)
	q.Response = true
	q.AA = true
	q.AD = true
	q.CD = true
	q.RA = true
	q.Rcode = RcodeNXDomain

	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for name, ok := range map[string]bool{
		"Response": got.Response, "AA": got.AA, "AD": got.AD, "CD": got.CD, "RA": got.RA,
	} {
		if !ok {
			t.Errorf("%s flag lost in round trip", name)
		}
	}
	if got.Rcode != RcodeNXDomain {
		t.Errorf("Rcode = %d, want %d", got.Rcode, RcodeNXDomain)
	}
}

// buildResponse assembles a reply by hand so the decoder is tested against
// bytes rather than against its own encoder.
func buildResponse(t *testing.T, qname string, answers ...[]byte) []byte {
	t.Helper()
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0xabcd)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180) // QR + RD + RA
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(answers)))

	for _, label := range strings.Split(qname, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, uint16(TypeA))
	buf = binary.BigEndian.AppendUint16(buf, uint16(ClassIN))
	for _, a := range answers {
		buf = append(buf, a...)
	}
	return buf
}

// aRecord builds an answer that points its name back at the question via a
// compression pointer, which is what real servers emit.
func aRecord(ip net.IP) []byte {
	rr := []byte{0xc0, 0x0c} // pointer to offset 12, the question name
	rr = binary.BigEndian.AppendUint16(rr, uint16(TypeA))
	rr = binary.BigEndian.AppendUint16(rr, uint16(ClassIN))
	rr = binary.BigEndian.AppendUint32(rr, 300)
	v4 := ip.To4()
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(v4)))
	return append(rr, v4...)
}

func TestUnpackAnswersWithCompression(t *testing.T) {
	wire := buildResponse(t, "dns.google",
		aRecord(net.IPv4(8, 8, 8, 8)),
		aRecord(net.IPv4(8, 8, 4, 4)))

	msg, err := Unpack(wire)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("got %d answers, want 2", len(msg.Answers))
	}
	if msg.Answers[0].Name != "dns.google." {
		t.Errorf("compressed name = %q, want %q", msg.Answers[0].Name, "dns.google.")
	}
	got := msg.IPStrings()
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "8.8.4.4" {
		t.Errorf("IPStrings() = %v, want [8.8.8.8 8.8.4.4]", got)
	}
	if !msg.HasIP("8.8.4.4") {
		t.Error("HasIP(8.8.4.4) = false, want true")
	}
	if msg.HasIP("1.2.3.4") {
		t.Error("HasIP(1.2.3.4) = true, want false")
	}
}

// A malformed tail must not discard the answers already decoded: an
// interceptor emitting non-conforming records should still be reportable.
func TestUnpackToleratesTruncatedTail(t *testing.T) {
	wire := buildResponse(t, "dns.google", aRecord(net.IPv4(8, 8, 8, 8)))
	binary.BigEndian.PutUint16(wire[6:8], 2) // claim an answer that is absent

	msg, err := Unpack(wire)
	if err != nil {
		t.Fatalf("Unpack returned error on truncated tail: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("got %d answers, want the 1 that was parseable", len(msg.Answers))
	}
}

func TestUnpackRejectsPointerLoop(t *testing.T) {
	// A name whose pointer refers to itself must terminate rather than hang.
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	buf = append(buf, 0xc0, 0x0c) // offset 12 points at itself

	if _, err := Unpack(buf); err == nil {
		t.Error("Unpack accepted a self-referential compression pointer")
	}
}

func TestUnpackShortMessage(t *testing.T) {
	if _, err := Unpack([]byte{0x00, 0x01}); err == nil {
		t.Error("Unpack accepted a message shorter than a header")
	}
}

func TestTXTDecoding(t *testing.T) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], 1)
	buf = append(buf, 2, 'i', 'd', 6, 's', 'e', 'r', 'v', 'e', 'r', 0)
	buf = binary.BigEndian.AppendUint16(buf, uint16(TypeTXT))
	buf = binary.BigEndian.AppendUint16(buf, uint16(ClassCH))

	rr := []byte{0xc0, 0x0c}
	rr = binary.BigEndian.AppendUint16(rr, uint16(TypeTXT))
	rr = binary.BigEndian.AppendUint16(rr, uint16(ClassCH))
	rr = binary.BigEndian.AppendUint32(rr, 0)
	txt := append([]byte{5}, "res01"...)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(txt)))
	rr = append(rr, txt...)

	msg, err := Unpack(append(buf, rr...))
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	got := msg.TXTs()
	if len(got) != 1 || got[0] != "res01" {
		t.Errorf("TXTs() = %v, want [res01]", got)
	}
}

func TestRandomizeCasePreservesName(t *testing.T) {
	const name = "wikipedia.org"
	for i := 0; i < 50; i++ {
		got := RandomizeCase(name)
		if !strings.EqualFold(got, name) {
			t.Fatalf("RandomizeCase(%q) = %q, which is a different name", name, got)
		}
		if len(got) != len(name) {
			t.Fatalf("RandomizeCase changed length: %q", got)
		}
	}
}

func TestRandomLabelShape(t *testing.T) {
	got := RandomLabel(20)
	if len(got) != 20 {
		t.Fatalf("RandomLabel(20) returned %d characters", len(got))
	}
	for _, c := range got {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", c) {
			t.Fatalf("RandomLabel produced %q, which is not a valid DNS label character", c)
		}
	}
	if RandomLabel(20) == got {
		t.Error("RandomLabel returned the same label twice; probes would be cacheable")
	}
}

func TestPackRejectsOversizedLabel(t *testing.T) {
	q := NewQuery(strings.Repeat("a", 64)+".com", TypeA, ClassIN)
	if _, err := q.Pack(); err == nil {
		t.Error("Pack accepted a label longer than 63 bytes")
	}
}

func TestFqdnNormalisation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"", "."},
		{".", "."},
	} {
		if got := fqdn(tc.in); got != tc.want {
			t.Errorf("fqdn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
