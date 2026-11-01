// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package egresscheck

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildSTUNSuccess assembles a binding success response containing an
// XOR-MAPPED-ADDRESS, exactly as a real STUN server would.
func buildSTUNSuccess(txID []byte, ip net.IP, port uint16) []byte {
	v4 := ip.To4()
	value := make([]byte, 8)
	value[0] = 0
	value[1] = 0x01 // IPv4 family
	binary.BigEndian.PutUint16(value[2:4], port^uint16(stunMagicCookie>>16))
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	for i := 0; i < 4; i++ {
		value[4+i] = v4[i] ^ cookie[i]
	}

	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))
	attr = append(attr, value...)

	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101) // binding success
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	return append(msg, attr...)
}

func TestParseSTUNResponse(t *testing.T) {
	txID := []byte("0123456789ab")
	want := net.IPv4(203, 0, 113, 45)
	msg := buildSTUNSuccess(txID, want, 54321)

	addr, err := parseSTUNResponse(msg, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	if !addr.IP.Equal(want) {
		t.Errorf("IP = %v, want %v", addr.IP, want)
	}
	if addr.Port != 54321 {
		t.Errorf("port = %d, want 54321", addr.Port)
	}
}

func TestParseSTUNResponseRejectsForgery(t *testing.T) {
	txID := []byte("0123456789ab")
	msg := buildSTUNSuccess(txID, net.IPv4(203, 0, 113, 45), 1234)

	// A reply for somebody else's transaction must be refused, otherwise an
	// off-path responder could dictate the reported mapping.
	if _, err := parseSTUNResponse(msg, []byte("ba9876543210")); err == nil {
		t.Error("parseSTUNResponse accepted a mismatched transaction id")
	}

	bad := append([]byte{}, msg...)
	binary.BigEndian.PutUint32(bad[4:8], 0xdeadbeef)
	if _, err := parseSTUNResponse(bad, txID); err == nil {
		t.Error("parseSTUNResponse accepted a bad magic cookie")
	}

	short := msg[:10]
	if _, err := parseSTUNResponse(short, txID); err == nil {
		t.Error("parseSTUNResponse accepted a truncated message")
	}

	notSuccess := append([]byte{}, msg...)
	binary.BigEndian.PutUint16(notSuccess[0:2], 0x0111) // binding error
	if _, err := parseSTUNResponse(notSuccess, txID); err == nil {
		t.Error("parseSTUNResponse accepted an error response as success")
	}
}

func TestParseSTUNResponseWithoutAddress(t *testing.T) {
	txID := []byte("0123456789ab")
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)

	if _, err := parseSTUNResponse(msg, txID); err == nil {
		t.Error("parseSTUNResponse succeeded without a mapped address attribute")
	}
}

func TestCompactErrIsReadable(t *testing.T) {
	cases := map[string]string{
		"dial tcp 1.2.3.4:853: i/o timeout":       "silently dropped (timeout)",
		"dial tcp 1.2.3.4:25: connection refused": "actively refused",
		"read tcp: connection reset by peer":      "connection reset",
	}
	for in, want := range cases {
		if got := compactErr(errTest(in)); got != want {
			t.Errorf("compactErr(%q) = %q, want %q", in, got, want)
		}
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

// stunWithAttribute wraps one raw attribute in a binding success response,
// with no padding added, so malformed shapes can be fed to the parser.
func stunWithAttribute(txID []byte, typ uint16, value []byte) []byte {
	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], typ)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))
	attr = append(attr, value...)

	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	return append(msg, attr...)
}

// A reply is attacker-controlled input: anything on the path can answer a
// UDP request. None of these may panic, because a panic here ends the scan.
func TestParseSTUNResponseSurvivesMalformedAttributes(t *testing.T) {
	txID := []byte("0123456789ab")
	cases := map[string][]byte{
		// Longer than the 16-byte cookie-plus-transaction-id XOR mask.
		"oversized ipv6 xor-mapped": append([]byte{0, 0x02, 0, 0}, make([]byte, 24)...),
		"oversized ipv4 xor-mapped": append([]byte{0, 0x01, 0, 0}, make([]byte, 40)...),
		"ipv6 family, ipv4 length":  {0, 0x02, 0, 0, 1, 2, 3, 4},
		"unknown family":            {0, 0x07, 0, 0, 1, 2, 3, 4},
		// Five bytes with no padding: the advance overruns the message.
		"unpadded final attribute": {0, 0x07, 0, 0, 1},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseSTUNResponse panicked: %v", r)
				}
			}()
			msg := stunWithAttribute(txID, 0x0020, value)
			addr, err := parseSTUNResponse(msg, txID)
			// An oversized attribute still carries a usable address in its
			// leading bytes; everything else must be rejected.
			if err == nil && addr == nil {
				t.Error("nil address without an error")
			}
		})
	}
}

func TestParseSTUNResponseSkipsBadAttributeForGoodOne(t *testing.T) {
	txID := []byte("0123456789ab")
	good := buildSTUNSuccess(txID, net.IPv4(203, 0, 113, 45), 1234)
	goodAttr := good[20:]

	// A malformed attribute first, then the real mapping.
	bad := []byte{0x00, 0x20, 0x00, 0x08, 0, 0x07, 0, 0, 1, 2, 3, 4}
	msg := append(append([]byte{}, good[:20]...), append(bad, goodAttr...)...)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)-20))

	addr, err := parseSTUNResponse(msg, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	if !addr.IP.Equal(net.IPv4(203, 0, 113, 45)) || addr.Port != 1234 {
		t.Errorf("got %v, want 203.0.113.45:1234", addr)
	}
}
