// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package dnsx is a minimal DNS message encoder/decoder and multi-transport
// client. midwatch ships its own rather than taking a dependency: a tool people
// run to audit their network should have a supply chain you can read in an
// afternoon, and the checks need wire-level control (raw flags, 0x20 case
// encoding, malformed-server tolerance) that stub resolvers do not expose.
package dnsx

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Type is a DNS RR type.
type Type uint16

// Class is a DNS RR class.
type Class uint16

const (
	TypeA      Type = 1
	TypeNS     Type = 2
	TypeCNAME  Type = 5
	TypeSOA    Type = 6
	TypePTR    Type = 12
	TypeMX     Type = 15
	TypeTXT    Type = 16
	TypeAAAA   Type = 28
	TypeOPT    Type = 41
	TypeDS     Type = 43
	TypeRRSIG  Type = 46
	TypeDNSKEY Type = 48
	TypeHTTPS  Type = 65
)

const (
	ClassIN Class = 1
	ClassCH Class = 3
)

// Response codes.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT", TypeDS: "DS",
	TypeRRSIG: "RRSIG", TypeDNSKEY: "DNSKEY", TypeHTTPS: "HTTPS",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

var rcodeNames = map[int]string{
	RcodeSuccess: "NOERROR", RcodeFormErr: "FORMERR", RcodeServFail: "SERVFAIL",
	RcodeNXDomain: "NXDOMAIN", RcodeNotImp: "NOTIMP", RcodeRefused: "REFUSED",
}

// RcodeString names a response code.
func RcodeString(r int) string {
	if n, ok := rcodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("RCODE%d", r)
}

var (
	errTruncated = errors.New("dnsx: message truncated")
	errBadLabel  = errors.New("dnsx: invalid label length")
)

// Question is a single DNS question.
type Question struct {
	Name  string
	Type  Type
	Class Class
}

// RR is a resource record. Common rdata shapes are decoded into the
// convenience fields; Data always holds the raw rdata.
type RR struct {
	Name   string
	Type   Type
	Class  Class
	TTL    uint32
	Data   []byte
	IP     net.IP
	Target string
	TXT    []string
}

// Msg is a DNS message.
type Msg struct {
	ID       uint16
	Response bool
	Opcode   uint8
	AA       bool // authoritative answer
	TC       bool // truncated
	RD       bool // recursion desired
	RA       bool // recursion available
	AD       bool // authentic data (DNSSEC validated by the resolver)
	CD       bool // checking disabled
	Rcode    int

	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR

	// EDNS(0) options, emitted as an OPT record in the additional section.
	EDNS    bool
	UDPSize uint16
	DO      bool // DNSSEC OK

	Raw []byte // populated on unpack
}

// NewQuery builds a recursive query with a cryptographically random ID and
// EDNS(0) enabled.
func NewQuery(name string, t Type, c Class) *Msg {
	return &Msg{
		ID:        randomID(),
		RD:        true,
		Questions: []Question{{Name: fqdn(name), Type: t, Class: c}},
		EDNS:      true,
		UDPSize:   1232,
	}
}

func randomID() uint16 {
	n, err := rand.Int(rand.Reader, big.NewInt(65536))
	if err != nil {
		return 0x2a2a
	}
	return uint16(n.Int64())
}

// RandomLabel returns a random lowercase hex label of n characters, for
// probing wildcard/NXDOMAIN behaviour with a name that cannot be cached.
func RandomLabel(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "midwatchprobe0000000000"[:n]
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// RandomizeCase applies DNS 0x20 encoding: a conforming resolver echoes the
// question name back byte for byte, so a normalised name reveals a middlebox
// that rewrote the query.
func RandomizeCase(name string) string {
	b := []byte(name)
	r := make([]byte, len(b))
	if _, err := rand.Read(r); err != nil {
		return name
	}
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r[i]&1 == 1 {
			b[i] = c - 32
		}
	}
	return string(b)
}

func fqdn(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// Pack serialises the message to wire format.
func (m *Msg) Pack() ([]byte, error) {
	additional := m.Additional
	if m.EDNS {
		size := m.UDPSize
		if size == 0 {
			size = 1232
		}
		ttl := uint32(0)
		if m.DO {
			ttl |= 1 << 15
		}
		opt := RR{Name: ".", Type: TypeOPT, Class: Class(size), TTL: ttl}
		additional = append(append([]RR{}, additional...), opt)
	}

	buf := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(buf[0:2], m.ID)
	binary.BigEndian.PutUint16(buf[2:4], m.flags())
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(additional)))

	var err error
	for _, q := range m.Questions {
		if buf, err = packName(buf, q.Name); err != nil {
			return nil, err
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(q.Type))
		buf = binary.BigEndian.AppendUint16(buf, uint16(q.Class))
	}
	for _, set := range [][]RR{m.Answers, m.Authority, additional} {
		for _, rr := range set {
			if buf, err = packRR(buf, rr); err != nil {
				return nil, err
			}
		}
	}
	return buf, nil
}

func (m *Msg) flags() uint16 {
	var f uint16
	if m.Response {
		f |= 1 << 15
	}
	f |= uint16(m.Opcode&0xF) << 11
	if m.AA {
		f |= 1 << 10
	}
	if m.TC {
		f |= 1 << 9
	}
	if m.RD {
		f |= 1 << 8
	}
	if m.RA {
		f |= 1 << 7
	}
	if m.AD {
		f |= 1 << 5
	}
	if m.CD {
		f |= 1 << 4
	}
	f |= uint16(m.Rcode & 0xF)
	return f
}

func packName(buf []byte, name string) ([]byte, error) {
	name = fqdn(name)
	if name == "." {
		return append(buf, 0), nil
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("dnsx: bad label %q in %q", label, name)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0), nil
}

func packRR(buf []byte, rr RR) ([]byte, error) {
	var err error
	if buf, err = packName(buf, rr.Name); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(rr.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(rr.Class))
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rr.Data)))
	return append(buf, rr.Data...), nil
}

// Unpack parses a wire format message.
func Unpack(buf []byte) (*Msg, error) {
	if len(buf) < 12 {
		return nil, errTruncated
	}
	m := &Msg{Raw: buf}
	m.ID = binary.BigEndian.Uint16(buf[0:2])
	f := binary.BigEndian.Uint16(buf[2:4])
	m.Response = f&(1<<15) != 0
	m.Opcode = uint8((f >> 11) & 0xF)
	m.AA = f&(1<<10) != 0
	m.TC = f&(1<<9) != 0
	m.RD = f&(1<<8) != 0
	m.RA = f&(1<<7) != 0
	m.AD = f&(1<<5) != 0
	m.CD = f&(1<<4) != 0
	m.Rcode = int(f & 0xF)

	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	ns := int(binary.BigEndian.Uint16(buf[8:10]))
	ar := int(binary.BigEndian.Uint16(buf[10:12]))

	off := 12
	var err error
	for i := 0; i < qd; i++ {
		var q Question
		if q, off, err = unpackQuestion(buf, off); err != nil {
			return m, err
		}
		m.Questions = append(m.Questions, q)
	}
	for _, spec := range []struct {
		n   int
		dst *[]RR
	}{{an, &m.Answers}, {ns, &m.Authority}, {ar, &m.Additional}} {
		for i := 0; i < spec.n; i++ {
			var rr RR
			if rr, off, err = unpackRR(buf, off); err != nil {
				// Tolerate a malformed tail: partial answers are still
				// evidence, and interceptors emit non-conforming records.
				return m, nil
			}
			*spec.dst = append(*spec.dst, rr)
			if rr.Type == TypeOPT {
				m.EDNS = true
				m.UDPSize = uint16(rr.Class)
				m.DO = rr.TTL&(1<<15) != 0
			}
		}
	}
	return m, nil
}

func unpackQuestion(buf []byte, off int) (Question, int, error) {
	name, next, err := unpackName(buf, off)
	if err != nil {
		return Question{}, off, err
	}
	if next+4 > len(buf) {
		return Question{}, off, errTruncated
	}
	q := Question{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(buf[next : next+2])),
		Class: Class(binary.BigEndian.Uint16(buf[next+2 : next+4])),
	}
	return q, next + 4, nil
}

func unpackRR(buf []byte, off int) (RR, int, error) {
	name, next, err := unpackName(buf, off)
	if err != nil {
		return RR{}, off, err
	}
	if next+10 > len(buf) {
		return RR{}, off, errTruncated
	}
	rr := RR{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(buf[next : next+2])),
		Class: Class(binary.BigEndian.Uint16(buf[next+2 : next+4])),
		TTL:   binary.BigEndian.Uint32(buf[next+4 : next+8]),
	}
	rdlen := int(binary.BigEndian.Uint16(buf[next+8 : next+10]))
	next += 10
	if next+rdlen > len(buf) {
		return RR{}, off, errTruncated
	}
	rr.Data = buf[next : next+rdlen]
	decodeRdata(&rr, buf, next, rdlen)
	return rr, next + rdlen, nil
}

func decodeRdata(rr *RR, buf []byte, off, rdlen int) {
	switch rr.Type {
	case TypeA:
		if rdlen == 4 {
			rr.IP = net.IP(append([]byte{}, rr.Data...))
		}
	case TypeAAAA:
		if rdlen == 16 {
			rr.IP = net.IP(append([]byte{}, rr.Data...))
		}
	case TypeCNAME, TypeNS, TypePTR:
		if n, _, err := unpackName(buf, off); err == nil {
			rr.Target = n
		}
	case TypeSOA:
		if n, _, err := unpackName(buf, off); err == nil {
			rr.Target = n
		}
	case TypeMX:
		if rdlen > 2 {
			if n, _, err := unpackName(buf, off+2); err == nil {
				rr.Target = n
			}
		}
	case TypeTXT:
		p := 0
		for p < rdlen {
			l := int(rr.Data[p])
			p++
			if p+l > rdlen {
				break
			}
			rr.TXT = append(rr.TXT, string(rr.Data[p:p+l]))
			p += l
		}
	}
}

// unpackName decodes a (possibly compressed) domain name, returning the name
// and the offset just past the name in the current record.
func unpackName(buf []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := off
	jumped := false
	hops := 0
	for {
		if off >= len(buf) {
			return "", 0, errTruncated
		}
		l := int(buf[off])
		switch {
		case l == 0:
			off++
			if !jumped {
				next = off
			}
			s := sb.String()
			if s == "" {
				s = "."
			}
			return s, next, nil
		case l&0xC0 == 0:
			off++
			if off+l > len(buf) {
				return "", 0, errTruncated
			}
			sb.Write(buf[off : off+l])
			sb.WriteByte('.')
			off += l
		case l&0xC0 == 0xC0:
			if off+1 >= len(buf) {
				return "", 0, errTruncated
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if !jumped {
				next = off + 2
				jumped = true
			}
			if hops++; hops > 16 {
				return "", 0, errors.New("dnsx: compression pointer loop")
			}
			off = ptr
		default:
			return "", 0, errBadLabel
		}
	}
}

// IPs returns every A/AAAA address in the answer section.
func (m *Msg) IPs() []net.IP {
	var out []net.IP
	for _, rr := range m.Answers {
		if rr.IP != nil {
			out = append(out, rr.IP)
		}
	}
	return out
}

// IPStrings returns the answer addresses as sorted strings.
func (m *Msg) IPStrings() []string {
	var out []string
	for _, ip := range m.IPs() {
		out = append(out, ip.String())
	}
	return out
}

// TXTs returns every TXT string in the answer section.
func (m *Msg) TXTs() []string {
	var out []string
	for _, rr := range m.Answers {
		out = append(out, rr.TXT...)
	}
	return out
}

// HasIP reports whether the answer section contains the given address.
func (m *Msg) HasIP(want string) bool {
	for _, ip := range m.IPs() {
		if ip.String() == want {
			return true
		}
	}
	return false
}

// QuestionName returns the name echoed back in the first question, which for
// a conforming resolver is byte-identical to what was asked.
func (m *Msg) QuestionName() string {
	if len(m.Questions) == 0 {
		return ""
	}
	return m.Questions[0].Name
}
