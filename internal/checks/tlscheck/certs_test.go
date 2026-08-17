// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tlscheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestCountSCTListEntries(t *testing.T) {
	entry := func(payload string) []byte {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(payload)))
		return append(b, payload...)
	}
	body := append(entry("first"), entry("second")...)
	list := make([]byte, 2)
	binary.BigEndian.PutUint16(list, uint16(len(body)))
	list = append(list, body...)

	if got := countSCTListEntries(list); got != 2 {
		t.Errorf("countSCTListEntries = %d, want 2", got)
	}
	if got := countSCTListEntries(nil); got != 0 {
		t.Errorf("countSCTListEntries(nil) = %d, want 0", got)
	}
	// A truncated list must not panic or over-count.
	if got := countSCTListEntries(list[:len(list)-3]); got > 2 {
		t.Errorf("countSCTListEntries(truncated) = %d, want at most 2", got)
	}
}

func TestMatchInterceptor(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		expect bool
	}{
		{"Zscaler Intermediate Root CA", "Zscaler", true},
		{"FortiGate CA", "Fortinet FortiGate", true},
		{"Kaspersky Anti-Virus Personal Root", "Kaspersky", true},
		{"mitmproxy", "mitmproxy", true},
		{"DO_NOT_TRUST_FiddlerRoot", "Fiddler / Burp root", true},
		{"DigiCert Global Root G2", "", false},
		{"ISRG Root X1", "", false},
	}
	for _, tc := range cases {
		got, ok := matchInterceptor(tc.in)
		if ok != tc.expect {
			t.Errorf("matchInterceptor(%q) matched = %v, want %v", tc.in, ok, tc.expect)
			continue
		}
		if ok && got.vendor != tc.want {
			t.Errorf("matchInterceptor(%q) vendor = %q, want %q", tc.in, got.vendor, tc.want)
		}
	}
}

func TestIsPublicCA(t *testing.T) {
	public := []string{
		"DigiCert Global Root G2", "ISRG Root X1 / Let's Encrypt",
		"GTS Root R1 / Google Trust Services LLC", "USERTrust RSA Certification Authority",
		"Apple Public EV Server RSA CA 1 - G1 / Apple Inc.",
	}
	for _, s := range public {
		if !isPublicCA(s) {
			t.Errorf("isPublicCA(%q) = false, want true", s)
		}
	}
	private := []string{
		"Acme Corp Internal CA", "Zscaler Root CA", "mitmproxy",
		"BurpSuite Community Edition", "",
	}
	for _, s := range private {
		if isPublicCA(s) {
			t.Errorf("isPublicCA(%q) = true, want false", s)
		}
	}
}

func TestKeyDescription(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: &rsaKey.PublicKey}
	desc, bits, weak := keyDescription(cert)
	if desc != "RSA-1024" || bits != 1024 || !weak {
		t.Errorf("keyDescription(RSA-1024) = %q/%d/%v, want RSA-1024/1024/true", desc, bits, weak)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desc, _, weak = keyDescription(&x509.Certificate{PublicKey: &ecKey.PublicKey})
	if desc != "ECDSA-P256" || weak {
		t.Errorf("keyDescription(P256) = %q/%v, want ECDSA-P256/false", desc, weak)
	}
}

func TestWeakSignature(t *testing.T) {
	for _, alg := range []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.MD5WithRSA, x509.ECDSAWithSHA1} {
		if !weakSignature(alg) {
			t.Errorf("weakSignature(%v) = false, want true", alg)
		}
	}
	for _, alg := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.ECDSAWithSHA384, x509.PureEd25519} {
		if weakSignature(alg) {
			t.Errorf("weakSignature(%v) = true, want false", alg)
		}
	}
}

func TestLifetimeDays(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	if got := lifetimeDays(cert); got != 90 {
		t.Errorf("lifetimeDays = %d, want 90", got)
	}
}

// makeCert builds a self-signed leaf, standing in for what an interception
// appliance presents: a locally minted certificate with no CT proof.
func makeCert(t *testing.T, cn string, hosts []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSPKIFingerprintDistinguishesKeys(t *testing.T) {
	a := makeCert(t, "one.example", []string{"one.example"})
	b := makeCert(t, "two.example", []string{"two.example"})

	if spkiFingerprint(a) == spkiFingerprint(b) {
		t.Error("distinct keys produced the same SPKI fingerprint")
	}
	first := spkiFingerprint(a)
	if spkiFingerprint(a) != first {
		t.Error("SPKI fingerprint is not stable for one certificate")
	}
	if len(first) != 64 {
		t.Errorf("SPKI fingerprint is %d characters, want a 64 character sha256 hex digest", len(first))
	}
	if len(shortFingerprint(spkiFingerprint(a))) != 16 {
		t.Error("shortFingerprint did not truncate to 16 characters")
	}
}
