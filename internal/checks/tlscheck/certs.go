// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tlscheck

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// oidSCTList is the certificate extension carrying embedded Signed
// Certificate Timestamps (RFC 6962). Every certificate issued by a publicly
// trusted CA since 2018 carries SCTs, because browsers reject those that do
// not. Interception appliances mint certificates locally and therefore cannot
// produce them: absence of SCTs is the single most reliable tell that a
// certificate did not come from the public web PKI.
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// interceptor maps a substring of an issuer or root subject to the product
// that emits it. Matching is case insensitive.
type interceptor struct {
	needle string
	vendor string
	kind   string // "enterprise", "endpoint", "developer"
}

var knownInterceptors = []interceptor{
	// Enterprise / network security appliances and SASE vendors.
	{"zscaler", "Zscaler", "enterprise"},
	{"netskope", "Netskope", "enterprise"},
	{"blue coat", "Broadcom Blue Coat", "enterprise"},
	{"bluecoat", "Broadcom Blue Coat", "enterprise"},
	{"forcepoint", "Forcepoint", "enterprise"},
	{"websense", "Forcepoint Websense", "enterprise"},
	{"fortinet", "Fortinet FortiGate", "enterprise"},
	{"fortigate", "Fortinet FortiGate", "enterprise"},
	{"palo alto", "Palo Alto Networks", "enterprise"},
	{"paloalto", "Palo Alto Networks", "enterprise"},
	{"cisco umbrella", "Cisco Umbrella", "enterprise"},
	{"opendns", "Cisco OpenDNS", "enterprise"},
	{"check point", "Check Point", "enterprise"},
	{"checkpoint", "Check Point", "enterprise"},
	{"sonicwall", "SonicWall", "enterprise"},
	{"watchguard", "WatchGuard", "enterprise"},
	{"barracuda", "Barracuda", "enterprise"},
	{"iboss", "iboss", "enterprise"},
	{"lightspeed systems", "Lightspeed Systems", "enterprise"},
	{"securly", "Securly", "enterprise"},
	{"smoothwall", "Smoothwall", "enterprise"},
	{"untangle", "Untangle", "enterprise"},
	{"sangfor", "Sangfor", "enterprise"},
	{"cyberoam", "Cyberoam", "enterprise"},
	{"hillstone", "Hillstone Networks", "enterprise"},
	{"menlo security", "Menlo Security", "enterprise"},
	{"skyhigh", "Skyhigh Security", "enterprise"},
	{"mcafee web gateway", "McAfee Web Gateway", "enterprise"},
	{"sslsplit", "sslsplit", "enterprise"},
	{"squid", "Squid proxy", "enterprise"},
	{"mitm", "generic MITM proxy", "enterprise"},

	// Endpoint security suites that install a local root to scan TLS.
	{"kaspersky", "Kaspersky", "endpoint"},
	{"eset", "ESET", "endpoint"},
	{"bitdefender", "Bitdefender", "endpoint"},
	{"avast", "Avast", "endpoint"},
	{"avg ", "AVG", "endpoint"},
	{"mcafee", "McAfee", "endpoint"},
	{"trend micro", "Trend Micro", "endpoint"},
	{"dr.web", "Dr.Web", "endpoint"},
	{"f-secure", "F-Secure", "endpoint"},
	{"sophos", "Sophos", "endpoint"},
	{"malwarebytes", "Malwarebytes", "endpoint"},
	{"webroot", "Webroot", "endpoint"},
	{"comodo internet security", "Comodo Internet Security", "endpoint"},

	// Developer and research tooling.
	{"mitmproxy", "mitmproxy", "developer"},
	{"portswigger", "Burp Suite", "developer"},
	{"charles proxy", "Charles Proxy", "developer"},
	{"fiddler", "Fiddler", "developer"},
	{"do not trust", "Fiddler / Burp root", "developer"},
	{"do_not_trust", "Fiddler / Burp root", "developer"},
	{"proxyman", "Proxyman", "developer"},
	{"httptoolkit", "HTTP Toolkit", "developer"},
	{"stunnel", "stunnel", "developer"},
}

// publicCAs lists organisations that operate roots in the major public trust
// programmes. A chain anchored outside this set is not automatically hostile,
// but combined with missing SCTs it means the certificate was minted by
// something local rather than by the web PKI.
var publicCAs = []string{
	"digicert", "let's encrypt", "isrg", "google trust services", "gts",
	"sectigo", "comodo ca", "usertrust", "globalsign", "amazon", "starfield",
	"godaddy", "entrust", "identrust", "baltimore", "certum", "buypass",
	"ssl.com", "zerossl", "actalis", "quovadis", "thawte", "geotrust",
	"rapidssl", "verisign", "aaa certificate services", "d-trust", "telia",
	"harica", "firmaprofesional", "t-systems", "swisssign", "microsoft",
	"apple", "cloudflare", "atos", "e-tugra", "emsign", "netlock",
	"security communication", "secom", "cybertrust", "affirmtrust",
	"trustwave", "hongkong post", "twca", "wo sign", "certsign", "izenpe",
	"camerfirma", "disig", "sk id", "ac camerfirma", "amazon root",
	"starfield technologies", "sheca", "cfca", "vtrus", "certainly",
	"open root certificate", "xramp", "unizeto", "asseco",
}

// weakCiphers are suites whose presence on a modern endpoint indicates a
// middlebox terminating with a dated TLS stack.
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "RC4",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "3DES-CBC",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "RSA key exchange, no forward secrecy",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "RSA key exchange, no forward secrecy",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "RSA key exchange, no forward secrecy",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "RSA key exchange, no forward secrecy",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "RSA key exchange, no forward secrecy",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "RC4",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "RC4",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "3DES-CBC",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "CBC mode",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "CBC mode",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "CBC mode",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "CBC mode",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "CBC mode",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "CBC mode",
}

// matchInterceptor reports the vendor behind a subject/issuer string. The
// longest matching needle wins, so a specific product name is preferred over
// the generic substring it happens to contain ("mitmproxy" over "mitm").
func matchInterceptor(fields ...string) (interceptor, bool) {
	joined := strings.ToLower(strings.Join(fields, " | "))
	best, found := interceptor{}, false
	for _, k := range knownInterceptors {
		if !strings.Contains(joined, k.needle) {
			continue
		}
		if !found || len(k.needle) > len(best.needle) {
			best, found = k, true
		}
	}
	return best, found
}

// isPublicCA reports whether a root subject looks like a member of the public
// trust programmes.
func isPublicCA(subject string) bool {
	s := strings.ToLower(subject)
	for _, ca := range publicCAs {
		if strings.Contains(s, ca) {
			return true
		}
	}
	return false
}

// spkiFingerprint hashes the SubjectPublicKeyInfo. Two different hostnames
// presenting the same SPKI is proof of a single interception key, since no
// legitimate pair of unrelated sites shares a private key.
func spkiFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func shortFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

// countSCTs totals the Signed Certificate Timestamps visible to the client,
// from the certificate extension, the TLS handshake extension and the stapled
// OCSP response.
func countSCTs(leaf *x509.Certificate, state *tls.ConnectionState) int {
	n := 0
	if state != nil {
		n += len(state.SignedCertificateTimestamps)
	}
	if leaf == nil {
		return n
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}
		var octets []byte
		if _, err := asn1.Unmarshal(ext.Value, &octets); err != nil {
			continue
		}
		n += countSCTListEntries(octets)
	}
	return n
}

// countSCTListEntries walks a TLS SignedCertificateTimestampList: a two byte
// list length followed by two byte length prefixed entries.
func countSCTListEntries(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	total := int(binary.BigEndian.Uint16(b[0:2]))
	if total+2 > len(b) {
		total = len(b) - 2
	}
	body := b[2 : 2+total]
	n, off := 0, 0
	for off+2 <= len(body) {
		l := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2 + l
		if off > len(body) {
			break
		}
		n++
	}
	return n
}

// keyDescription renders the leaf public key type and strength.
func keyDescription(c *x509.Certificate) (desc string, bits int, weak bool) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits = pub.N.BitLen()
		return fmt.Sprintf("RSA-%d", bits), bits, bits < 2048
	case *ecdsa.PublicKey:
		bits = pub.Curve.Params().BitSize
		return fmt.Sprintf("ECDSA-P%d", bits), bits, bits < 224
	case ed25519.PublicKey:
		return "Ed25519", 256, false
	default:
		return "unknown", 0, false
	}
}

// weakSignature flags signature algorithms no public CA may still use.
func weakSignature(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// issuerName renders the most useful identity fields of an issuer.
func issuerName(c *x509.Certificate) string {
	cn := c.Issuer.CommonName
	org := strings.Join(c.Issuer.Organization, ", ")
	switch {
	case cn != "" && org != "" && !strings.Contains(strings.ToLower(cn), strings.ToLower(org)):
		return fmt.Sprintf("%s / %s", cn, org)
	case cn != "":
		return cn
	case org != "":
		return org
	default:
		return c.Issuer.String()
	}
}

// subjectName renders a certificate subject compactly.
func subjectName(c *x509.Certificate) string {
	cn := c.Subject.CommonName
	org := strings.Join(c.Subject.Organization, ", ")
	switch {
	case cn != "" && org != "" && !strings.Contains(strings.ToLower(cn), strings.ToLower(org)):
		return fmt.Sprintf("%s / %s", cn, org)
	case cn != "":
		return cn
	case org != "":
		return org
	default:
		return c.Subject.String()
	}
}

// lifetimeDays is the total validity window of a certificate. Public CAs are
// capped by the CA/Browser Forum baseline requirements (398 days and falling);
// appliances routinely mint multi year certificates.
func lifetimeDays(c *x509.Certificate) int {
	return int(c.NotAfter.Sub(c.NotBefore).Hours() / 24)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func expiresIn(c *x509.Certificate) string {
	d := time.Until(c.NotAfter)
	if d < 0 {
		return "expired"
	}
	return fmt.Sprintf("%dd left", int(d.Hours()/24))
}
