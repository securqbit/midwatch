// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnscheck

import (
	"bufio"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/securqbit/midwatch/internal/dnsx"
)

// PublicResolvers are well known recursive resolvers reachable on plaintext
// port 53. They serve as a control group: their answers are what the network
// *should* be delivering.
var PublicResolvers = []dnsx.Resolver{
	{Name: "Cloudflare", Transport: dnsx.UDP, Addr: "1.1.1.1:53"},
	{Name: "Google", Transport: dnsx.UDP, Addr: "8.8.8.8:53"},
	{Name: "Quad9", Transport: dnsx.UDP, Addr: "9.9.9.9:53"},
}

// EncryptedResolvers are the encrypted transports a privacy-conscious client
// would prefer. Networks that want to keep reading DNS block them.
var EncryptedResolvers = []dnsx.Resolver{
	{Name: "Cloudflare DoT", Transport: dnsx.DoT, Addr: "1.1.1.1:853", ServerName: "cloudflare-dns.com"},
	{Name: "Quad9 DoT", Transport: dnsx.DoT, Addr: "9.9.9.9:853", ServerName: "dns.quad9.net"},
	{Name: "Cloudflare DoH", Transport: dnsx.DoH, Addr: "https://cloudflare-dns.com/dns-query"},
	{Name: "Google DoH", Transport: dnsx.DoH, Addr: "https://dns.google/dns-query"},
}

// BlackholeProbes are addresses in the RFC 5737 documentation ranges. Nothing
// on the internet answers DNS here, so a reply proves that port 53 is being
// transparently redirected to a local device.
var BlackholeProbes = []string{
	"192.0.2.53:53",
	"198.51.100.53:53",
	"203.0.113.53:53",
}

// anchors are hostnames whose addresses are fixed anycast constants rather
// than CDN-dependent. Any deviation is a rewritten answer, not load
// balancing, which makes them ideal forgery canaries.
var anchors = []struct {
	Name string
	IPs  []string
}{
	{"dns.google", []string{"8.8.8.8", "8.8.4.4"}},
	{"one.one.one.one", []string{"1.1.1.1", "1.0.0.1"}},
	{"dns.quad9.net", []string{"9.9.9.9", "149.112.112.112"}},
}

// controlDomains are ordinary destinations used for cross-resolver comparison.
var controlDomains = []string{"cloudflare.com", "www.google.com", "github.com"}

const (
	// reachabilityProbe is a name every resolver on earth can answer. The
	// answer is discarded; only whether one arrives is measured.
	reachabilityProbe = "example.com"

	// caseEchoProbe carries the 0x20 test. It must be a name that resolves
	// everywhere and is not filtered in any jurisdiction, because a blocked
	// name would look like a rewriting middlebox.
	caseEchoProbe = "example.com"

	// dnssecFailedProbe is published with deliberately invalid signatures, so
	// a validating resolver must answer SERVFAIL.
	dnssecFailedProbe = "dnssec-failed.org"

	// dnssecValidProbe is correctly signed, so a validating resolver sets AD.
	dnssecValidProbe = "cloudflare.com"

	// encryptedProbe is the question asked over DoT and DoH.
	encryptedProbe = "cloudflare.com"
)

// SystemResolvers returns the resolvers this host is configured to use.
func SystemResolvers() []dnsx.Resolver {
	var out []dnsx.Resolver
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return out
	}
	defer f.Close()

	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := fields[1]
		if net.ParseIP(ip) == nil || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, dnsx.Resolver{
			Name:      "system",
			Transport: dnsx.UDP,
			Addr:      net.JoinHostPort(ip, "53"),
		})
	}
	// A read error mid-file leaves a partial list. Returning what was parsed
	// is still useful, but silently returning nothing would be read as "this
	// host has no resolvers configured", which is a different claim entirely.
	if err := sc.Err(); err != nil && len(out) == 0 {
		return nil
	}
	return out
}

// isBogon reports whether an address is one that a public hostname should
// never resolve to. Sinkholes and captive portals answer with exactly these.
func isBogon(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// 100.64.0.0/10 carrier grade NAT, 192.0.2.0/24 documentation.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 2 {
			return true
		}
	}
	return false
}

func bogonsIn(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		if isBogon(ip) {
			out = append(out, ip.String())
		}
	}
	return out
}

func anyContained(got, want []string) bool {
	for _, g := range got {
		if slices.Contains(want, g) {
			return true
		}
	}
	return false
}
