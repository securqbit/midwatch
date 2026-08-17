// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package commscheck

import (
	"net"
	"strconv"
)

// endpoint is one host a communication app must reach to work.
//
// TLS distinguishes the two kinds of probe this module performs. An endpoint
// that speaks TLS can be tested for the *name* it is blocked by, and for the
// certificate it serves. One that does not — WhatsApp's chat servers speak
// Noise, Telegram's data centres speak MTProto, Apple's push service speaks its
// own framing — can only be tested for reachability, and asking it for a
// handshake it does not implement would measure nothing.
type endpoint struct {
	Host string
	Port int
	Role string
	TLS  bool

	// Issuer names the authority this endpoint is expected to present when it
	// deliberately does not use the public web PKI. Signal runs its own CA and
	// pins it in the app, so its chain validates against no browser trust store
	// and appears in no Certificate Transparency log — exactly the two signals
	// that mean "forged" anywhere else. Reading that as interception would be
	// wrong on every network on earth, which is worse than missing something:
	// it teaches the reader to disbelieve the tool.
	//
	// The match is on the issuer's name, which an interceptor could copy. It
	// cannot copy the name *and* be accepted by a client that pins the key, so
	// what this buys is an honest report rather than a proof. Taking a chain
	// apart properly is the tls module's job.
	Issuer string
}

// Addr renders the endpoint as host:port.
func (e endpoint) Addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// service is one communication product and the endpoints it depends on.
//
// E2EE marks the services that encrypt message contents end to end by default,
// with no server-side copy the operator could hand over. The distinction is the
// point of this module: a network that blocks exactly those while leaving the
// ones with server-readable history alone has not made a bandwidth decision, it
// has made a decision about what somebody is able to read.
type service struct {
	Name      string
	E2EE      bool
	Note      string
	Endpoints []endpoint
}

// services are the endpoints midwatch probes. Each host is one the vendor
// documents as required, and each is stable enough that failing to reach it is
// a property of the path rather than of the day.
var services = []service{
	{
		Name: "Signal", E2EE: true,
		Note: "end-to-end encrypted by default, no server-side message copy",
		Endpoints: []endpoint{
			{Host: "chat.signal.org", Port: 443, Role: "messaging", TLS: true, Issuer: "Signal Messenger"},
			{Host: "cdn.signal.org", Port: 443, Role: "attachments", TLS: true, Issuer: "Signal Messenger"},
		},
	},
	{
		Name: "WhatsApp", E2EE: true,
		Note: "end-to-end encrypted by default",
		Endpoints: []endpoint{
			{Host: "web.whatsapp.com", Port: 443, Role: "web client", TLS: true},
			// The chat servers speak Noise rather than TLS, so only reachability
			// is meaningful here.
			{Host: "g.whatsapp.net", Port: 443, Role: "chat servers", TLS: false},
			{Host: "mmg.whatsapp.net", Port: 443, Role: "media", TLS: true},
		},
	},
	{
		Name: "Telegram", E2EE: false,
		Note: "cloud chats are readable by the operator; only secret chats are end to end",
		Endpoints: []endpoint{
			{Host: "api.telegram.org", Port: 443, Role: "api", TLS: true},
			{Host: "web.telegram.org", Port: 443, Role: "web client", TLS: true},
			// A data centre reached by address rather than by name. It is the
			// control that separates "Telegram's names are being poisoned" from
			// "Telegram's network is unreachable": a DNS-level block cannot touch
			// this one, so if it answers while the names do not, the block is in
			// the resolver and the app itself would still connect.
			{Host: "149.154.167.51", Port: 443, Role: "MTProto DC2 (by address)", TLS: false},
		},
	},
	{
		Name: "iMessage / FaceTime", E2EE: true,
		Note: "end-to-end encrypted; both ride Apple's push service",
		Endpoints: []endpoint{
			// Reachability only. Apple's edge answers this host with a general
			// certificate naming images.apple.com rather than one naming the
			// endpoint, so a TLS identity check here would measure Apple's CDN
			// arrangements and report them as interception.
			{Host: "init-p01st.push.apple.com", Port: 443, Role: "push registration", TLS: false},
			// APNs proper. Apple documents tcp/5223 for it, and the port is a
			// routine casualty of "web ports only" policies, which is why
			// messages arrive late on some networks and not at all on others.
			{Host: "courier.push.apple.com", Port: 5223, Role: "push delivery", TLS: false},
			{Host: "gateway.icloud.com", Port: 443, Role: "account services", TLS: true},
		},
	},
	{
		Name: "Matrix", E2EE: true,
		Note: "federated, end-to-end encrypted by default in current clients",
		Endpoints: []endpoint{
			{Host: "matrix.org", Port: 443, Role: "homeserver", TLS: true},
		},
	},
	{
		Name: "XMPP", E2EE: false,
		Note: "federated open standard; encryption is per-client and optional",
		Endpoints: []endpoint{
			{Host: "xmpp.org", Port: 5222, Role: "client-to-server", TLS: false},
		},
	},
	{
		Name: "Discord", E2EE: false,
		Endpoints: []endpoint{
			{Host: "discord.com", Port: 443, Role: "api", TLS: true},
			{Host: "gateway.discord.gg", Port: 443, Role: "gateway", TLS: true},
		},
	},
	{
		Name: "Zoom", E2EE: false,
		Note: "end-to-end encryption is opt-in per meeting",
		Endpoints: []endpoint{
			{Host: "zoom.us", Port: 443, Role: "web and signalling", TLS: true},
		},
	},
	{
		Name: "Google Meet", E2EE: false,
		Endpoints: []endpoint{
			{Host: "meet.google.com", Port: 443, Role: "web and signalling", TLS: true},
		},
	},
	{
		Name: "Jitsi Meet", E2EE: false,
		Note: "self-hostable; the public instance is probed here",
		Endpoints: []endpoint{
			{Host: "meet.jit.si", Port: 443, Role: "web and signalling", TLS: true},
		},
	},
}

// control is an ordinary, uncontroversial TLS endpoint. Nothing below it is
// interpreted until this one works: a laptop with no connectivity would
// otherwise report every messenger on earth as censored.
var control = endpoint{Host: "example.com", Port: 443, Role: "control", TLS: true}

// benignSNI is the hostname offered during the differential handshake. It is
// deliberately dull. Sending it to a service's own address separates a device
// that is blocking the address from one that is reading the name out of the
// ClientHello and acting on it.
const benignSNI = "example.com"

// mediaProbes test the path that voice and video calls actually use. Every one
// of these apps negotiates media with ICE, and ICE begins with a STUN binding
// request over UDP. If that never completes, calls either fail outright or fall
// back to a TCP relay operated by the vendor — slower, and one more party in a
// position to see that the call happened.
var mediaProbes = []struct {
	Label string
	Addr  string
}{
	{"STUN (Google)", "stun.l.google.com:19302"},
	{"STUN (Cloudflare)", "stun.cloudflare.com:3478"},
}

// blackholeNets are ranges no public communication service is ever reachable
// at. A resolver that hands one back for signal.org is not answering the
// question, it is redirecting it.
var blackholeNets = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),
	mustCIDR("10.0.0.0/8"),
	mustCIDR("100.64.0.0/10"),
	mustCIDR("127.0.0.0/8"),
	mustCIDR("169.254.0.0/16"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.0.2.0/24"),
	mustCIDR("192.168.0.0/16"),
	mustCIDR("198.51.100.0/24"),
	mustCIDR("203.0.113.0/24"),
	mustCIDR("::/128"),
	mustCIDR("::1/128"),
	mustCIDR("fc00::/7"),
	mustCIDR("fe80::/10"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("commscheck: bad CIDR " + s)
	}
	return n
}

// isBlackhole reports whether an address could never host a public service.
func isBlackhole(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	for _, n := range blackholeNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// allBlackhole reports whether every answer was a redirection. One usable
// address is enough for the app to work, so a mixed answer is not a block.
func allBlackhole(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !isBlackhole(ip) {
			return false
		}
	}
	return true
}

// firstUsable picks the address to dial, preferring IPv4 so that the
// differential handshake and the first connection are known to have gone to the
// same place.
func firstUsable(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil && !isBlackhole(ip) {
			return ip
		}
	}
	for _, ip := range ips {
		if !isBlackhole(ip) {
			return ip
		}
	}
	return nil
}
