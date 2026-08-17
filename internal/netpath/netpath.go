// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package netpath answers a question every check in midwatch depends on:
// whose network is being measured?
//
// When a VPN owns the default route, the probes do not describe the network the
// machine is attached to. They describe the tunnel operator's forwarding and
// resolution policy, which is usually software the user installed on purpose. A
// tunnel that carries its own traffic over TCP commonly declines to forward
// udp/443, and one that offers a private resolver answers port 53 itself —
// behaviour that looks exactly like a hostile middlebox to a probe that cannot
// see the tunnel. Reporting it as network interception blames the wrong party
// and buries the findings that matter in noise, so the checks consult this
// package and attribute their conclusions accordingly.
package netpath

import (
	"net"
	"strings"
)

// tunnelPrefixes are the interface name prefixes used by VPN and tunnel
// software across the platforms midwatch runs on.
var tunnelPrefixes = []string{
	"utun", "tun", "tap", "ppp", "ipsec", "wg", "nordlynx", "proton", "zt", "gpd",
}

// Path describes the route this machine uses to reach the public internet.
type Path struct {
	// Interface is the name of the interface carrying the default route, or
	// empty when it could not be determined.
	Interface string
	// Tunneled reports whether that interface is a tunnel rather than a
	// physical link.
	Tunneled bool
}

// Describe renders the path for a report row.
func (p Path) Describe() string {
	if p.Interface == "" {
		return "unknown"
	}
	return p.Interface
}

// Detect reports which interface would carry traffic to the public internet and
// whether it is a tunnel. A zero Path means the question could not be answered,
// which callers must treat as "no tunnel known", never as "tunnel present".
func Detect() Path {
	// A connected UDP socket sends nothing; it only makes the kernel perform
	// the route lookup and pick the source address it would really use.
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return Path{}
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil || local.IP.IsUnspecified() {
		return Path{}
	}
	iface := interfaceFor(local.IP)
	if iface == nil {
		return Path{}
	}
	return Path{Interface: iface.Name, Tunneled: isTunnel(*iface)}
}

// interfaceFor returns the interface holding the given address.
func interfaceFor(ip net.IP) *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var candidate net.IP
			switch v := a.(type) {
			case *net.IPNet:
				candidate = v.IP
			case *net.IPAddr:
				candidate = v.IP
			}
			if candidate != nil && candidate.Equal(ip) {
				return &ifaces[i]
			}
		}
	}
	return nil
}

// isTunnel decides whether an interface is a tunnel. Name prefixes catch the
// common VPN clients; the point-to-point flag catches the ones that invent a
// name, since a physical ethernet or wireless link is never point-to-point.
func isTunnel(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return iface.Flags&net.FlagPointToPoint != 0
}
