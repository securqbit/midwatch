// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package netpath

import (
	"net"
	"strings"
	"testing"
)

func TestIsTunnel(t *testing.T) {
	tests := []struct {
		name  string
		iface net.Interface
		want  bool
	}{
		{"wifi", net.Interface{Name: "en0", Flags: net.FlagUp | net.FlagBroadcast}, false},
		{"ethernet", net.Interface{Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast}, false},
		{"loopback", net.Interface{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}, false},
		{"bridge", net.Interface{Name: "bridge100", Flags: net.FlagUp | net.FlagBroadcast}, false},
		{"macos vpn", net.Interface{Name: "utun9", Flags: net.FlagUp | net.FlagPointToPoint}, true},
		{"linux vpn", net.Interface{Name: "tun0", Flags: net.FlagUp}, true},
		{"wireguard", net.Interface{Name: "wg0", Flags: net.FlagUp}, true},
		{"ipsec", net.Interface{Name: "ipsec0", Flags: net.FlagUp}, true},
		{"unnamed tunnel caught by flag", net.Interface{Name: "vpnX", Flags: net.FlagUp | net.FlagPointToPoint}, true},
		{"case insensitive", net.Interface{Name: "UTUN0", Flags: net.FlagUp}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTunnel(tc.iface); got != tc.want {
				t.Errorf("isTunnel(%q, %v) = %v, want %v", tc.iface.Name, tc.iface.Flags, got, tc.want)
			}
		})
	}
}

// Detect must never invent an answer or panic on a host with unusual routing.
// A zero Path is the honest outcome, and it must not read as "tunnel present":
// downgrading findings on a guess would hide real interception.
func TestDetectIsConsistent(t *testing.T) {
	p := Detect()
	if p.Interface == "" && p.Tunneled {
		t.Error("Detect reported a tunnel without naming an interface")
	}
	if p.Interface != "" && strings.TrimSpace(p.Interface) != p.Interface {
		t.Errorf("interface name %q has surrounding whitespace", p.Interface)
	}
	if (Path{}).Tunneled {
		t.Error("the zero Path must not be tunneled")
	}
}

func TestDescribe(t *testing.T) {
	if got := (Path{}).Describe(); got != "unknown" {
		t.Errorf("zero Path Describe() = %q, want %q", got, "unknown")
	}
	if got := (Path{Interface: "utun9", Tunneled: true}).Describe(); got != "utun9" {
		t.Errorf("Describe() = %q, want %q", got, "utun9")
	}
}
