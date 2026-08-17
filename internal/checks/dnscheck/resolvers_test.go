// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dnscheck

import (
	"net"
	"testing"
)

func TestIsBogon(t *testing.T) {
	bogons := []string{
		"0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"169.254.10.10", "100.64.0.1", "192.0.2.1", "::1", "fe80::1",
	}
	for _, s := range bogons {
		if !isBogon(net.ParseIP(s)) {
			t.Errorf("isBogon(%s) = false, want true", s)
		}
	}
	routable := []string{"8.8.8.8", "1.1.1.1", "104.16.132.229", "2606:4700::1111"}
	for _, s := range routable {
		if isBogon(net.ParseIP(s)) {
			t.Errorf("isBogon(%s) = true, want false", s)
		}
	}
	if !isBogon(nil) {
		t.Error("isBogon(nil) = false, want true")
	}
}

func TestBogonsIn(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("104.16.132.229"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("0.0.0.0"),
	}
	got := bogonsIn(ips)
	if len(got) != 2 {
		t.Fatalf("bogonsIn returned %v, want the two non-routable addresses", got)
	}
}

func TestAnyContained(t *testing.T) {
	// An anchor check passes when any returned address is one of the expected
	// constants, since resolvers return them in arbitrary order and subsets.
	if !anyContained([]string{"8.8.4.4"}, []string{"8.8.8.8", "8.8.4.4"}) {
		t.Error("anyContained missed a valid subset match")
	}
	if anyContained([]string{"10.0.0.1"}, []string{"8.8.8.8", "8.8.4.4"}) {
		t.Error("anyContained matched a forged answer")
	}
	if anyContained(nil, []string{"8.8.8.8"}) {
		t.Error("anyContained matched an empty answer set")
	}
}

func TestAnchorsAreFixedAddresses(t *testing.T) {
	// The anchors only work as forgery canaries if every expected address is
	// a literal, routable IP. A typo here would silently disable the check.
	for _, a := range anchors {
		if len(a.IPs) == 0 {
			t.Errorf("anchor %s has no expected addresses", a.Name)
		}
		for _, s := range a.IPs {
			ip := net.ParseIP(s)
			if ip == nil {
				t.Errorf("anchor %s: %q is not an IP address", a.Name, s)
				continue
			}
			if isBogon(ip) {
				t.Errorf("anchor %s: %q is not publicly routable", a.Name, s)
			}
		}
	}
}

func TestBlackholeProbesUseDocumentationRanges(t *testing.T) {
	// These probes are only meaningful if nothing on the internet can answer
	// them, so they must stay inside the RFC 5737 documentation prefixes.
	for _, addr := range BlackholeProbes {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("blackhole probe %q is not a host:port pair", addr)
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Errorf("blackhole probe %q is not an IP address", host)
			continue
		}
		v4 := ip.To4()
		documentation := (v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
			(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
			(v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
		if !documentation {
			t.Errorf("blackhole probe %s is outside the documentation ranges; a real host could answer", host)
		}
	}
}

func TestAnyContainedEdgeCases(t *testing.T) {
	// A resolver that returns the right address alongside others has not
	// forged anything, and an empty anchor list must never match.
	if !anyContained([]string{"203.0.113.1", "8.8.8.8"}, []string{"8.8.8.8"}) {
		t.Error("anyContained missed a match mixed in with other addresses")
	}
	if anyContained([]string{"8.8.8.8"}, nil) {
		t.Error("anyContained matched against an empty anchor list")
	}
}
