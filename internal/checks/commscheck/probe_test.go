// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package commscheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// selfSigned mints a certificate valid for localhost under the given issuer
// name. It stands in for the two things this module has to tell apart: an
// authority a service pins on purpose, and one an interceptor brought along.
func selfSigned(t *testing.T, issuer string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuer, Organization: []string{issuer}},
		Issuer:                pkix.Name{CommonName: issuer, Organization: []string{issuer}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve accepts one connection and hands it to h, returning the address to
// dial. It exists so each test can decide exactly how the far end behaves.
func serve(t *testing.T, h func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go h(c)
		}
	}()
	return l.Addr().String()
}

func TestReachesTLSSeparatesTheServerFromTheBlock(t *testing.T) {
	cert := selfSigned(t, "Test CA")
	ctx := context.Background()

	// A completed handshake obviously reached a server.
	completes := serve(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tc.Handshake()
		_ = tc.Close()
	})
	if !reachesTLS(ctx, completes, "localhost", time.Second) {
		t.Error("a completed handshake must count as reaching the server")
	}

	// So did one the server rejected in the protocol. This is the case that
	// matters: treating a TLS alert as a block would report every endpoint that
	// dislikes a benign hostname as censorship.
	alerts := serve(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errors.New("no certificate for that name")
			},
		})
		_ = tc.Handshake()
		_ = tc.Close()
	})
	if !reachesTLS(ctx, alerts, "localhost", time.Second) {
		t.Error("a TLS alert is the server speaking, so the path is not blocked")
	}

	// A connection accepted and then destroyed without a word is what a
	// middlebox does, and is the only outcome that counts as blocked.
	kills := serve(t, func(c net.Conn) { _ = c.Close() })
	if reachesTLS(ctx, kills, "localhost", time.Second) {
		t.Error("a connection killed without a TLS reply must count as blocked")
	}

	// Nothing listening at all.
	if reachesTLS(ctx, "127.0.0.1:1", "localhost", 200*time.Millisecond) {
		t.Error("an unreachable address must not count as reaching a server")
	}
}

// handshakeWith dials addr, completes TLS under sni and returns the state.
func handshakeWith(t *testing.T, addr, sni string) *tls.ConnectionState {
	t.Helper()
	conn, err := dial(context.Background(), addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	state, err := handshake(context.Background(), conn, sni, 2*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return state
}

func TestIdentifyOverARealHandshake(t *testing.T) {
	cert := selfSigned(t, "Interception Appliance")
	addr := serve(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tc.Handshake()
		_ = tc.Close()
	})

	// An ordinary endpoint: this chain validates against no trust store and
	// carries no Certificate Transparency proofs, which is what interception
	// looks like.
	state := handshakeWith(t, addr, "localhost")
	ok, issuer := identify(state, endpoint{Host: "localhost", Port: 443, TLS: true})
	if ok {
		t.Errorf("an unlogged, untrusted chain was accepted as genuine (issuer %q)", issuer)
	}
	if issuer != "Interception Appliance" {
		t.Errorf("issuer = %q, want the name the certificate carried", issuer)
	}

	// The same chain on an endpoint that pins that authority is exactly what
	// was expected. This is the Signal case, and getting it wrong would report
	// interception on every network in the world.
	pinned := endpoint{Host: "localhost", Port: 443, TLS: true, Issuer: "Interception Appliance"}
	if ok, _ := identify(handshakeWith(t, addr, "localhost"), pinned); !ok {
		t.Error("an endpoint's own pinned authority was reported as interception")
	}

	// And a pinned endpoint answered by anyone else is an interceptor.
	other := endpoint{Host: "localhost", Port: 443, TLS: true, Issuer: "Signal Messenger"}
	if ok, _ := identify(handshakeWith(t, addr, "localhost"), other); ok {
		t.Error("a certificate from the wrong authority was accepted for a pinned endpoint")
	}
}

func TestProbeReportsHowAConnectionFailed(t *testing.T) {
	ctx := context.Background()

	// Nothing is listening, and the address is a literal so no name is looked
	// up: the failure is unambiguously the connection itself.
	r := probe(ctx, endpoint{Host: "127.0.0.1", Port: 1, Role: "test"}, 500*time.Millisecond)
	if r.V != vRefused && r.V != vDropped {
		t.Errorf("probe of a closed port = %v, want refused or dropped", r.V)
	}
	if r.Detail == "" {
		t.Error("a failed probe must say what happened")
	}

	// A plain TCP endpoint has told us everything it can once the port opens.
	addr := serve(t, func(c net.Conn) { _ = c.Close() })
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	r = probe(ctx, endpoint{Host: host, Port: p, Role: "test"}, time.Second)
	if r.V != vOK {
		t.Errorf("probe of an open TCP port = %v (%s), want reachable", r.V, r.Detail)
	}
}
