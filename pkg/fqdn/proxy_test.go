package fqdn

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

type auth bool

func (a auth) AllowedResolver(context.Context, string, string, netip.AddrPort, uint8) (bool, error) {
	return bool(a), nil
}

type forward struct {
	answer []byte
	called bool
}

func (f *forward) Exchange(context.Context, netip.AddrPort, uint8, []byte) ([]byte, error) {
	f.called = true
	return f.answer, nil
}

func TestProxyChecksResolverBeforeForwarding(t *testing.T) {
	e, _ := setup(t)
	q := query(1, "a.example")
	f := &forward{answer: q}
	p := ProxyCore{Engine: e, Authorizer: auth(false), Forwarder: f, MaxRecords: 10}
	if _, err := p.Resolve(context.Background(), Exchange{Endpoint: "pod", Lifetime: "uid-1", WireQuery: q}); err == nil {
		t.Fatal("denied resolver forwarded")
	}
	if f.called {
		t.Fatal("forwarder called")
	}
}

func TestProxyDoesNotReleaseOnProgrammingFailure(t *testing.T) {
	e, programmer := setup(t)
	if err := e.UpdateRules(context.Background(), "pod", "uid-1", []Rule{{Owner: "p", Name: "a.example"}}); err != nil {
		t.Fatal(err)
	}
	q := query(1, "a.example")
	r := append([]byte(nil), q...)
	r[2] = 0x80
	binary.BigEndian.PutUint16(r[6:], 1)
	r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 0, 2, 1)
	programmer.fail = errors.New("write failed")
	p := ProxyCore{Engine: e, Authorizer: auth(true), Forwarder: &forward{answer: r}, MaxRecords: 10}
	if answer, err := p.Resolve(context.Background(), Exchange{Endpoint: "pod", Lifetime: "uid-1", WireQuery: q}); err == nil || answer != nil {
		t.Fatal("positive response released before programming")
	}
}
