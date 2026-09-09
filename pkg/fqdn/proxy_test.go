//go:build linux

package fqdn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsTestBridge struct {
	endpoint Endpoint
	err      error
}

func (b *dnsTestBridge) LookupDNSIdentity(context.Context, netip.AddrPort, netip.AddrPort, uint8) (Endpoint, error) {
	return b.endpoint, b.err
}
func (b *dnsTestBridge) SetProxyReady(context.Context, uint32, uint32, bool) error { return nil }

func dnsProxyFixture(t *testing.T) (*Proxy, *testBackend, Endpoint) {
	t.Helper()
	engine, backend, _, ep := stateFixture(t)
	engine.config.Clock = BootClock{}
	proxy, err := NewProxy(engine, &dnsTestBridge{endpoint: ep}, ProxyConfig{Port: 1053, Family: 4, MaxPending: 2, MaxPendingBytes: 2 * (maxDNSMessage + 100), MaxTCPSockets: 2, ExchangeTimeout: time.Second, TCPIdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return proxy, backend, ep
}

func TestDNSProxyNeverPublishesBeforeAllEffectiveAddresses(t *testing.T) {
	p, backend, ep := dnsProxyFixture(t)
	q, r := dnsTestExchange(t, "api.example.com.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("api.example.com.", 60, [4]byte{192, 0, 2, 1}), dnsTestA("api.example.com.", 60, [4]byte{192, 0, 2, 2})}, nil)
	source, resolver := netip.AddrPortFrom(ep.IP, 42000), netip.MustParseAddrPort("10.0.0.2:53")
	backend.deny = netip.MustParseAddr("192.0.2.2")
	var writes atomic.Int32
	write := func(context.Context, []byte) error { writes.Add(1); return nil }
	if err := p.publish(context.Background(), ep, source, resolver, 17, q, r, write); err == nil || writes.Load() != 0 {
		t.Fatal("partially denied response escaped")
	}
	backend.deny = netip.Addr{}
	entered, allow := make(chan struct{}), make(chan struct{})
	backend.replace = func(ctx context.Context) error {
		close(entered)
		select {
		case <-allow:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	completed := make(chan error, 1)
	go func() { completed <- p.publish(context.Background(), ep, source, resolver, 17, q, r, write) }()
	<-entered
	if writes.Load() != 0 {
		t.Fatal("positive bytes preceded map completion")
	}
	close(allow)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("successful response not released")
	}
	backend.replace = func(context.Context) error { return errors.New("active map write failed") }
	if err := p.publish(context.Background(), ep, source, resolver, 17, q, r, write); err == nil || writes.Load() != 1 {
		t.Fatal("duplicate response skipped checked programming")
	}
}

func TestDNSProxyAuthenticatesAtPublicationAndHonorsInformationalNames(t *testing.T) {
	p, backend, ep := dnsProxyFixture(t)
	q, r := dnsTestExchange(t, "other.invalid.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("other.invalid.", 60, [4]byte{192, 0, 2, 1})}, nil)
	source, resolver := netip.AddrPortFrom(ep.IP, 42000), netip.MustParseAddrPort("10.0.0.2:53")
	writes := 0
	write := func(context.Context, []byte) error { writes++; return nil }
	if err := p.publish(context.Background(), ep, source, resolver, 17, q, r, write); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || len(backend.grants[ep.Lifetime]) != 0 {
		t.Fatal("informational name learned authority")
	}
	p.bridge.(*dnsTestBridge).endpoint.UID = "reused-address-other-pod"
	if err := p.publish(context.Background(), ep, source, resolver, 17, q, r, write); err == nil || writes != 1 {
		t.Fatal("untrusted lifetime published")
	}
	if _, err := p.authenticate(context.Background(), source, netip.AddrPortFrom(resolver.Addr(), 1053), 17); err == nil {
		t.Fatal("direct listener access impersonated DNS interception")
	}
}

func TestDNSProxyWireAndConcurrencyBounds(t *testing.T) {
	p, _, _ := dnsProxyFixture(t)
	if !p.reserve(maxDNSMessage+100) || !p.reserve(maxDNSMessage+100) {
		t.Fatal("unexpected reservation rejection")
	}
	if p.reserve(1) {
		t.Fatal("pending limit exceeded")
	}
	p.release(maxDNSMessage + 100)
	p.release(maxDNSMessage + 100)
	if p.reserve(p.config.MaxPendingBytes + 1) {
		t.Fatal("wire byte limit exceeded")
	}
	stats := p.Stats()
	if stats.Pending != 0 || stats.PendingBytes != 0 || stats.CapacityFailures != 2 {
		t.Fatalf("bad reservation accounting %+v", stats)
	}
}

func TestDNSProxyUpstreamUDPUsesRequestedResolverAndCancellation(t *testing.T) {
	p, _, _ := dnsProxyFixture(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	q, r := dnsTestExchange(t, "api.example.com.", dnsmessage.TypeA, []dnsmessage.Resource{dnsTestA("api.example.com.", 60, [4]byte{192, 0, 2, 1})}, nil)
	go func() {
		buffer := make([]byte, 2048)
		_, source, err := listener.ReadFromUDPAddrPort(buffer)
		if err == nil {
			_, _ = listener.WriteToUDPAddrPort(r, source)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := p.exchangeUDP(ctx, listener.LocalAddr().(*net.UDPAddr).AddrPort(), q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDNSAnswer(q, got, 0, 4); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := p.exchangeUDP(cancelled, listener.LocalAddr().(*net.UDPAddr).AddrPort(), q); err == nil {
		t.Fatal("cancelled upstream exchange succeeded")
	}
}
