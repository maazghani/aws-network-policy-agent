//go:build linux && fqdn_integration

package fqdn_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"golang.org/x/sys/unix"
)

func TestKernelEnforcement(t *testing.T) {
	f := newFixture(t)
	allowed, denied := uint32(0), uint32(2)
	check := func(protocol uint8, port uint16, flags uint8, want uint32) {
		t.Helper()
		got := f.packetVerdict(f.pod, f.target, protocol, 32000, port, flags, f.ifindex)
		if got != want {
			t.Fatalf("protocol %d port %d flags %02x: TC verdict %d, want %d", protocol, port, flags, got, want)
		}
	}

	t.Run("no grant", func(t *testing.T) { check(17, 443, 0, denied); check(6, 443, 2, denied) })
	t.Run("UDP range and cross endpoint isolation", func(t *testing.T) {
		f.grant(f.target, 17, 443, 445, bootNS(t)+uint64(time.Minute))
		check(17, 443, 0, allowed)
		check(17, 445, 0, allowed)
		check(17, 446, 0, denied)
		check(6, 443, 2, denied)
		other := *f
		other.ifindex = 1
		other.lifetime = 200
		other.endpoint(3)
		if got := f.packetVerdict(f.pod, f.target, 17, 32000, 443, 0, 1); got != denied {
			t.Fatalf("sibling endpoint inherited grant: %d", got)
		}
	})
	t.Run("expired UDP reused tuple", func(t *testing.T) { f.grant(f.target, 17, 443, 445, bootNS(t)-1); check(17, 443, 0, denied) })
	t.Run("fresh SYN cannot reuse expired flow", func(t *testing.T) {
		f.grant(f.target, 6, 443, 443, bootNS(t)+uint64(time.Minute))
		check(6, 443, 2, allowed)
		f.grant(f.target, 6, 443, 443, bootNS(t)-1)
		check(6, 443, 2, denied)
	})
	t.Run("generation invalidates old grants", func(t *testing.T) {
		f.grant(f.target, 17, 443, 443, bootNS(t)+uint64(time.Minute))
		check(17, 443, 0, allowed)
		f.generation++
		f.endpoint(3)
		check(17, 443, 0, denied)
	})
	t.Run("lifetime reuse invalidates grants", func(t *testing.T) {
		f.grant(f.target, 17, 443, 443, bootNS(t)+uint64(time.Minute))
		check(17, 443, 0, allowed)
		f.lifetime++
		f.endpoint(3)
		check(17, 443, 0, denied)
	})
	t.Run("Admin deny overrides namespace grant", func(t *testing.T) {
		f.grant(f.target, 17, 443, 443, bootNS(t)+uint64(time.Minute))
		check(17, 443, 0, allowed)
		ip := address(f.target)
		mask := uint32(128)
		if f.family == 4 {
			ip = ip[:4]
			mask = 32
		}
		key := append(u32(mask), ip...)
		value := make([]byte, 24*16)
		binary.NativeEndian.PutUint32(value, 254)
		binary.NativeEndian.PutUint32(value[4:], 100) // Admin priority 10, deny.
		f.update("cp_egress_map", key, value)
		check(17, 443, 0, denied)
		binary.NativeEndian.PutUint32(value[4:], 102) // Admin pass restores namespace evaluation.
		f.update("cp_egress_map", key, value)
		check(17, 443, 0, allowed)
	})
	t.Run("source spoof is rejected before shared static allow", func(t *testing.T) {
		f.static(f.target, 254, 0)
		if got := f.packetVerdict(f.resolver, f.target, 17, 32000, 443, 0, f.ifindex); got != denied {
			t.Fatalf("spoofed source admitted: %d", got)
		}
	})
	t.Run("socket steering and ingress isolation", func(t *testing.T) { f.steering(t) })
}

func (f *fixture) proxyReady(ready uint32) {
	v := make([]byte, 16)
	binary.NativeEndian.PutUint32(v, 1053)
	binary.NativeEndian.PutUint32(v[4:], fqdn.DefaultDNSMark)
	binary.NativeEndian.PutUint32(v[8:], ready)
	binary.NativeEndian.PutUint32(v[12:], fqdn.DNSReplyMark)
	f.update("fqdn_proxy", u32(0), v)
}

func (f *fixture) steering(t *testing.T) {
	family := fmt.Sprint(f.family)
	// Baseline is a real reachable resolver. Both directions still use the
	// production static datapath and conntrack; no denial can pass on NXDOMAIN.
	f.static(f.resolver, 254, 53)
	f.endpoint(0)
	baseline := map[string]probeResult{}
	for _, network := range []string{"udp", "tcp"} {
		result := f.probe(network+family, f.resolver, 53, 40)
		if !result.Success {
			t.Fatalf("controlled resolver is not reachable for baseline %s: %+v", network, result)
		}
		baseline[network] = result
	}
	f.endpoint(3)
	f.proxyReady(0)
	for _, network := range []string{"udp", "tcp"} {
		if result := f.probe(network+family, f.resolver, 53, 1); result.Success {
			t.Fatalf("selected DNS bypassed missing plumbing for %s", network)
		}
	}

	udp, err := fqdn.ListenTransparentUDP(context.Background(), f.family, 1053)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := fqdn.ListenTransparentTCP(context.Background(), f.family, 1053)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	cleanup,err:=fqdn.NewFQDNSteeringIntegration(f.family,fqdn.DefaultDNSMark,20153,1053)
	if err!=nil{t.Fatal(err)}
	defer func(){if err:=cleanup();err!=nil{t.Errorf("host steering cleanup: %v",err)}}()
	errors := make(chan error, 100)
	go f.serveTransparentUDP(udp, errors)
	go f.serveTransparentTCP(tcp, errors)
	f.proxyReady(1)

	// Remove transport authorization while sockets are present. Neither a UDP
	// query nor a TCP SYN may reach the listener simply because an ANP exists.
	ip := address(f.resolver)
	mask := uint32(128)
	if f.family == 4 {
		ip = ip[:4]
		mask = 32
	}
	key := append(u32(mask), ip...)
	f.update("egress_map", key, make([]byte, 24*12))
	for _, network := range []string{"udp", "tcp"} {
		if result := f.probe(network+family, f.resolver, 53, 1); result.Success || (network=="tcp"&&result.Connected) {
			t.Fatalf("transport-denied resolver admitted for %s", network)
		}
	}
	f.static(f.resolver, 254, 53)
	for _, network := range []string{"udp", "tcp"} {
		result := f.probe(network+family, f.resolver, 53, 40)
		if !result.Success {
			select {
			case err := <-errors:
				t.Fatalf("%s proxy: %v; pod: %+v", network, err, result)
			default:
				t.Fatalf("steered %s failed: %+v", network, result)
			}
		}
		if result.Remote != net.JoinHostPort(f.resolver.String(), "53") {
			t.Fatalf("resolver tuple changed: %+v", result)
		}
		baseP99, proxyP99 := percentile(baseline[network].LatenciesNS, 99), percentile(result.LatenciesNS, 99)
		t.Logf("MEASUREMENT family=%d transport=%s samples=%d baseline_p99_ns=%d proxy_p99_ns=%d ratio=%.3f (feasibility echo transport, not production DNS performance budget)", f.family, network, len(result.LatenciesNS), baseP99, proxyP99, float64(proxyP99)/float64(baseP99))
	}
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
	// Exercise abrupt listener loss with a stale kernel ready bit, as on crash.
	_ = udp.Close()
	_ = tcp.Close()
	for _, network := range []string{"udp", "tcp"} {
		if result := f.probe(network+family, f.resolver, 53, 1); result.Success {
			t.Fatalf("selected DNS bypassed proxy crash for %s", network)
		}
	}
	f.proxyReady(0)
}

func percentile(values []int64, p int) int64 {
	values = append([]int64(nil), values...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := (len(values)*p+99)/100 - 1
	if index < 0 {
		return 0
	}
	return values[index]
}

func (f *fixture) serveTransparentTCP(listener net.Listener, failures chan<- error) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer client.Close()
			if client.LocalAddr().String() != net.JoinHostPort(f.resolver.String(), "53") {
				failures <- fmt.Errorf("TCP original destination lost: %s", client.LocalAddr())
				return
			}
			if err := f.attest(client.RemoteAddr().String(), 6); err != nil {
				failures <- err
				return
			}
			upstream, err := net.DialTimeout(fmt.Sprintf("tcp%d", f.family), client.LocalAddr().String(), time.Second)
			if err != nil {
				failures <- err
				return
			}
			defer upstream.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
			go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
			_, _ = io.Copy(client, upstream)
		}()
	}
}

func (f *fixture) serveTransparentUDP(listener *net.UDPConn, failures chan<- error) {
	buffer, oob := make([]byte, 65535), make([]byte, 256)
	for {
		n, on, _, source, err := listener.ReadMsgUDP(buffer, oob)
		if err != nil {
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:on])
		if err != nil {
			failures <- err
			continue
		}
		var destination netip.AddrPort
		for _, msg := range messages {
			if f.family == 4 && msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR && len(msg.Data) >= 8 {
				destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(msg.Data[4:8])), binary.BigEndian.Uint16(msg.Data[2:4]))
			}
			if f.family == 6 && msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR && len(msg.Data) >= 24 {
				destination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(msg.Data[8:24])), binary.BigEndian.Uint16(msg.Data[2:4]))
			}
		}
		if destination != netip.AddrPortFrom(f.resolver, 53) {
			failures <- fmt.Errorf("UDP original destination lost: %v", destination)
			continue
		}
		if err := f.attest(source.String(), 17); err != nil {
			failures <- err
			continue
		}
		upstream, err := net.DialTimeout(fmt.Sprintf("udp%d", f.family), destination.String(), time.Second)
		if err != nil {
			failures <- err
			continue
		}
		_ = upstream.SetDeadline(time.Now().Add(time.Second))
		_, err = upstream.Write(buffer[:n])
		if err == nil {
			n, err = upstream.Read(buffer)
		}
		_ = upstream.Close()
		if err != nil {
			failures <- err
			continue
		}
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			var result error
			err := raw.Control(func(fd uintptr) {
				if result=unix.SetsockoptInt(int(fd),unix.SOL_SOCKET,unix.SO_MARK,int(fqdn.DNSReplyMark));result!=nil{return}
				if f.family == 4 {
					result = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				} else {
					result = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				}
			})
			if err != nil {
				return err
			}
			return result
		}}
		reply, err := lc.ListenPacket(context.Background(), fmt.Sprintf("udp%d", f.family), destination.String())
		if err != nil {
			failures <- err
			continue
		}
		_, err = reply.WriteTo(buffer[:n], source)
		_ = reply.Close()
		if err != nil {
			failures <- err
		}
	}
}

// Verify kernel provenance, including the reusable interface and current pod
// lifetime. A source address supplied directly to a listener is insufficient.
func (f *fixture) attest(source string, protocol uint8) error {
	peer, err := netip.ParseAddrPort(source)
	if err != nil {
		return err
	}
	if peer.Addr().Unmap() != f.pod {
		return fmt.Errorf("wrong originating IP %v", peer)
	}
	key := make([]byte, 40)
	copy(key, address(f.pod))
	copy(key[16:], address(f.resolver))
	binary.NativeEndian.PutUint16(key[32:], peer.Port())
	binary.NativeEndian.PutUint16(key[34:], 53)
	key[36] = protocol
	key[37] = byte(f.family)
	value, err := f.lookup("fqdn_dns", key, 32)
	if err != nil {
		return fmt.Errorf("missing trusted DNS tuple: %w", err)
	}
	if binary.NativeEndian.Uint64(value) != f.lifetime || binary.NativeEndian.Uint64(value[8:]) != f.generation || binary.NativeEndian.Uint32(value[24:]) != f.ifindex {
		return fmt.Errorf("wrong DNS tuple provenance %x", value)
	}
	return nil
}
