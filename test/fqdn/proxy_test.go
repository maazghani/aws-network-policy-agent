//go:build linux && fqdn_integration

package fqdn_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
)

// Controlled resolver wire generation is intentionally small and independent
// from the production parser. All other requests remain the transport echo.
func dnsFixtureAnswer(request []byte, udp bool) []byte {
	if len(request) < 12 || binary.BigEndian.Uint16(request[4:]) != 1 || request[2]&0x80 != 0 {
		return append([]byte(nil), request...)
	}
	end := 12
	var labels []string
	for end < len(request) && request[end] != 0 {
		n := int(request[end])
		end++
		if n > 63 || end+n > len(request) {
			return nil
		}
		labels = append(labels, string(request[end:end+n]))
		end += n
	}
	if end+5 > len(request) {
		return nil
	}
	name := strings.Join(labels, ".")
	end += 5
	response := append([]byte(nil), request[:end]...)
	binary.BigEndian.PutUint16(response[2:], 0x8180)
	binary.BigEndian.PutUint16(response[6:], 0)
	if name == "negative.allowed.test" {
		response[3] = 0x83
		return response
	}
	if name == "truncated.allowed.test" && udp {
		response[2] |= 2
		return response
	}
	addr, err := netip.ParseAddr(os.Getenv("FQDN_DNS_ANSWER"))
	if err != nil {
		return nil
	}
	offset := map[string]int{"delayed.allowed.test": 1, "failed.allowed.test": 2, "deleted.allowed.test": 3, "detached.allowed.test": 4, "unmatched.test": 5, "multi.allowed.test": 6}[name]
	for i := 0; i < offset; i++ {
		addr = addr.Next()
	}
	var rdata []byte
	kind := uint16(1)
	if addr.Is4() {
		a := addr.As4()
		rdata = a[:]
	} else {
		kind = 28
		a := addr.As16()
		rdata = a[:]
	}
	if binary.BigEndian.Uint16(request[end-4:]) != kind {
		return response
	}
	answer := make([]byte, 12)
	answer[0], answer[1] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(answer[2:], kind)
	binary.BigEndian.PutUint16(answer[4:], 1)
	binary.BigEndian.PutUint32(answer[6:], 2)
	binary.BigEndian.PutUint16(answer[10:], uint16(len(rdata)))
	answer = append(answer, rdata...)
	binary.BigEndian.PutUint16(response[6:], 1)
	response = append(response, answer...)
	if name == "multi.allowed.test" {
		second := append([]byte(nil), answer...)
		second[len(second)-1]++
		response = append(response, second...)
		binary.BigEndian.PutUint16(response[6:], 2)
	}
	return response
}

func serveDNSOrEchoTCP(conn net.Conn) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	if bytes.Equal(header[:], []byte("fq")) {
		_, _ = conn.Write(header[:])
		_, _ = io.Copy(conn, conn)
		return
	}
	for {
		length := int(binary.BigEndian.Uint16(header[:]))
		if length < 12 {
			return
		}
		request := make([]byte, length)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		response := dnsFixtureAnswer(request, false)
		binary.BigEndian.PutUint16(header[:], uint16(len(response)))
		if _, err := conn.Write(append(header[:], response...)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
	}
}

type dnsResult struct {
	Positive                  bool
	RCode, Answers            int
	ElapsedNS, ReceivedUnixNS int64
	Error                     string
	Truncated                 bool
}

func TestDNSFixtureEncoding(t *testing.T) {
	for _, family := range []int{4, 6} {
		answer := "198.18.0.80"
		kind := uint16(1)
		if family == 6 {
			answer = "fd00:2::80"
			kind = 28
		}
		t.Setenv("FQDN_DNS_ANSWER", answer)
		for _, sample := range []struct {
			name      string
			udp       bool
			addresses int
		}{{"allowed.test", true, 1}, {"multi.allowed.test", true, 2}, {"truncated.allowed.test", true, 0}, {"truncated.allowed.test", false, 1}, {"negative.allowed.test", true, 0}, {"unmatched.test", true, 1}} {
			request := make([]byte, 12)
			binary.BigEndian.PutUint16(request, 1)
			binary.BigEndian.PutUint16(request[2:], 0x0100)
			binary.BigEndian.PutUint16(request[4:], 1)
			request = append(request, benchName(sample.name)...)
			request = binary.BigEndian.AppendUint16(request, kind)
			request = binary.BigEndian.AppendUint16(request, 1)
			parsed, err := fqdn.ParseDNSAnswer(request, dnsFixtureAnswer(request, sample.udp), 1_000_000_000, family)
			if err != nil {
				t.Fatalf("fixture IPv%d %s: %v", family, sample.name, err)
			}
			if parsed.Question != sample.name || len(parsed.Observations) != sample.addresses {
				t.Fatalf("fixture IPv%d %s encoded wrong question/address set: %+v", family, sample.name, parsed)
			}
		}
	}
}

func probeDNS() int {
	result := dnsResult{}
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(result) }()
	network := os.Getenv("FQDN_PROBE_NETWORK")
	start := time.Now()
	conn, err := net.DialTimeout(network, os.Getenv("FQDN_PROBE_ADDRESS"), time.Second)
	if err != nil {
		result.Error = err.Error()
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request, 0x1729)
	binary.BigEndian.PutUint16(request[2:], 0x0100)
	binary.BigEndian.PutUint16(request[4:], 1)
	for _, label := range strings.Split(os.Getenv("FQDN_DNS_QUESTION"), ".") {
		request = append(request, byte(len(label)))
		request = append(request, label...)
	}
	request = append(request, 0)
	kind := uint16(1)
	if strings.HasSuffix(network, "6") {
		kind = 28
	}
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail, kind)
	binary.BigEndian.PutUint16(tail[2:], 1)
	request = append(request, tail...)
	// Two queries share a TCP socket, exercising original tuple preservation
	// after the SYN lookup has become an established-socket lookup.
	count := 1
	if strings.HasPrefix(network, "tcp") {
		count = 2
	}
	for i := 0; i < count; i++ {
		wire := request
		if strings.HasPrefix(network, "tcp") {
			header := make([]byte, 2)
			binary.BigEndian.PutUint16(header, uint16(len(wire)))
			wire = append(header, wire...)
		}
		if _, err = conn.Write(wire); err != nil {
			result.Error = err.Error()
			return 0
		}
		response := make([]byte, 65535)
		var n int
		if strings.HasPrefix(network, "tcp") {
			var header [2]byte
			if _, err = io.ReadFull(conn, header[:]); err == nil {
				n = int(binary.BigEndian.Uint16(header[:]))
				_, err = io.ReadFull(conn, response[:n])
			}
		} else {
			n, err = conn.Read(response)
		}
		if err != nil {
			result.Error = err.Error()
			return 0
		}
		if n < 12 || binary.BigEndian.Uint16(response) != 0x1729 {
			result.Error = "invalid fixture DNS response"
			return 0
		}
		result.ReceivedUnixNS = time.Now().UnixNano()
		result.ElapsedNS = time.Since(start).Nanoseconds()
		result.RCode = int(response[3] & 15)
		result.Answers = int(binary.BigEndian.Uint16(response[6:]))
		result.Truncated = response[2]&2 != 0
		result.Positive = result.RCode == 0 && result.Answers > 0
	}
	return 0
}

func (f *fixture) dns(network, name string) dnsResult {
	f.t.Helper()
	exe, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", f.ns, exe)
	cmd.Env = append(os.Environ(), "FQDN_TEST_HELPER=dns", "FQDN_PROBE_NETWORK="+network, "FQDN_PROBE_ADDRESS="+net.JoinHostPort(f.resolver.String(), "53"), "FQDN_DNS_QUESTION="+name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("DNS client infrastructure failure: %v %s", err, out)
	}
	var result dnsResult
	if err = json.Unmarshal(out, &result); err != nil {
		f.t.Fatalf("DNS client result: %v %s", err, out)
	}
	return result
}

// Faults wrap a real backend. Successful operations and all map/attachment
// checks execute production code against real kernel maps; only the selected
// failure or scheduling boundary is injected.
type faultBackend struct {
	*ebpf.FQDNBackend
	mode      atomic.Int32
	committed atomic.Int64
	entered   chan struct{}
	detach    func() error
}

func (b *faultBackend) Replace(ctx context.Context, ep fqdn.Endpoint, revision uint64, grants []fqdn.Grant) error {
	switch b.mode.Load() {
	case 1:
		select {
		case b.entered <- struct{}{}:
		default:
		}
		select {
		case <-time.After(120 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	case 2:
		return errors.New("injected checked map write failure")
	case 3:
		select {
		case b.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	case 4:
		if err := b.detach(); err != nil {
			return err
		}
	}
	err := b.FQDNBackend.Replace(ctx, ep, revision, grants)
	if err == nil {
		b.committed.Store(time.Now().UnixNano())
	}
	return err
}

func (f *fixture) fullProxy(t *testing.T) {
	// Clear the independent static target allow installed by the spoof test.
	ip := address(f.target)
	mask := uint32(128)
	if f.family == 4 {
		ip = ip[:4]
		mask = 32
	}
	f.update("egress_map", append(u32(mask), ip...), make([]byte, 24*12))
	globals := map[string]goebpfmaps.BpfMap{}
	for name, m := range f.maps {
		globals["/sys/fs/bpf/globals/aws/maps/global_"+name] = m
	}
	programs := ebpf.FQDNPrograms{}
	for name, p := range f.progs {
		if strings.Contains(name, "egress") {
			programs.Egress = p
		} else if strings.Contains(name, "ingress") {
			programs.Ingress = p
		}
	}
	backend, err := ebpf.NewFQDNIntegrationBackend(globals, map[string]ebpf.FQDNPrograms{"fqdn-test": programs})
	if err != nil {
		t.Fatal(err)
	}
	faults := &faultBackend{FQDNBackend: backend, entered: make(chan struct{}, 1), detach: func() error { return tc.New([]string{"eni"}).TCIngressDetach(f.host) }}
	engine, err := fqdn.NewEngine(fqdn.Config{Limits: fqdn.Limits{MaxEndpoints: 10, MaxRulesPerEndpoint: 10, MaxObservationsPerEndpoint: 100, MaxAddressesPerEndpoint: 100, MaxGrantsPerAddress: 24, MaxGrantsPerEndpoint: 100, MaxTotalObservations: 1000, MaxTotalGrants: 1000}, PublicationTimeout: 500 * time.Millisecond}, faults)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := engine.Enroll(context.Background(), fqdn.Endpoint{UID: "fqdn-client-uid", Name: "client", Namespace: "fqdn-namespace", PodIdentifier: "fqdn-test", IP: f.pod, IfIndex: f.ifindex}, fqdn.Snapshot{Rules: []fqdn.Rule{{Owner: "fqdn-policy", Name: "allowed.test", Ports: []fqdn.PortRange{{Protocol: 6, StartPort: 443, EndPort: 443}}}, {Owner: "fqdn-policy", Name: "*.allowed.test", Ports: []fqdn.PortRange{{Protocol: 6, StartPort: 443, EndPort: 443}}}}})
	if err != nil {
		t.Fatal(err)
	}
	f.lifetime = ep.Lifetime
	proxy, err := fqdn.NewProxy(engine, backend, fqdn.ProxyConfig{Family: f.family, Port: 1053, MaxPending: 16, MaxPendingBytes: 2 * 65535 * 16, MaxTCPSockets: 16, ExchangeTimeout: 750 * time.Millisecond, TCPIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			t.Errorf("proxy close: %v", err)
		}
	}()
	checkPositive := func(network, name string) {
		t.Helper()
		result := f.dns(network+fmt.Sprint(f.family), name)
		if !result.Positive {
			t.Fatalf("expected positive %s %s: %+v", network, name, result)
		}
		if result.ReceivedUnixNS < faults.committed.Load() {
			t.Fatalf("premature positive response: %+v committed=%d", result, faults.committed.Load())
		}
		if got := f.packetVerdict(f.pod, f.target, 6, 32200, 443, 2, f.ifindex); got != 0 {
			t.Fatalf("positive DNS preceded effective datapath admission: %d", got)
		}
	}
	checkPositive("udp", "allowed.test")
	checkPositive("udp", "allowed.test")
	checkPositive("tcp", "allowed.test")
	truncated := f.dns(fmt.Sprintf("udp%d", f.family), "truncated.allowed.test")
	if !truncated.Truncated || truncated.Positive {
		t.Fatalf("UDP truncation contract: %+v", truncated)
	}
	checkPositive("tcp", "truncated.allowed.test")
	unmatched := f.dns(fmt.Sprintf("udp%d", f.family), "unmatched.test")
	if !unmatched.Positive {
		t.Fatalf("nonmatching answer should remain informational: %+v", unmatched)
	}
	unmatchedIP := f.target
	for i := 0; i < 5; i++ {
		unmatchedIP = unmatchedIP.Next()
	}
	if got := f.packetVerdict(f.pod, unmatchedIP, 6, 32201, 443, 2, f.ifindex); got != 2 {
		t.Fatalf("nonmatching answer created permission: %d", got)
	}
	deniedIP := unmatchedIP.Next().Next()
	deniedBytes := address(deniedIP)
	if f.family == 4 {
		deniedBytes = deniedBytes[:4]
	}
	admin := make([]byte, 24*16)
	binary.NativeEndian.PutUint32(admin, 254)
	binary.NativeEndian.PutUint32(admin[4:], 100)
	f.update("cp_egress_map", append(u32(mask), deniedBytes...), admin)
	multi := f.dns(fmt.Sprintf("udp%d", f.family), "multi.allowed.test")
	if multi.Positive || multi.RCode != 2 {
		t.Fatalf("partially denied multi-address answer did not fail with SERVFAIL: %+v", multi)
	}
	faults.mode.Store(1)
	delayed := f.dns(fmt.Sprintf("udp%d", f.family), "delayed.allowed.test")
	if !delayed.Positive || delayed.ElapsedNS < int64(120*time.Millisecond) || delayed.ReceivedUnixNS < faults.committed.Load() {
		t.Fatalf("response escaped delayed publication: %+v", delayed)
	}
	faults.mode.Store(2)
	failed := f.dns(fmt.Sprintf("udp%d", f.family), "failed.allowed.test")
	if failed.Positive || failed.RCode != 2 {
		t.Fatalf("failed map write did not produce SERVFAIL: %+v", failed)
	}
	faults.mode.Store(4)
	detached := f.dns(fmt.Sprintf("udp%d", f.family), "detached.allowed.test")
	if detached.Positive || detached.RCode != 2 {
		t.Fatalf("attachment loss did not produce SERVFAIL: %+v", detached)
	}
	if err = tc.New([]string{"eni"}).TCIngressAttach(f.host, f.egressFD, "fqdn-egress"); err != nil {
		t.Fatal(err)
	}
	faults.mode.Store(3)
	select {
	case <-faults.entered:
	default:
	}
	deletedResult := make(chan dnsResult, 1)
	go func() { deletedResult <- f.dns(fmt.Sprintf("udp%d", f.family), "deleted.allowed.test") }()
	select {
	case <-faults.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS never reached deletion boundary")
	}
	if err = engine.Delete(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-deletedResult:
		if result.Positive {
			t.Fatalf("positive response after endpoint deletion: %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deleted DNS exchange exceeded bound")
	}
	t.Log("ASSERTION zero premature positive responses for delayed writes, failed writes, missing attachment, duplicate answers, and endpoint deletion; real production proxy/engine/backend/TC")
}
