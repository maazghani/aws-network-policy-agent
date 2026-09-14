package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"golang.org/x/sys/unix"
)

type fqdnTestMap struct {
	entries             map[string][]byte
	failPut, failDelete bool
}

func (m *fqdnTestMap) Get(k, v []byte) error {
	raw, ok := m.entries[string(k)]
	if !ok {
		return unix.ENOENT
	}
	copy(v, raw)
	return nil
}
func (m *fqdnTestMap) Put(k, v []byte) error {
	if m.failPut {
		return errors.New("injected write failure")
	}
	m.entries[string(k)] = append([]byte(nil), v...)
	return nil
}
func (m *fqdnTestMap) Delete(k []byte) error {
	if m.failDelete {
		return errors.New("injected deletion failure")
	}
	if _, ok := m.entries[string(k)]; !ok {
		return unix.ENOENT
	}
	delete(m.entries, string(k))
	return nil
}
func (m *fqdnTestMap) Keys() ([]string, error) {
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	return keys, nil
}
func (m *fqdnTestMap) ID() uint32 { return 1 }
func fqdnTestBackend() (*FQDNBackend, fqdn.Endpoint) {
	b := &FQDNBackend{gate: make(chan struct{}, 1), maps: map[string]fqdnMap{}, bound: map[uint32]*fqdnBinding{}, verify: func(context.Context, fqdn.Endpoint) error { return nil }, now: func() (uint64, error) { return 100, nil }, readPolicy: func(fqdn.Endpoint, netip.Addr) (fqdnStaticPolicy, error) {
		return fqdnStaticPolicy{state: uint8(POLICIES_APPLIED)}, nil
	}}
	for _, name := range []string{"fqdn_endpoints", "fqdn_grants", "fqdn_flows", "fqdn_dns", "fqdn_proxy"} {
		b.maps[name] = &fqdnTestMap{entries: map[string][]byte{}}
	}
	ep := fqdn.Endpoint{UID: "pod-uid", PodIdentifier: "shared", Namespace: "test", Name: "pod", IfIndex: 12, IP: netip.MustParseAddr("10.0.0.2"), Lifetime: 123}
	b.bound[ep.IfIndex] = &fqdnBinding{endpoint: ep, grants: map[fqdnGrantKey]fqdnGrantValue{}, flowNames: map[fqdnFlowKey][]string{}}
	return b, ep
}
func fqdnTestGrant() fqdn.Grant {
	return fqdn.Grant{Address: netip.MustParseAddr("203.0.113.10"), Protocol: 6, StartPort: 443, EndPort: 443, Deadline: 200, Names: []string{"allowed.example"}}
}
func TestFQDNABILayout(t *testing.T) {
	got := []uintptr{unsafe.Sizeof(fqdnEndpointValue{}), unsafe.Sizeof(fqdnGrantKey{}), unsafe.Sizeof(fqdnGrantValue{}), unsafe.Sizeof(fqdnTuple{}), unsafe.Sizeof(fqdnDNSValue{}), unsafe.Sizeof(fqdnProxyValue{}), unsafe.Sizeof(fqdnFlowKey{}), unsafe.Sizeof(fqdnFlowValue{})}
	want := []uintptr{40, 32, 384, 40, 32, 16, 48, 40}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kernel ABI: got %v want %v", got, want)
	}
	if fqdnAddress(netip.MustParseAddr("192.0.2.1")) != [16]byte{192, 0, 2, 1} {
		t.Fatal("IPv4 bytes must not use IPv4-mapped IPv6 representation")
	}
}
func TestFQDNFailedReplacementStaysRestrictiveAndRetries(t *testing.T) {
	b, ep := fqdnTestBackend()
	g := fqdnTestGrant()
	ctx := context.Background()
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal(err)
	}
	m := b.maps["fqdn_grants"].(*fqdnTestMap)
	m.failDelete = true
	if err := b.Replace(ctx, ep, 2, nil); err == nil {
		t.Fatal("failed deletion reported success")
	}
	var endpoint fqdnEndpointValue
	_ = b.maps["fqdn_endpoints"].Get(fqdnUint32(ep.IfIndex), fqdnBytes(&endpoint))
	if endpoint.Flags&fqdnEndpointReady != 0 {
		t.Fatal("failed revocation left old grants active")
	}
	if len(b.bound[ep.IfIndex].grants) != 1 {
		t.Fatal("failed deletion was lost from retry state")
	}
	m.failDelete = false
	if err := b.Replace(ctx, ep, 2, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.entries) != 0 {
		t.Fatal("retry retained revoked grant")
	}
}
func TestFQDNCheckedAdmission(t *testing.T) {
	for _, failure := range []string{"attachment", "write", "readback", "expiry", "admin-deny", "identity", "staging"} {
		t.Run(failure, func(t *testing.T) {
			b, ep := fqdnTestBackend()
			g := fqdnTestGrant()
			ctx := context.Background()
			if failure == "write" {
				b.maps["fqdn_grants"].(*fqdnTestMap).failPut = true
				if b.Replace(ctx, ep, 1, []fqdn.Grant{g}) == nil {
					t.Fatal("write failure admitted")
				}
				return
			}
			if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "attachment":
				b.verify = func(context.Context, fqdn.Endpoint) error { return errors.New("TC detached") }
			case "readback":
				b.maps["fqdn_grants"].(*fqdnTestMap).entries = map[string][]byte{}
			case "expiry":
				b.now = func() (uint64, error) { return 201, nil }
			case "admin-deny":
				b.readPolicy = func(fqdn.Endpoint, netip.Addr) (fqdnStaticPolicy, error) {
					p := fqdnStaticPolicy{state: 0}
					p.cluster[0] = fqdnClusterPort{Protocol: 254, Priority: 10}
					return p, nil
				}
			case "identity":
				ep.UID = "recreated"
			case "staging":
				if err := b.BeginFQDNPolicyUpdate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if b.Check(ctx, ep, 1, []fqdn.Grant{g}) == nil {
				t.Fatal("invalid admission succeeded")
			}
		})
	}
}
func TestFQDNIndependentNamespacePermissionAndAdminOrder(t *testing.T) {
	p := fqdnStaticPolicy{state: 0}
	if !p.verdict(6, 443, true) || p.verdict(6, 443, false) {
		t.Fatal("dynamic grant must join namespace union")
	}
	p.cluster[0] = fqdnClusterPort{Protocol: 6, Priority: 10, Start: 443}
	if p.verdict(6, 443, true) {
		t.Fatal("Admin deny must precede dynamic grant")
	}
	p.cluster[0].Priority = 11
	if !p.verdict(6, 443, false) {
		t.Fatal("Admin allow must remain terminal")
	}
	p.cluster[0] = fqdnClusterPort{Protocol: 254, Priority: 20000}
	if !p.verdict(6, 443, true) {
		t.Fatal("namespace grant must precede Baseline deny")
	}
}
func TestFQDNWhollyDeniedRange(t *testing.T) {
	b, ep := fqdnTestBackend()
	g := fqdnTestGrant()
	g.StartPort = 400
	g.EndPort = 500
	b.readPolicy = func(fqdn.Endpoint, netip.Addr) (fqdnStaticPolicy, error) {
		p := fqdnStaticPolicy{}
		p.cluster[0] = fqdnClusterPort{Protocol: 6, Priority: 10, Start: 400, End: 499}
		return p, nil
	}
	if ok, err := b.effectiveGrant(context.Background(), ep, g); err != nil || !ok {
		t.Fatal("port 500 independently admits address", ok, err)
	}
	g.EndPort = 499
	if ok, err := b.effectiveGrant(context.Background(), ep, g); err != nil || ok {
		t.Fatal("wholly denied address must fail", ok, err)
	}
}
func TestFQDNFlowExpirySurvivalAndSelectiveRevocation(t *testing.T) {
	b, ep := fqdnTestBackend()
	g := fqdnTestGrant()
	ctx := context.Background()
	s := b.bound[ep.IfIndex]
	s.policy = fqdn.Snapshot{Rules: []fqdn.Rule{{Owner: "one", Name: "allowed.example", Ports: []fqdn.PortRange{{Protocol: 6, StartPort: 443, EndPort: 443}}}, {Owner: "two", Name: "allowed.example", Ports: []fqdn.PortRange{{Protocol: 6, StartPort: 443, EndPort: 443}}}}}
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal(err)
	}
	key := fqdnFlowKey{Lifetime: ep.Lifetime, Tuple: fqdnTuple{Source: fqdnAddress(ep.IP), Destination: fqdnAddress(g.Address), SourcePort: 45000, DestinationPort: 443, Protocol: 6, Family: 4}}
	v := fqdnFlowValue{Generation: 1, Deadline: 1000, State: 3}
	_ = b.maps["fqdn_flows"].Put(fqdnBytes(&key), fqdnBytes(&v))
	b.now = func() (uint64, error) { return 300, nil }
	if err := b.Replace(ctx, ep, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.maps["fqdn_flows"].Get(fqdnBytes(&key), fqdnBytes(&v)); err != nil || v.Generation != 1 {
		t.Fatal("DNS expiry killed established TCP", err, v)
	}
	s.policy.Rules = s.policy.Rules[1:]
	if err := b.Replace(ctx, ep, 2, nil); err != nil {
		t.Fatal(err)
	}
	_ = b.maps["fqdn_flows"].Get(fqdnBytes(&key), fqdnBytes(&v))
	if v.Generation != 2 {
		t.Fatal("overlapping surviving contributor must preserve flow")
	}
	s.policy.Rules = nil
	if err := b.Replace(ctx, ep, 3, nil); err != nil {
		t.Fatal(err)
	}
	_ = b.maps["fqdn_flows"].Get(fqdnBytes(&key), fqdnBytes(&v))
	if v.Generation != 0 {
		t.Fatal("revoked flow must leave reverse-path tombstone")
	}
}
func TestFQDNFenceCancellationAndNestedValidation(t *testing.T) {
	b, _ := fqdnTestBackend()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = b.WithFence(context.Background(), func(ctx context.Context) error {
			close(entered)
			if err := b.WithFence(ctx, func(context.Context) error { return nil }); err != nil {
				panic(err)
			}
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := b.WithFence(ctx, func(context.Context) error { t.Fatal("entered conflicting publication"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	<-done
}
func TestBulkRefreshReturnsDeletionFailure(t *testing.T) {
	m := &InMemoryBpfMap{bpfMap: &goebpfmaps.BpfMap{MapFD: 0xffffffff}, contents: map[string][]byte{"key": {1}}}
	if err := m.BulkRefresh(map[string][]byte{}); err == nil {
		t.Fatal("failed kernel delete was reported as success")
	}
	if _, ok := m.contents["key"]; !ok {
		t.Fatal("failed deletion must remain retryable")
	}
}

func TestFQDNDeleteIsIdempotentAndCannotInvalidateSuccessor(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{fqdnTestGrant()}); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, ep); err != nil {
		t.Fatal("retry failed", err)
	}
	successor := fqdnEndpointValue{Lifetime: 999, Generation: 1, Flags: fqdnEndpointSelected | fqdnEndpointReady}
	_ = b.maps["fqdn_endpoints"].Put(fqdnUint32(ep.IfIndex), fqdnBytes(&successor))
	if err := b.Delete(ctx, ep); err != nil {
		t.Fatal(err)
	}
	var after fqdnEndpointValue
	_ = b.maps["fqdn_endpoints"].Get(fqdnUint32(ep.IfIndex), fqdnBytes(&after))
	if after != successor {
		t.Fatal("old lifetime deletion modified successor")
	}
}
func TestFQDNStaticOnlyAdmissionCannotUseDynamicGrant(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	g := fqdnTestGrant()
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal(err)
	}
	g.Deadline = 0
	if err := b.CheckStatic(ctx, ep, []fqdn.Grant{g}); err == nil {
		t.Fatal("dynamic grant is not static permission")
	}
	b.readPolicy = func(fqdn.Endpoint, netip.Addr) (fqdnStaticPolicy, error) {
		p := fqdnStaticPolicy{state: 0}
		p.ports[0] = fqdnStaticPort{Protocol: 6, Start: 443}
		return p, nil
	}
	if err := b.CheckStatic(ctx, ep, []fqdn.Grant{g}); err != nil {
		t.Fatal("independent static grant should satisfy zero TTL", err)
	}
}
func TestFQDNProofNamesNeverSilentlyTruncate(t *testing.T) {
	names := []string{}
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("name-%d.example", i))
	}
	if got := appendUniqueNames(nil, names); len(got) != len(names) {
		t.Fatal("truncated surviving contributor proof")
	}
}

func TestFQDNFenceContextCannotBypassAfterPublication(t *testing.T) {
	b, _ := fqdnTestBackend()
	var saved context.Context
	if err := b.WithFence(context.Background(), func(ctx context.Context) error { saved = ctx; return nil }); err != nil {
		t.Fatal(err)
	}
	b.gate <- struct{}{}
	defer func() { <-b.gate }()
	ctx, cancel := context.WithTimeout(saved, time.Millisecond)
	defer cancel()
	if err := b.WithFence(ctx, func(context.Context) error { t.Fatal("expired publication fence reused"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestFQDNScopedFailedStagePreservesUnrelatedEndpoint(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	other := ep
	other.PodIdentifier = "unrelated"
	other.Namespace = "other"
	other.IfIndex++
	other.Lifetime++
	b.bound[other.IfIndex] = &fqdnBinding{endpoint: other, grants: map[fqdnGrantKey]fqdnGrantValue{}, flowNames: map[fqdnFlowKey][]string{}}
	for _, endpoint := range []fqdn.Endpoint{ep, other} {
		if err := b.Replace(ctx, endpoint, 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.BeginFQDNPolicyUpdateFor(ctx, "failed", []string{ep.PodIdentifier}); err != nil {
		t.Fatal(err)
	}
	if err := b.EndFQDNPolicyUpdateFor(ctx, "failed", false); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(ctx, other, 1, nil); err != nil {
		t.Fatal("unrelated endpoint lost permission", err)
	}
	if err := b.BeginFQDNPolicyUpdateFor(ctx, "other", []string{other.PodIdentifier}); err != nil {
		t.Fatal(err)
	}
	if err := b.EndFQDNPolicyUpdateFor(ctx, "other", true); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(ctx, ep, 1, nil); err == nil {
		t.Fatal("unrelated success reopened failed transaction")
	}
	if err := b.Check(ctx, other, 1, nil); err != nil {
		t.Fatal("unrelated success cannot recover independently", err)
	}
}
func TestFQDNStageCannotReactivateUncommittedOrphan(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	if err := b.BeginFQDNPolicyUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.EndFQDNPolicyUpdate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(ctx, ep, 0, nil); err == nil {
		t.Fatal("orphan bind became ready without committed policy")
	}
}
func TestFQDNSameRevisionAnswersDoNotDropEstablishedTraffic(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	g := fqdnTestGrant()
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal(err)
	}
	// No readiness write is needed for a duplicate or valid same-policy addition.
	b.maps["fqdn_endpoints"].(*fqdnTestMap).failPut = true
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal("duplicate answer toggled readiness", err)
	}
	g.Deadline++
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal("same-policy learning toggled readiness", err)
	}
	if err := b.Check(ctx, ep, 1, []fqdn.Grant{g}); err != nil {
		t.Fatal(err)
	}
}
func TestFQDNSelectedVethReplacementStaysRestrictive(t *testing.T) {
	b, ep := fqdnTestBackend()
	ctx := context.Background()
	if err := b.Replace(ctx, ep, 1, []fqdn.Grant{fqdnTestGrant()}); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, ep); err != nil {
		t.Fatal(err)
	}
	selected := b.selections[ep.Namespace+"/"+ep.Name]
	newIndex := ep.IfIndex + 10
	if err := b.preserveSelectedInterface(newIndex, selected); err != nil {
		t.Fatal(err)
	}
	var v fqdnEndpointValue
	if err := b.maps["fqdn_endpoints"].Get(fqdnUint32(newIndex), fqdnBytes(&v)); err != nil {
		t.Fatal(err)
	}
	if v.Flags != fqdnEndpointSelected || v.Generation != 0 {
		t.Fatal("replacement became unselected or retained grant generation", v)
	}
	successor := ep
	successor.Lifetime++
	if err := b.rememberSelection(successor, true); err != nil {
		t.Fatal(err)
	}
	if err := b.ForgetFQDNSelection(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if b.selections[ep.Namespace+"/"+ep.Name] != successor {
		t.Fatal("forgetting old pod erased successor selection")
	}
}
