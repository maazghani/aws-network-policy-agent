package fqdn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type memoryProgrammer struct {
	attached map[string]string
	grants   map[string][]Grant
	fail     error
}

func (m *memoryProgrammer) Attached(e, l string) bool { return m.attached[e] == l }
func (m *memoryProgrammer) Replace(_ context.Context, e, l string, g []Grant) error {
	if m.fail != nil {
		return m.fail
	}
	if !m.Attached(e, l) {
		return ErrEndpointGone
	}
	m.grants[e] = append([]Grant(nil), g...)
	return nil
}
func setup(t *testing.T) (*Engine, *memoryProgrammer) {
	t.Helper()
	p := &memoryProgrammer{attached: map[string]string{"pod": "uid-1"}, grants: map[string][]Grant{}}
	e := New(p, DefaultLimits())
	if err := e.Enroll(context.Background(), "pod", "uid-1"); err != nil {
		t.Fatal(err)
	}
	return e, p
}

func TestWildcardExcludesApex(t *testing.T) {
	if matches("*.example.com", "example.com") {
		t.Fatal("wildcard matched apex")
	}
	if !matches("*.example.com.", "A.B.Example.Com") {
		t.Fatal("wildcard did not match descendant")
	}
}

func TestAdmissionIsEndpointLifetimeScopedAndUsesEarliestTTL(t *testing.T) {
	e, p := setup(t)
	now := time.Unix(100, 0)
	e.now = func() time.Time { return now }
	rules := []Rule{{Owner: "p1", Name: "api.example.com", Ports: []Port{{Protocol: 6, Start: 443, End: 443}}}}
	if err := e.UpdateRules(context.Background(), "pod", "uid-1", rules); err != nil {
		t.Fatal(err)
	}
	err := e.Admit(context.Background(), "pod", "uid-1", Response{Question: "API.EXAMPLE.COM.", CNAMEs: []CNAMERecord{{Name: "api.example.com", Target: "edge.example.net", TTL: 5 * time.Second}}, Addresses: []AddressRecord{{Name: "edge.example.net", Address: netip.MustParseAddr("192.0.2.4"), TTL: 30 * time.Second}, {Name: "unrelated.test", Address: netip.MustParseAddr("192.0.2.9"), TTL: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.grants["pod"]) != 1 {
		t.Fatalf("got %d grants", len(p.grants["pod"]))
	}
	if got := p.grants["pod"][0].ExpiresAt; !got.Equal(now.Add(5 * time.Second)) {
		t.Fatalf("expiry %v", got)
	}
	if err := e.Admit(context.Background(), "pod", "uid-old", Response{Question: "api.example.com"}); !errors.Is(err, ErrEndpointGone) {
		t.Fatalf("old lifetime: %v", err)
	}
}

func TestPolicyCompositionAndRevocation(t *testing.T) {
	e, p := setup(t)
	rules := []Rule{{Owner: "p1", Name: "api.example.com"}, {Owner: "p2", Name: "api.example.com"}}
	if err := e.UpdateRules(context.Background(), "pod", "uid-1", rules); err != nil {
		t.Fatal(err)
	}
	if err := e.Admit(context.Background(), "pod", "uid-1", Response{Question: "api.example.com", Addresses: []AddressRecord{{Name: "api.example.com", Address: netip.MustParseAddr("2001:db8::1"), TTL: time.Minute}}}); err != nil {
		t.Fatal(err)
	}
	if len(p.grants["pod"]) != 2 {
		t.Fatalf("want two contributions, got %d", len(p.grants["pod"]))
	}
	if err := e.UpdateRules(context.Background(), "pod", "uid-1", rules[1:]); err != nil {
		t.Fatal(err)
	}
	if len(p.grants["pod"]) != 1 || p.grants["pod"][0].Owner != "p2" {
		t.Fatalf("surviving grant: %#v", p.grants["pod"])
	}
}

func TestProgrammingFailureNeverCommitsGrant(t *testing.T) {
	e, p := setup(t)
	if err := e.UpdateRules(context.Background(), "pod", "uid-1", []Rule{{Owner: "p", Name: "a.example"}}); err != nil {
		t.Fatal(err)
	}
	p.fail = errors.New("map full")
	err := e.Admit(context.Background(), "pod", "uid-1", Response{Question: "a.example", Addresses: []AddressRecord{{Name: "a.example", Address: netip.MustParseAddr("192.0.2.1"), TTL: time.Minute}}})
	if err == nil {
		t.Fatal("failed publication released response")
	}
	if len(e.endpoints["pod"].grants) != 0 {
		t.Fatal("userspace committed failed grant")
	}
}

func TestCapacityFailureIsRestrictive(t *testing.T) {
	e, p := setup(t)
	e.limits.Rules = 1
	err := e.UpdateRules(context.Background(), "pod", "uid-1", []Rule{{Name: "a.example"}, {Name: "b.example"}})
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("got %v", err)
	}
	if len(p.grants["pod"]) != 0 || len(e.endpoints["pod"].rules) != 0 {
		t.Fatal("rejected update retained authority")
	}
}

func TestDeleteInvalidatesBeforeReuse(t *testing.T) {
	e, p := setup(t)
	if err := e.Delete(context.Background(), "pod", "uid-1"); err != nil {
		t.Fatal(err)
	}
	p.attached["pod"] = "uid-2"
	if err := e.Enroll(context.Background(), "pod", "uid-2"); err != nil {
		t.Fatal(err)
	}
	if len(p.grants["pod"]) != 0 {
		t.Fatal("new lifetime inherited grants")
	}
}
