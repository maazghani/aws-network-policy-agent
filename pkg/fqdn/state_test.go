package fqdn

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testClock struct{ now atomic.Uint64 }

func (c *testClock) Now() (uint64, error) { return c.now.Load(), nil }

type testBackend struct {
	gate      chan struct{}
	mu        sync.Mutex
	grants    map[uint64][]Grant
	bound     map[uint64]bool
	checks    int
	deny      netip.Addr
	replace   func(context.Context) error
	deleteErr error
}

func newTestBackend() *testBackend {
	return &testBackend{gate: make(chan struct{}, 1), grants: make(map[uint64][]Grant), bound: make(map[uint64]bool)}
}
func (b *testBackend) WithFence(ctx context.Context, f func(context.Context) error) error {
	if err := acquire(ctx, b.gate); err != nil {
		return err
	}
	defer release(b.gate)
	return f(ctx)
}
func (b *testBackend) Bind(_ context.Context, ep Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bound[ep.Lifetime] = true
	return nil
}
func (b *testBackend) Replace(ctx context.Context, ep Endpoint, _ uint64, grants []Grant) error {
	if b.replace != nil {
		if err := b.replace(ctx); err != nil {
			return err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.bound[ep.Lifetime] {
		return ErrEndpoint
	}
	b.grants[ep.Lifetime] = slices.Clone(grants)
	return nil
}
func (b *testBackend) Check(_ context.Context, ep Endpoint, _ uint64, grants []Grant) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checks++
	if !b.bound[ep.Lifetime] {
		return ErrEndpoint
	}
	for _, g := range grants {
		if g.Address == b.deny {
			return ErrNoPermission
		}
	}
	return nil
}
func (b *testBackend) Delete(_ context.Context, ep Endpoint) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bound, ep.Lifetime)
	delete(b.grants, ep.Lifetime)
	return nil
}

func stateFixture(t *testing.T) (*Engine, *testBackend, *testClock, Endpoint) {
	t.Helper()
	clock := &testClock{}
	clock.now.Store(uint64(time.Hour))
	backend := newTestBackend()
	engine, err := NewEngine(Config{Clock: clock, PublicationTimeout: time.Second, Limits: Limits{MaxEndpoints: 8, MaxRulesPerEndpoint: 8, MaxObservationsPerEndpoint: 8, MaxAddressesPerEndpoint: 8, MaxGrantsPerAddress: 8, MaxGrantsPerEndpoint: 16, MaxTotalObservations: 32, MaxTotalGrants: 64}}, backend)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := engine.Enroll(context.Background(), Endpoint{UID: "pod-a", IfIndex: 10, IP: netip.MustParseAddr("10.0.0.10")}, Snapshot{Rules: []Rule{allowRule("owner-a", "*.example.com", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	return engine, backend, clock, ep
}
func allowRule(owner, name string, port uint16) Rule {
	return Rule{Owner: owner, Name: name, Ports: []PortRange{{Protocol: 6, StartPort: port, EndPort: port}}}
}
func observation(clock *testClock, address string, ttl time.Duration) Observation {
	return Observation{Name: "api.example.com", Address: netip.MustParseAddr(address), ExpiresAt: clock.now.Load() + uint64(ttl)}
}
func publish(t *testing.T, e *Engine, ep Endpoint, obs ...Observation) []uint32 {
	t.Helper()
	var ttls []uint32
	if err := e.Publish(context.Background(), ep, "api.example.com", obs, func(_ context.Context, values []uint32) error { ttls = values; return nil }); err != nil {
		t.Fatal(err)
	}
	return ttls
}

func TestEndpointIsolationAndLifetimeReuse(t *testing.T) {
	e, b, clock, a := stateFixture(t)
	second := a
	second.UID = "pod-b"
	second.IfIndex = 11
	second.IP = netip.MustParseAddr("10.0.0.11")
	second, err := e.Enroll(context.Background(), second, Snapshot{Rules: []Rule{allowRule("owner-a", "*.example.com", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	publish(t, e, a, observation(clock, "192.0.2.10", time.Minute))
	if len(b.grants[a.Lifetime]) != 1 || len(b.grants[second.Lifetime]) != 0 {
		t.Fatal("sibling inherited grants")
	}
	replacement, err := e.Enroll(context.Background(), a, Snapshot{Rules: []Rule{allowRule("owner-a", "*.example.com", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Lifetime == a.Lifetime {
		t.Fatal("interface lifetime was reused")
	}
	if err = e.Publish(context.Background(), a, "api.example.com", nil, func(context.Context, []uint32) error { t.Fatal("stale endpoint published"); return nil }); !errors.Is(err, ErrEndpoint) {
		t.Fatal(err)
	}
	if len(b.grants[replacement.Lifetime]) != 0 {
		t.Fatal("replacement inherited grants")
	}
	if _, ok := e.Lookup(replacement.IfIndex, second.IP); ok {
		t.Fatal("source identity spoof accepted")
	}
}

func TestPolicyOwnershipCompositionAndImmutability(t *testing.T) {
	e, _, clock, ep := stateFixture(t)
	rules := []Rule{allowRule("owner-a", "*.example.com", 443), allowRule("owner-b", "api.example.com", 8443)}
	if err := e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: rules}); err != nil {
		t.Fatal(err)
	}
	rules[0].Ports[0].StartPort = 22
	rules[0].Name = "other.example.com"
	publish(t, e, ep, observation(clock, "192.0.2.10", time.Minute))
	d, err := e.Inspect(ep)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Grants) != 2 || d.Grants[0].StartPort != 443 {
		t.Fatalf("snapshot was mutable or ports lost: %+v", d.Grants)
	}
	if err = e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: []Rule{allowRule("owner-b", "api.example.com", 8443)}}); err != nil {
		t.Fatal(err)
	}
	d, _ = e.Inspect(ep)
	if len(d.Grants) != 1 || d.Grants[0].StartPort != 8443 {
		t.Fatalf("contributor removal damaged surviving rule: %+v", d.Grants)
	}
	d.Grants[0].Names[0] = "mutated.example.com"
	d, _ = e.Inspect(ep)
	if d.Grants[0].Names[0] != "api.example.com" {
		t.Fatal("diagnostic mutates state")
	}
}

func TestCapacityFailureRevokesRemovedRulesAndRetainsSurvivors(t *testing.T) {
	e, _, clock, ep := stateFixture(t)
	old := []Rule{allowRule("removed", "api.example.com", 443), allowRule("survivor", "api.example.com", 8443)}
	if err := e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: old}); err != nil {
		t.Fatal(err)
	}
	publish(t, e, ep, observation(clock, "192.0.2.10", time.Minute))
	oversized := []Rule{old[1]}
	for i := 0; i < e.Limits().MaxRulesPerEndpoint; i++ {
		oversized = append(oversized, allowRule("new", "other.example.com", 1234))
	}
	if err := e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: oversized}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected capacity error: %v", err)
	}
	d, _ := e.Inspect(ep)
	if len(d.Rules) != 1 || d.Rules[0].Owner != "survivor" || len(d.Grants) != 1 || d.Grants[0].StartPort != 8443 {
		t.Fatalf("capacity rejection preserved revoked authority: %+v", d)
	}
	if err := e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: []Rule{{Owner: "broken", Name: "*"}}}); !errors.Is(err, ErrPolicy) {
		t.Fatal(err)
	}
	d, _ = e.Inspect(ep)
	if len(d.Grants) != 0 {
		t.Fatal("invalid policy preserved removed authority")
	}
}

func TestRotationExpiryAndTTLBarrier(t *testing.T) {
	e, _, clock, ep := stateFixture(t)
	old := observation(clock, "192.0.2.10", 10*time.Second)
	if ttl := publish(t, e, ep, old); len(ttl) != 1 || ttl[0] != 10 {
		t.Fatal(ttl)
	}
	clock.now.Add(uint64(5 * time.Second))
	publish(t, e, ep, observation(clock, "192.0.2.11", time.Minute))
	d, _ := e.Inspect(ep)
	if len(d.Observations) != 2 {
		t.Fatal("rotation discarded still valid absent address")
	}
	for _, g := range d.Grants {
		if g.Address == old.Address && g.Deadline != old.ExpiresAt {
			t.Fatal("rotation renewed absent address")
		}
	}
	clock.now.Add(uint64(6 * time.Second))
	if err := e.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	d, _ = e.Inspect(ep)
	if len(d.Grants) != 1 || d.Grants[0].Address == old.Address {
		t.Fatal("expired observation retained")
	}
	zero := observation(clock, "192.0.2.12", 0)
	if err := e.Publish(context.Background(), ep, zero.Name, []Observation{zero}, func(context.Context, []uint32) error { t.Fatal("zero TTL released"); return nil }); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
}

func TestNoPositiveAnswerBeforeEveryEffectiveAddressAndDuplicateCheck(t *testing.T) {
	e, b, clock, ep := stateFixture(t)
	first, second := observation(clock, "192.0.2.10", time.Minute), observation(clock, "192.0.2.11", time.Minute)
	b.deny = second.Address
	if err := e.Publish(context.Background(), ep, first.Name, []Observation{first, second}, func(context.Context, []uint32) error { t.Fatal("partially denied answer released"); return nil }); !errors.Is(err, ErrNoPermission) {
		t.Fatal(err)
	}
	b.deny = netip.Addr{}
	publish(t, e, ep, first, second)
	publish(t, e, ep, first, second)
	if b.checks != 3 {
		t.Fatalf("duplicate response skipped current admission: %d checks", b.checks)
	}
}

func TestProgrammingFailureAndExpirationSuppressPositiveAnswer(t *testing.T) {
	for _, mode := range []string{"write-fails", "expires-during-write", "attachment-lost", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e, b, clock, ep := stateFixture(t)
			obs := observation(clock, "192.0.2.10", time.Second)
			e.config.PublicationTimeout = 20 * time.Millisecond
			b.replace = func(ctx context.Context) error {
				switch mode {
				case "write-fails":
					return errors.New("map write failed")
				case "expires-during-write":
					clock.now.Add(uint64(2 * time.Second))
				case "attachment-lost":
					b.mu.Lock()
					b.bound[ep.Lifetime] = false
					b.mu.Unlock()
				case "timeout":
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			if err := e.Publish(context.Background(), ep, obs.Name, []Observation{obs}, func(context.Context, []uint32) error { t.Fatal("premature positive answer"); return nil }); err == nil {
				t.Fatal("expected admission failure")
			}
		})
	}
}

func TestDeletionCancelsPendingPublicationAndCanRetryFailedCleanup(t *testing.T) {
	e, b, clock, ep := stateFixture(t)
	entered := make(chan struct{})
	b.replace = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	result := make(chan error, 1)
	go func() {
		result <- e.Publish(context.Background(), ep, "api.example.com", []Observation{observation(clock, "192.0.2.10", time.Minute)}, func(context.Context, []uint32) error { return errors.New("response should have been canceled") })
	}()
	<-entered
	b.deleteErr = errors.New("delete failed")
	if err := e.Delete(context.Background(), ep); err == nil {
		t.Fatal("unmodifiable kernel falsely reported revoked")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending write not canceled: %v", err)
	}
	if _, ok := e.Lookup(ep.IfIndex, ep.IP); ok {
		t.Fatal("deleted identity still usable")
	}
	b.deleteErr = nil
	if err := e.Delete(context.Background(), ep); err != nil {
		t.Fatalf("physical cleanup cannot retry: %v", err)
	}
}

func TestPublicationFenceCoversResponseWriteAndStatsStayPrompt(t *testing.T) {
	e, b, clock, ep := stateFixture(t)
	inWrite, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- e.Publish(context.Background(), ep, "api.example.com", []Observation{observation(clock, "192.0.2.10", time.Minute)}, func(ctx context.Context, _ []uint32) error {
			close(inWrite)
			select {
			case <-finish:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	<-inWrite
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.WithFence(ctx, func(context.Context) error { t.Fatal("static update crossed response barrier"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	statsReturned := make(chan struct{})
	go func() { _ = e.Stats(); close(statsReturned) }()
	select {
	case <-statsReturned:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("metrics blocked on DNS publication")
	}
	close(finish)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestFailedRevocationCanRebindOnRetry(t *testing.T) {
	e, b, clock, ep := stateFixture(t)
	publish(t, e, ep, observation(clock, "192.0.2.10", time.Minute))
	b.replace = func(context.Context) error { return errors.New("transient write failure") }
	snapshot := Snapshot{Rules: []Rule{allowRule("new", "api.example.com", 8443)}}
	if err := e.UpdatePolicy(context.Background(), ep, snapshot); err == nil {
		t.Fatal("expected failed revocation")
	}
	b.replace = nil
	if err := e.UpdatePolicy(context.Background(), ep, snapshot); err != nil {
		t.Fatalf("retry cannot bind: %v", err)
	}
	publish(t, e, ep, observation(clock, "192.0.2.10", time.Minute))
	d, _ := e.Inspect(ep)
	if len(d.Grants) != 1 || d.Grants[0].StartPort != 8443 {
		t.Fatal(d.Grants)
	}
}

func TestPublishDNSMatchesCurrentPolicyUnderFence(t *testing.T) {
	e, _, clock, ep := stateFixture(t)
	obs := observation(clock, "192.0.2.10", time.Minute)
	obs.Name = "other.test.com"
	if err := e.PublishDNS(context.Background(), ep, obs.Name, []Observation{obs}, func(_ context.Context, matched bool, ttls []uint32) error {
		if matched || len(ttls) != 0 {
			t.Fatal("nonmatching answer learned")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Inspect(ep); len(d.Grants) != 0 {
		t.Fatal("informational answer grants access")
	}
	if err := e.UpdatePolicy(context.Background(), ep, Snapshot{Rules: []Rule{allowRule("new", obs.Name, 443)}}); err != nil {
		t.Fatal(err)
	}
	if err := e.PublishDNS(context.Background(), ep, obs.Name, []Observation{obs}, func(_ context.Context, matched bool, ttls []uint32) error {
		if !matched || len(ttls) != 1 {
			t.Fatal("newly matching answer bypassed admission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalCapacityReclaimsExpiredOtherEndpoint(t *testing.T) {
	e, _, clock, a := stateFixture(t)
	e.config.Limits.MaxTotalObservations = 1
	second := a
	second.UID = "pod-b"
	second.IfIndex = 11
	second.IP = netip.MustParseAddr("10.0.0.11")
	second, err := e.Enroll(context.Background(), second, Snapshot{Rules: []Rule{allowRule("owner-a", "*.example.com", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	publish(t, e, a, observation(clock, "192.0.2.10", time.Second))
	clock.now.Add(uint64(2 * time.Second))
	publish(t, e, second, observation(clock, "192.0.2.11", time.Minute))
	if got := e.Stats().Observations; got != 1 {
		t.Fatalf("expired capacity not reclaimed: %d", got)
	}
}

func TestSuspendAwareClockAndExplicitLimits(t *testing.T) {
	before, err := (BootClock{}).Now()
	if err != nil {
		t.Fatal(err)
	}
	after, err := (BootClock{}).Now()
	if err != nil || after < before || before == 0 {
		t.Fatalf("invalid boot clock %d %d %v", before, after, err)
	}
	if _, err := NewEngine(Config{}, newTestBackend()); !errors.Is(err, ErrCapacity) {
		t.Fatal("missing qualified limits accepted")
	}
}
