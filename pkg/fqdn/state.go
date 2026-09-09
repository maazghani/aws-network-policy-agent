package fqdn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type observationKey struct {
	name    string
	address netip.Addr
}
type grantKey struct {
	address netip.Addr
	port    PortRange
}

type endpointState struct {
	endpoint     Endpoint
	gate         chan struct{}
	policy       Snapshot
	observations map[observationKey]Observation
	grants       []Grant
	// life and cancel are protected by Engine.mu; all other mutable state by gate.
	life     context.Context
	cancel   context.CancelFunc
	alive    bool
	counted  bool
	updating int
	blocked  bool
	dirty    bool
}

type Engine struct {
	config                                     Config
	backend                                    Backend
	mu                                         sync.Mutex
	endpoints                                  map[uint64]*endpointState
	interfaces                                 map[uint32]*endpointState
	lifecycle                                  chan struct{}
	totalObservations, totalGrants             int
	totalRules, totalAddresses                 int
	admissions, failures, revocations, expired atomic.Uint64
}

func NewEngine(config Config, backend Backend) (*Engine, error) {
	l := config.Limits
	if backend == nil || config.PublicationTimeout <= 0 || l.MaxEndpoints <= 0 || l.MaxRulesPerEndpoint <= 0 || l.MaxObservationsPerEndpoint <= 0 || l.MaxAddressesPerEndpoint <= 0 || l.MaxGrantsPerAddress <= 0 || l.MaxGrantsPerEndpoint <= 0 || l.MaxTotalObservations <= 0 || l.MaxTotalGrants <= 0 {
		return nil, fmt.Errorf("%w: explicit positive limits, timeout and backend are required", ErrCapacity)
	}
	if config.Clock == nil {
		config.Clock = BootClock{}
	}
	if _, err := config.Clock.Now(); err != nil {
		return nil, err
	}
	return &Engine{config: config, backend: backend, endpoints: make(map[uint64]*endpointState), interfaces: make(map[uint32]*endpointState), lifecycle: make(chan struct{}, 1)}, nil
}

func (e *Engine) Limits() Limits { return e.config.Limits }

func acquire(ctx context.Context, gate chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func release(gate chan struct{}) { <-gate }

func (e *Engine) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, e.config.PublicationTimeout)
}

func validEndpoint(ep Endpoint) bool {
	for _, identity := range []string{ep.UID, ep.Namespace, ep.Name, ep.PodIdentifier} {
		if len(identity) > 512 {
			return false
		}
	}
	return ep.UID != "" && ep.IfIndex != 0 && ep.IP.IsValid() && !ep.IP.IsUnspecified() && !ep.IP.IsMulticast() && ep.IP.Zone() == "" && !ep.IP.Is4In6()
}

func (e *Engine) find(ep Endpoint) (*endpointState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.endpoints[ep.Lifetime]
	if s == nil || !s.alive || s.endpoint != ep {
		return nil, ErrEndpoint
	}
	return s, nil
}

// Enroll never reuses a lifetime, including when a pod's UID/IP/veth is unchanged
// after reattachment. Old work is cancelled before physical cleanup is attempted.
func (e *Engine) Enroll(ctx context.Context, ep Endpoint, initial ...Snapshot) (Endpoint, error) {
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	if !validEndpoint(ep) || len(initial) > 1 {
		return Endpoint{}, ErrEndpoint
	}
	if err := acquire(ctx, e.lifecycle); err != nil {
		return Endpoint{}, err
	}
	defer release(e.lifecycle)
	e.mu.Lock()
	previous := e.interfaces[ep.IfIndex]
	e.mu.Unlock()
	if previous != nil {
		if err := e.Delete(ctx, previous.endpoint); err != nil {
			return Endpoint{}, err
		}
	}
	var policy Snapshot
	if len(initial) == 1 {
		policy = initial[0]
	}
	rules, policyErr := e.compile(policy.Rules, nil)
	if policyErr != nil {
		return Endpoint{}, policyErr
	}
	ep.Lifetime = 0
	var id [8]byte
	for ep.Lifetime == 0 {
		if _, err := rand.Read(id[:]); err != nil {
			return Endpoint{}, err
		}
		ep.Lifetime = binary.LittleEndian.Uint64(id[:])
	}
	e.mu.Lock()
	if len(e.endpoints) >= e.config.Limits.MaxEndpoints || e.endpoints[ep.Lifetime] != nil {
		e.mu.Unlock()
		return Endpoint{}, ErrCapacity
	}
	life, lifeCancel := context.WithCancel(context.Background())
	s := &endpointState{endpoint: ep, gate: make(chan struct{}, 1), policy: Snapshot{Revision: 1, Rules: rules}, observations: make(map[observationKey]Observation), life: life, cancel: lifeCancel}
	e.endpoints[ep.Lifetime] = s
	e.interfaces[ep.IfIndex] = s
	e.mu.Unlock()
	if err := acquire(ctx, s.gate); err != nil {
		e.remove(s)
		return Endpoint{}, err
	}
	defer release(s.gate)
	err := e.backend.WithFence(ctx, func(ctx context.Context) error {
		if err := e.backend.Bind(ctx, ep); err != nil {
			return err
		}
		if err := e.reconcilePolicy(ctx, s); err != nil {
			return err
		}
		return e.backend.Replace(ctx, ep, s.policy.Revision, nil)
	})
	if err != nil {
		e.remove(s)
		// A partially bound endpoint must stay restrictive; cleanup is checked.
		cleanupCtx, cleanupCancel := e.bounded(context.Background())
		defer cleanupCancel()
		cleanupErr := e.backend.WithFence(cleanupCtx, func(ctx context.Context) error { return e.backend.Delete(ctx, ep) })
		return Endpoint{}, errors.Join(err, cleanupErr)
	}
	e.mu.Lock()
	s.alive = true
	s.counted = true
	e.totalRules += len(s.policy.Rules)
	e.mu.Unlock()
	return ep, nil
}

func (e *Engine) remove(s *endpointState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.endpoints[s.endpoint.Lifetime] != s {
		return
	}
	s.alive = false
	s.cancel()
	delete(e.endpoints, s.endpoint.Lifetime)
	if e.interfaces[s.endpoint.IfIndex] == s {
		delete(e.interfaces, s.endpoint.IfIndex)
	}
	e.totalObservations -= len(s.observations)
	e.totalGrants -= len(s.grants)
	if s.counted {
		e.totalRules -= len(s.policy.Rules)
	}
	e.totalAddresses -= addressCount(s.grants)
}

// Delete invalidates userspace identity before waiting for a pending writer.
// Failure to restrict the kernel is returned; previously committed TTLs still run.
func (e *Engine) Delete(ctx context.Context, ep Endpoint) (err error) {
	started := time.Now()
	defer func() { Observe("revocation", started, err) }()
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	e.mu.Lock()
	s := e.endpoints[ep.Lifetime]
	if s == nil || s.endpoint != ep {
		e.mu.Unlock()
		return ErrEndpoint
	}
	s.alive = false
	s.cancel()
	e.mu.Unlock()
	if err = acquire(ctx, s.gate); err != nil {
		return err
	}
	defer release(s.gate)
	err = e.backend.WithFence(ctx, func(ctx context.Context) error { return e.backend.Delete(ctx, ep) })
	if err != nil {
		return err
	}
	e.remove(s)
	e.revocations.Add(1)
	return nil
}

func (e *Engine) Lookup(ifIndex uint32, source netip.Addr) (Endpoint, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.interfaces[ifIndex]
	if s == nil || !s.alive || s.endpoint.IP != source {
		return Endpoint{}, false
	}
	return s.endpoint, true
}

// compile returns only old, independently provable rules if any part of an
// update is rejected. Removed rules never survive a capacity/validation failure.
func (e *Engine) compile(input, previous []Rule) ([]Rule, error) {
	var normalized []Rule
	var rejected error
	if len(input) > e.config.Limits.MaxRulesPerEndpoint {
		rejected = ErrCapacity
	}
	for _, r := range input {
		if len(r.Owner) > 512 || len(r.Ports) > e.config.Limits.MaxGrantsPerAddress {
			rejected = errors.Join(rejected, ErrCapacity)
			continue
		}
		n, err := normalizeRule(r)
		if err != nil {
			rejected = errors.Join(rejected, err)
			continue
		}
		if rejected == nil {
			normalized = append(normalized, n)
		}
	}
	if rejected == nil {
		return normalized, nil
	}
	// Scan rather than retaining an oversized rejected snapshot in memory.
	normalized = nil
	for _, old := range previous {
		for _, r := range input {
			if r.Owner != old.Owner || len(r.Ports) > e.config.Limits.MaxGrantsPerAddress {
				continue
			}
			n, err := normalizeRule(r)
			if err == nil && sameRule(n, old) {
				normalized = append(normalized, old)
				break
			}
		}
	}
	return cloneRules(normalized), rejected
}

func (e *Engine) reconcilePolicy(ctx context.Context, s *endpointState) error {
	if backend, ok := e.backend.(PolicyBackend); ok {
		return backend.ReconcilePolicy(ctx, s.endpoint, Snapshot{Revision: s.policy.Revision, Rules: cloneRules(s.policy.Rules)})
	}
	return nil
}

func (e *Engine) UpdatePolicy(ctx context.Context, ep Endpoint, snapshot Snapshot) (err error) {
	started := time.Now()
	defer func() { Observe("revocation", started, err) }()
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	s, err := e.find(ep)
	if err != nil {
		return err
	}
	// Cancel an in-flight DNS response before contending on its publication gate.
	e.mu.Lock()
	s.cancel()
	s.updating++
	e.mu.Unlock()
	defer func() { e.mu.Lock(); s.updating--; e.mu.Unlock() }()
	if err = acquire(ctx, s.gate); err != nil {
		return err
	}
	defer release(s.gate)
	if _, err = e.find(ep); err != nil {
		return err
	}
	previousRules := s.policy.Rules
	rules, policyErr := e.compile(snapshot.Rules, previousRules)
	revision := s.policy.Revision + 1
	if snapshot.Revision > revision {
		revision = snapshot.Revision
	}
	if revision == 0 {
		return errors.Join(policyErr, ErrPolicy)
	}
	e.mu.Lock()
	e.totalRules += len(rules) - len(s.policy.Rules)
	s.policy = Snapshot{Revision: revision, Rules: rules}
	e.mu.Unlock()
	now, clockErr := e.config.Clock.Now()
	if clockErr != nil {
		e.mu.Lock()
		e.totalRules -= len(s.policy.Rules)
		s.policy.Rules = nil
		e.mu.Unlock()
		rules = nil
		policyErr = errors.Join(policyErr, clockErr)
	}
	observations := make(map[observationKey]Observation)
	for k, o := range s.observations {
		if o.ExpiresAt > now && len(matching(rules, o.Name)) > 0 {
			observations[k] = o
		}
	}
	grants, grantErr := e.grants(rules, observations, now)
	retainSurvivors := func() {
		var surviving []Rule
		for _, old := range previousRules {
			for _, current := range rules {
				if sameRule(old, current) {
					surviving = append(surviving, old)
					break
				}
			}
		}
		e.mu.Lock()
		e.totalRules += len(surviving) - len(s.policy.Rules)
		s.policy.Rules = surviving
		e.mu.Unlock()
		rules = surviving
		for key, o := range observations {
			if len(matching(rules, o.Name)) == 0 {
				delete(observations, key)
			}
		}
		grants, _ = e.grants(rules, observations, now)
	}
	if grantErr != nil {
		retainSurvivors()
		policyErr = errors.Join(policyErr, grantErr)
	}
	if reserveErr := e.reserve(s, observations, grants); reserveErr != nil {
		retainSurvivors()
		_ = e.reserve(s, observations, grants)
		policyErr = errors.Join(policyErr, reserveErr)
	}
	err = e.backend.WithFence(ctx, func(ctx context.Context) error {
		if s.blocked {
			if err := e.backend.Bind(ctx, ep); err != nil {
				return err
			}
		}
		if err := e.reconcilePolicy(ctx, s); err != nil {
			return err
		}
		return e.backend.Replace(ctx, ep, revision, grants)
	})
	s.blocked = err != nil
	if err == nil {
		s.dirty = false
	}
	if err != nil {
		// Do not retain a failed policy as usable authority. Deletion failure is
		// surfaced alongside the original failure, never reported as revocation.
		cleanupCtx, cleanupCancel := e.bounded(context.Background())
		defer cleanupCancel()
		cleanupErr := e.backend.WithFence(cleanupCtx, func(ctx context.Context) error { return e.backend.Delete(ctx, ep) })
		err = errors.Join(err, cleanupErr)
	}
	e.mu.Lock()
	s.life, s.cancel = context.WithCancel(context.Background())
	e.mu.Unlock()
	e.revocations.Add(1)
	if err == nil && policyErr != nil {
		return &RejectedPolicyError{Cause: policyErr}
	}
	return errors.Join(policyErr, err)
}

func (e *Engine) Matches(ep Endpoint, question string) (bool, error) {
	s, err := e.find(ep)
	if err != nil {
		return false, err
	}
	ctx, cancel := e.bounded(context.Background())
	defer cancel()
	if err = acquire(ctx, s.gate); err != nil {
		return false, err
	}
	defer release(s.gate)
	if _, err = e.find(ep); err != nil || s.blocked {
		return false, ErrEndpoint
	}
	return len(matching(s.policy.Rules, question)) > 0, nil
}

func (e *Engine) reserve(s *endpointState, observations map[observationKey]Observation, grants []Grant) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	obsTotal := e.totalObservations - len(s.observations) + len(observations)
	grantTotal := e.totalGrants - len(s.grants) + len(grants)
	if obsTotal > e.config.Limits.MaxTotalObservations || grantTotal > e.config.Limits.MaxTotalGrants {
		return ErrCapacity
	}
	e.totalObservations = obsTotal
	e.totalGrants = grantTotal
	e.totalAddresses += addressCount(grants) - addressCount(s.grants)
	s.observations = observations
	s.grants = grants
	return nil
}

func (e *Engine) grants(rules []Rule, observations map[observationKey]Observation, now uint64) ([]Grant, error) {
	if len(observations) > e.config.Limits.MaxObservationsPerEndpoint {
		return nil, ErrCapacity
	}
	entries := make(map[grantKey]Grant)
	addresses := make(map[netip.Addr]int)
	for _, o := range observations {
		if o.ExpiresAt <= now {
			continue
		}
		for _, r := range matching(rules, o.Name) {
			for _, p := range r.Ports {
				key := grantKey{o.Address, p}
				g, exists := entries[key]
				if !exists {
					if len(entries) >= e.config.Limits.MaxGrantsPerEndpoint || addresses[o.Address] >= e.config.Limits.MaxGrantsPerAddress || addresses[o.Address] == 0 && len(addresses) >= e.config.Limits.MaxAddressesPerEndpoint {
						return nil, ErrCapacity
					}
					g = Grant{Address: o.Address, Protocol: p.Protocol, StartPort: p.StartPort, EndPort: p.EndPort}
					addresses[o.Address]++
				}
				g.Deadline = max(g.Deadline, o.ExpiresAt)
				if !slices.Contains(g.Names, o.Name) {
					g.Names = append(g.Names, o.Name)
				}
				entries[key] = g
			}
		}
	}
	result := make([]Grant, 0, len(entries))
	for _, g := range entries {
		slices.Sort(g.Names)
		result = append(result, g)
	}
	slices.SortFunc(result, func(a, b Grant) int {
		if c := a.Address.Compare(b.Address); c != 0 {
			return c
		}
		if a.Protocol != b.Protocol {
			return int(a.Protocol) - int(b.Protocol)
		}
		if a.StartPort != b.StartPort {
			return int(a.StartPort) - int(b.StartPort)
		}
		return int(a.EndPort) - int(b.EndPort)
	})
	return result, nil
}

// Publish validates and programs every matching returned address before calling
// releaseResponse. Its callback runs under the endpoint and shared-policy fences
// and must honor context cancellation and a write deadline. Empty observations
// provide fenced publication of informational/negative responses without grants.
func (e *Engine) Publish(ctx context.Context, ep Endpoint, question string, answer []Observation, releaseResponse func(context.Context, []uint32) error) (err error) {
	return e.publish(ctx, ep, question, answer, false, func(ctx context.Context, _ bool, ttls []uint32) error {
		if releaseResponse == nil {
			return ErrPolicy
		}
		return releaseResponse(ctx, ttls)
	})
}

// PublishDNS selects query matching and learning inside the same publication
// fence. A prior Matches call is only advisory: policy can change while an
// upstream query is outstanding. Nonmatching responses remain informational.
func (e *Engine) PublishDNS(ctx context.Context, ep Endpoint, question string, answer []Observation, releaseResponse func(context.Context, bool, []uint32) error) error {
	return e.publish(ctx, ep, question, answer, true, releaseResponse)
}

func (e *Engine) publish(ctx context.Context, ep Endpoint, question string, answer []Observation, allowInformational bool, releaseResponse func(context.Context, bool, []uint32) error) (err error) {
	started := time.Now()
	defer func() { Observe("publication", started, err) }()
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	defer func() {
		if err != nil {
			e.failures.Add(1)
		}
	}()
	if releaseResponse == nil {
		return ErrPolicy
	}
	s, err := e.find(ep)
	if err != nil {
		return err
	}
	e.mu.Lock()
	life := s.life
	updating := s.updating
	e.mu.Unlock()
	if updating > 0 {
		return context.Canceled
	}
	stop := context.AfterFunc(life, cancel)
	defer stop()
	if err = acquire(ctx, s.gate); err != nil {
		return err
	}
	defer release(s.gate)
	if _, err = e.find(ep); err != nil || s.blocked {
		return ErrEndpoint
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	questionName, nameErr := NormalizeName(question)
	matched := nameErr == nil && len(matching(s.policy.Rules, questionName)) > 0
	if !matched && len(answer) > 0 {
		if !allowInformational {
			return ErrNoPermission
		}
		answer = nil
	}
	if len(answer) > e.config.Limits.MaxObservationsPerEndpoint {
		return ErrCapacity
	}
	now, err := e.config.Clock.Now()
	if err != nil {
		return err
	}
	// Validate the whole answer before any capacity fallback can publish it.
	for _, o := range answer {
		name, normalizeErr := NormalizeName(o.Name)
		if normalizeErr != nil || name != questionName || !o.Address.IsValid() || o.Address.IsUnspecified() || o.Address.IsMulticast() || o.Address.Is4In6() || o.Address.Zone() != "" || o.Address.Is4() != ep.IP.Is4() {
			return ErrNoPermission
		}
	}
	observations := make(map[observationKey]Observation, min(e.config.Limits.MaxObservationsPerEndpoint, len(s.observations)+len(answer)))
	expired := uint64(0)
	for key, o := range s.observations {
		if o.ExpiresAt > now {
			observations[key] = o
		} else {
			expired++
		}
	}
	for _, o := range answer {
		if o.ExpiresAt <= now {
			continue
		}
		o.Name = questionName
		key := observationKey{questionName, o.Address}
		prior, exists := observations[key]
		if !exists && len(observations) >= e.config.Limits.MaxObservationsPerEndpoint {
			return e.publishStatic(ctx, s, answer, matched, releaseResponse, ErrCapacity)
		}
		if !exists || o.ExpiresAt > prior.ExpiresAt {
			observations[key] = o
		}
	}
	grants, err := e.grants(s.policy.Rules, observations, now)
	if err != nil {
		if errors.Is(err, ErrCapacity) {
			return e.publishStatic(ctx, s, answer, matched, releaseResponse, err)
		}
		return err
	}
	oldObservations, oldGrants := s.observations, s.grants
	if err = e.reserve(s, observations, grants); err != nil {
		e.reclaimOthers(ctx, s)
		if err = e.reserve(s, observations, grants); err != nil {
			return e.publishStatic(ctx, s, answer, matched, releaseResponse, err)
		}
	}
	programmed := false
	err = e.backend.WithFence(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.backend.Replace(ctx, ep, s.policy.Revision, grants); err != nil {
			s.dirty = true
			return err
		}
		s.dirty = false
		programmed = true
		// Check the full answer set, including duplicate responses. A previous
		// write does not prove attachment or current tier-effective permission.
		var required []Grant
		for _, g := range grants {
			for _, o := range answer {
				if g.Address == o.Address {
					required = append(required, g)
					break
				}
			}
		}
		if err := e.backend.Check(ctx, ep, s.policy.Revision, required); err != nil {
			if !errors.Is(err, ErrExpired) {
				return err
			}
			if staticErr := e.checkStatic(ctx, s, answer); staticErr != nil {
				return errors.Join(err, staticErr)
			}
		}
		if _, err := e.find(ep); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		now, err := e.config.Clock.Now()
		if err != nil {
			return err
		}
		var unsupported []Observation
		for _, o := range answer {
			live := false
			for _, g := range required {
				if g.Address == o.Address && g.Deadline > now {
					live = true
					break
				}
			}
			if !live {
				unsupported = append(unsupported, o)
			}
		}
		if len(unsupported) > 0 {
			if err := e.checkStatic(ctx, s, unsupported); err != nil {
				return errors.Join(ErrExpired, err)
			}
		}
		ttls := make([]uint32, len(answer))
		remainingDeadline := e.config.PublicationTimeout
		for i, o := range answer {
			if o.ExpiresAt <= now {
				continue
			}
			remaining := (o.ExpiresAt - now) / uint64(time.Second)
			if remaining > uint64(^uint32(0)) {
				remaining = uint64(^uint32(0))
			}
			ttls[i] = uint32(remaining)
			if ttlRemaining := time.Duration(o.ExpiresAt - now); ttlRemaining > 0 && ttlRemaining < remainingDeadline {
				remainingDeadline = ttlRemaining
			}
		}
		writeCtx, writeCancel := context.WithTimeout(ctx, remainingDeadline)
		defer writeCancel()
		if err := releaseResponse(writeCtx, matched, ttls); err != nil {
			return err
		}
		e.admissions.Add(1)
		return nil
	})
	if !programmed {
		_ = e.reserve(s, oldObservations, oldGrants)
	} else {
		e.expired.Add(expired)
	}
	return err
}

func (e *Engine) checkStatic(ctx context.Context, s *endpointState, answer []Observation) error {
	backend, ok := e.backend.(StaticBackend)
	if !ok {
		return ErrNoPermission
	}
	entries := make(map[grantKey]Grant)
	for _, o := range answer {
		for _, rule := range matching(s.policy.Rules, o.Name) {
			for _, port := range rule.Ports {
				key := grantKey{o.Address, port}
				if _, exists := entries[key]; !exists && len(entries) >= e.config.Limits.MaxGrantsPerEndpoint {
					return ErrCapacity
				}
				entries[key] = Grant{Address: o.Address, Protocol: port.Protocol, StartPort: port.StartPort, EndPort: port.EndPort}
			}
		}
	}
	grants := make([]Grant, 0, len(entries))
	for _, g := range entries {
		grants = append(grants, g)
	}
	return backend.CheckStatic(ctx, s.endpoint, grants)
}

func (e *Engine) publishStatic(ctx context.Context, s *endpointState, answer []Observation, matched bool, write func(context.Context, bool, []uint32) error, cause error) error {
	return e.backend.WithFence(ctx, func(ctx context.Context) error {
		if err := e.checkStatic(ctx, s, answer); err != nil {
			return errors.Join(cause, err)
		}
		if _, err := e.find(s.endpoint); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		now, err := e.config.Clock.Now()
		if err != nil {
			return err
		}
		ttls := make([]uint32, len(answer))
		for i, o := range answer {
			if o.ExpiresAt > now {
				ttls[i] = uint32(min((o.ExpiresAt-now)/uint64(time.Second), uint64(^uint32(0))))
			}
		}
		if err := write(ctx, matched, ttls); err != nil {
			return err
		}
		e.admissions.Add(1)
		return nil
	})
}

func addressCount(grants []Grant) int {
	addresses := make(map[netip.Addr]bool)
	for _, g := range grants {
		addresses[g.Address] = true
	}
	return len(addresses)
}

func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Endpoints: len(e.endpoints), Rules: e.totalRules, Observations: e.totalObservations, Addresses: e.totalAddresses, Grants: e.totalGrants, Admissions: e.admissions.Load(), Failures: e.failures.Load(), Revocations: e.revocations.Load(), Expired: e.expired.Load()}
}

// Expire reclaims bounded userspace state and removes expired map entries.
// Kernel deadline checks remain authoritative when this maintenance loop stops.
func (e *Engine) Expire(ctx context.Context) (err error) {
	started := time.Now()
	defer func() { Observe("expiry", started, err) }()
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	e.mu.Lock()
	states := make([]*endpointState, 0, len(e.endpoints))
	for _, s := range e.endpoints {
		states = append(states, s)
	}
	e.mu.Unlock()
	var failures []error
	for _, s := range states {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if sweepErr := e.expireEndpoint(ctx, s); sweepErr != nil {
			failures = append(failures, sweepErr)
		}
	}
	return errors.Join(failures...)
}

func (e *Engine) expireEndpoint(ctx context.Context, s *endpointState) error {
	ctx, cancel := e.bounded(ctx)
	defer cancel()
	if err := acquire(ctx, s.gate); err != nil {
		return err
	}
	defer release(s.gate)
	return e.expireLocked(ctx, s)
}

func (e *Engine) expireLocked(ctx context.Context, s *endpointState) error {
	if _, err := e.find(s.endpoint); err != nil {
		return nil
	}
	if s.blocked {
		return nil
	}
	now, err := e.config.Clock.Now()
	if err != nil {
		return err
	}
	observations := make(map[observationKey]Observation)
	for k, o := range s.observations {
		if o.ExpiresAt > now {
			observations[k] = o
		}
	}
	if len(observations) == len(s.observations) && !s.dirty {
		return nil
	}
	grants, err := e.grants(s.policy.Rules, observations, now)
	if err != nil {
		return err
	}
	if err = e.backend.WithFence(ctx, func(ctx context.Context) error { return e.backend.Replace(ctx, s.endpoint, s.policy.Revision, grants) }); err != nil {
		s.dirty = true
		return err
	}
	s.dirty = false
	e.expired.Add(uint64(len(s.observations) - len(observations)))
	return e.reserve(s, observations, grants)
}

// Under global capacity pressure, first reclaim expired state belonging to idle
// sibling endpoints. A busy endpoint is skipped rather than reversing lock order.
func (e *Engine) reclaimOthers(ctx context.Context, except *endpointState) {
	e.mu.Lock()
	states := make([]*endpointState, 0, len(e.endpoints))
	for _, s := range e.endpoints {
		if s != except {
			states = append(states, s)
		}
	}
	e.mu.Unlock()
	for _, s := range states {
		select {
		case s.gate <- struct{}{}:
			_ = e.expireLocked(ctx, s)
			release(s.gate)
		default:
		}
	}
}

func (e *Engine) Inspect(ep Endpoint) (EndpointDiagnostic, error) {
	s, err := e.find(ep)
	if err != nil {
		return EndpointDiagnostic{}, err
	}
	ctx, cancel := e.bounded(context.Background())
	defer cancel()
	if err = acquire(ctx, s.gate); err != nil {
		return EndpointDiagnostic{}, err
	}
	defer release(s.gate)
	result := EndpointDiagnostic{Endpoint: ep, Revision: s.policy.Revision, Rules: cloneRules(s.policy.Rules), Grants: make([]Grant, len(s.grants))}
	for _, o := range s.observations {
		result.Observations = append(result.Observations, o)
	}
	for i, g := range s.grants {
		result.Grants[i] = g
		result.Grants[i].Names = slices.Clone(g.Names)
	}
	return result, nil
}
