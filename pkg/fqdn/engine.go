// Package fqdn contains the endpoint-scoped policy and DNS admission state.
// It intentionally has no DNS listener or Kubernetes dependencies so that the
// positive-response barrier can be tested independently from transport code.
package fqdn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	ErrEndpointGone = errors.New("fqdn endpoint is not enrolled")
	ErrNotAllowed   = errors.New("dns question is not allowed by current policy")
	ErrCapacity     = errors.New("fqdn admission capacity exhausted")
)

type Port struct {
	Protocol   uint8
	Start, End uint16
}
type Rule struct {
	Owner, Name string
	Ports       []Port
}
type AddressRecord struct {
	Name    string
	Address netip.Addr
	TTL     time.Duration
}
type CNAMERecord struct {
	Name, Target string
	TTL          time.Duration
}
type Response struct {
	Question  string
	Addresses []AddressRecord
	CNAMEs    []CNAMERecord
}
type Grant struct {
	Owner     string
	Address   netip.Addr
	Ports     []Port
	ExpiresAt time.Time
}

// Programmer is the synchronous kernel publication boundary. Replace must
// make exactly grants effective for the endpoint lifetime before returning.
type Programmer interface {
	Attached(endpoint, lifetime string) bool
	Replace(ctx context.Context, endpoint, lifetime string, grants []Grant) error
}

type Limits struct{ Rules, Grants, Addresses, CNAMEs int }

func DefaultLimits() Limits { return Limits{Rules: 256, Grants: 4096, Addresses: 1024, CNAMEs: 16} }

type endpointState struct {
	lifetime   string
	generation uint64
	rules      []Rule
	grants     []Grant
}

// Engine serializes policy changes and response publication per endpoint.
type Engine struct {
	mu         sync.Mutex
	programmer Programmer
	limits     Limits
	now        func() time.Time
	endpoints  map[string]*endpointState
}

func New(programmer Programmer, limits Limits) *Engine {
	if limits.Rules <= 0 || limits.Grants <= 0 || limits.Addresses <= 0 || limits.CNAMEs <= 0 {
		limits = DefaultLimits()
	}
	return &Engine{programmer: programmer, limits: limits, now: time.Now, endpoints: make(map[string]*endpointState)}
}

// Enroll establishes a new pod lifetime. Reusing an endpoint identifier never
// inherits grants: an empty set is synchronously published first.
func (e *Engine) Enroll(ctx context.Context, endpoint, lifetime string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if endpoint == "" || lifetime == "" {
		return errors.New("endpoint and lifetime are required")
	}
	if !e.programmer.Attached(endpoint, lifetime) {
		return fmt.Errorf("%w: attachment missing", ErrEndpointGone)
	}
	if err := e.programmer.Replace(ctx, endpoint, lifetime, nil); err != nil {
		return fmt.Errorf("invalidate previous lifetime: %w", err)
	}
	e.endpoints[endpoint] = &endpointState{lifetime: lifetime, generation: 1}
	return nil
}

// UpdateRules replaces the immutable effective snapshot and restrictively
// republishes only still-supported, unexpired contributions.
func (e *Engine) UpdateRules(ctx context.Context, endpoint, lifetime string, rules []Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, err := e.current(endpoint, lifetime)
	if err != nil {
		return err
	}
	if len(rules) > e.limits.Rules {
		rules = nil
		err = ErrCapacity
	}
	rules = cloneRules(rules)
	now := e.now()
	kept := s.grants[:0]
	for _, g := range s.grants {
		if now.Before(g.ExpiresAt) && contributionAllowed(g, rules) {
			kept = append(kept, g)
		}
	}
	if replaceErr := e.programmer.Replace(ctx, endpoint, lifetime, kept); replaceErr != nil {
		return fmt.Errorf("restrictive policy publication: %w", replaceErr)
	}
	s.rules, s.grants = rules, append([]Grant(nil), kept...)
	s.generation++
	return err
}

// Delete invalidates authority before forgetting userspace state.
func (e *Engine) Delete(ctx context.Context, endpoint, lifetime string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, err := e.current(endpoint, lifetime)
	if err != nil {
		return err
	}
	s.generation++
	if err := e.programmer.Replace(ctx, endpoint, lifetime, nil); err != nil {
		return fmt.Errorf("endpoint revocation: %w", err)
	}
	delete(e.endpoints, endpoint)
	return nil
}

// Admit implements the positive-response barrier. The caller may release the
// DNS response only after this returns nil.
func (e *Engine) Admit(ctx context.Context, endpoint, lifetime string, response Response) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, err := e.current(endpoint, lifetime)
	if err != nil {
		return err
	}
	if !e.programmer.Attached(endpoint, lifetime) {
		return ErrEndpointGone
	}
	question := normalize(response.Question)
	matching := matchingRules(question, s.rules)
	if len(matching) == 0 {
		return ErrNotAllowed
	}
	if len(response.CNAMEs) > e.limits.CNAMEs || len(response.Addresses) > e.limits.Addresses {
		return ErrCapacity
	}
	terminal, deadlines, err := reachable(question, response, e.now(), e.limits.CNAMEs)
	if err != nil {
		return err
	}
	if len(terminal) == 0 {
		return nil
	} // negative/non-address response learns nothing
	for _, address := range terminal {
		if !e.now().Before(deadlines[address]) {
			return errors.New("matched dns answer has no remaining lifetime")
		}
	}
	newGrants := append([]Grant(nil), live(s.grants, e.now())...)
	for _, a := range terminal {
		for _, rule := range matching {
			newGrants = append(newGrants, Grant{Owner: rule.Owner, Address: a, Ports: append([]Port(nil), rule.Ports...), ExpiresAt: deadlines[a]})
		}
	}
	newGrants = dedupe(newGrants)
	if len(newGrants) > e.limits.Grants {
		return ErrCapacity
	}
	generation := s.generation
	if err := e.programmer.Replace(ctx, endpoint, lifetime, newGrants); err != nil {
		return fmt.Errorf("grant publication: %w", err)
	}
	if ctx.Err() != nil || s.generation != generation || !e.programmer.Attached(endpoint, lifetime) {
		_ = e.programmer.Replace(context.Background(), endpoint, lifetime, s.grants)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrEndpointGone
	}
	s.grants = newGrants
	return nil
}

// Matches reports whether the current immutable snapshot authorizes learning
// for a question. It does not itself authorize resolver transport.
func (e *Engine) Matches(endpoint, lifetime, question string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, err := e.current(endpoint, lifetime)
	return err == nil && len(matchingRules(normalize(question), s.rules)) != 0
}

func (e *Engine) current(endpoint, lifetime string) (*endpointState, error) {
	s, ok := e.endpoints[endpoint]
	if !ok || s.lifetime != lifetime {
		return nil, ErrEndpointGone
	}
	return s, nil
}
func normalize(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func matches(pattern, name string) bool {
	pattern, name = normalize(pattern), normalize(name)
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(name, suffix) && len(name) > len(suffix)
	}
	return pattern == name
}
func matchingRules(q string, rules []Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		if matches(r.Name, q) {
			out = append(out, r)
		}
	}
	return out
}
func cloneRules(in []Rule) []Rule {
	out := make([]Rule, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Name = normalize(in[i].Name)
		out[i].Ports = append([]Port(nil), in[i].Ports...)
	}
	return out
}
func contributionAllowed(g Grant, rules []Rule) bool {
	for _, r := range rules {
		if r.Owner == g.Owner && equalPorts(r.Ports, g.Ports) {
			return true
		}
	}
	return false
}
func equalPorts(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func live(in []Grant, now time.Time) []Grant {
	out := make([]Grant, 0, len(in))
	for _, g := range in {
		if now.Before(g.ExpiresAt) {
			out = append(out, g)
		}
	}
	return out
}
func dedupe(in []Grant) []Grant {
	out := make([]Grant, 0, len(in))
	for _, g := range in {
		found := false
		for i := range out {
			if out[i].Owner == g.Owner && out[i].Address == g.Address && equalPorts(out[i].Ports, g.Ports) {
				if g.ExpiresAt.After(out[i].ExpiresAt) {
					out[i].ExpiresAt = g.ExpiresAt
				}
				found = true
				break
			}
		}
		if !found {
			out = append(out, g)
		}
	}
	return out
}

func reachable(question string, response Response, now time.Time, maxDepth int) ([]netip.Addr, map[netip.Addr]time.Time, error) {
	edges := map[string]CNAMERecord{}
	for _, c := range response.CNAMEs {
		c.Name = normalize(c.Name)
		c.Target = normalize(c.Target)
		if c.TTL < 0 {
			return nil, nil, errors.New("negative cname ttl")
		}
		if old, ok := edges[c.Name]; ok && old.Target != c.Target {
			return nil, nil, errors.New("conflicting cname records")
		}
		edges[c.Name] = c
	}
	name := question
	deadline := time.Time{}
	seen := map[string]bool{}
	for depth := 0; ; depth++ {
		c, ok := edges[name]
		if !ok {
			break
		}
		if depth >= maxDepth || seen[name] {
			return nil, nil, errors.New("invalid cname chain")
		}
		seen[name] = true
		d := now.Add(c.TTL)
		if deadline.IsZero() || d.Before(deadline) {
			deadline = d
		}
		name = c.Target
	}
	var addresses []netip.Addr
	deadlines := map[netip.Addr]time.Time{}
	for _, a := range response.Addresses {
		if normalize(a.Name) != name || !a.Address.IsValid() || a.TTL < 0 {
			continue
		}
		d := now.Add(a.TTL)
		if !deadline.IsZero() && deadline.Before(d) {
			d = deadline
		}
		if old, ok := deadlines[a.Address]; !ok {
			addresses = append(addresses, a.Address)
			deadlines[a.Address] = d
		} else if d.Before(old) {
			deadlines[a.Address] = d
		}
	}
	return addresses, deadlines, nil
}
