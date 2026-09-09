package fqdn

import (
	"context"
	"errors"
	"net/netip"
)

// Exchange identifies a query by a verified pod lifetime and its original
// resolver. Listener/TC plumbing must construct this only from redirected
// traffic, never from caller-provided DNS payload metadata.
type Exchange struct {
	Endpoint, Lifetime string
	Resolver           netip.AddrPort
	Protocol           uint8
	WireQuery          []byte
}

type ResolverAuthorizer interface {
	AllowedResolver(ctx context.Context, endpoint, lifetime string, resolver netip.AddrPort, protocol uint8) (bool, error)
}

type Forwarder interface {
	Exchange(ctx context.Context, resolver netip.AddrPort, protocol uint8, query []byte) ([]byte, error)
}

// ProxyCore implements policy composition and the response publication
// barrier. Socket steering and transparent reply tuple preservation are kept
// outside this type and must be qualified on each supported host platform.
type ProxyCore struct {
	Engine     *Engine
	Authorizer ResolverAuthorizer
	Forwarder  Forwarder
	MaxRecords int
}

func (p *ProxyCore) Resolve(ctx context.Context, x Exchange) ([]byte, error) {
	if p.Engine == nil || p.Authorizer == nil || p.Forwarder == nil {
		return nil, errors.New("fqdn proxy is not ready")
	}
	allowed, err := p.Authorizer.AllowedResolver(ctx, x.Endpoint, x.Lifetime, x.Resolver, x.Protocol)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errors.New("resolver transport denied")
	}
	answer, err := p.Forwarder.Exchange(ctx, x.Resolver, x.Protocol, x.WireQuery)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseResponse(x.WireQuery, answer, p.MaxRecords)
	if err != nil {
		return nil, err
	}
	// Independently allowed service-discovery queries are forwarded but only a
	// matching FQDN question is permitted to populate dynamic grants.
	if !p.Engine.Matches(x.Endpoint, x.Lifetime, parsed.Question) {
		return answer, nil
	}
	if err := p.Engine.Admit(ctx, x.Endpoint, x.Lifetime, parsed); err != nil {
		return nil, err // listener returns SERVFAIL or closes; never releases answer
	}
	return answer, nil
}
