// Package fqdn owns endpoint-local DNS observations and the publication barrier
// between resolver answers and effective datapath permission.
package fqdn

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var (
	ErrEndpoint     = errors.New("FQDN endpoint is not enrolled or its lifetime changed")
	ErrPolicy       = errors.New("invalid FQDN policy")
	ErrCapacity     = errors.New("FQDN capacity exhausted")
	ErrExpired      = errors.New("FQDN answer has no remaining authorized lifetime")
	ErrNoPermission = errors.New("FQDN answer has no effective permission")
)

// Endpoint is an immutable workload/interface lifetime. IP and ifindex alone
// cannot identify it: both are reusable. Lifetime is assigned by Engine.Enroll.
type Endpoint struct {
	UID, PodIdentifier, Namespace, Name string
	IfIndex                             uint32
	IP                                  netip.Addr
	Lifetime                            uint64
}

// Protocol zero means every transport. Port zero/zero means every port.
type PortRange struct {
	Protocol           uint8
	StartPort, EndPort uint16
}

type Rule struct {
	Owner string
	Name  string
	Ports []PortRange
}

// Snapshot is copied and normalized on installation; callers may reuse inputs.
type Snapshot struct {
	Revision uint64
	Rules    []Rule
}

// ExpiresAt and Deadline are absolute CLOCK_BOOTTIME nanoseconds, including
// suspend time. A DNS parser must take the earliest supporting CNAME/A/AAAA TTL.
type Observation struct {
	Name      string
	Address   netip.Addr
	ExpiresAt uint64
}

type Grant struct {
	Address            netip.Addr
	Protocol           uint8
	StartPort, EndPort uint16
	Deadline           uint64
	// Names are observed question names supporting this permission. They let
	// the backend retain bounded established-flow proof after DNS expiry.
	Names []string
}

type PolicyBackend interface {
	ReconcilePolicy(context.Context, Endpoint, Snapshot) error
}

// Backend methods are synchronous. WithFence serializes shared static policy
// refreshes with the entire admission/check/response-write interval. Its context
// and the response writer must have bounded cancellation and I/O deadlines.
type Backend interface {
	WithFence(context.Context, func(context.Context) error) error
	Bind(context.Context, Endpoint) error
	Replace(context.Context, Endpoint, uint64, []Grant) error
	Check(context.Context, Endpoint, uint64, []Grant) error
	Delete(context.Context, Endpoint) error
}

// Clock reads the same time domain used by bpf_ktime_get_boot_ns.
type Clock interface{ Now() (uint64, error) }

// Limits are explicit qualification inputs, not asserted production defaults.
// All fields must be positive. Per-address limits count distinct L4 intervals.
type Limits struct {
	MaxEndpoints               int
	MaxRulesPerEndpoint        int
	MaxObservationsPerEndpoint int
	MaxAddressesPerEndpoint    int
	MaxGrantsPerAddress        int
	MaxGrantsPerEndpoint       int
	MaxTotalObservations       int
	MaxTotalGrants             int
}

type Config struct {
	Limits             Limits
	PublicationTimeout time.Duration
	Clock              Clock
}

type Stats struct {
	Endpoints, Rules, Observations, Addresses, Grants int
	Admissions, Failures, Revocations, Expired        uint64
}

type EndpointDiagnostic struct {
	Endpoint     Endpoint
	Revision     uint64
	Rules        []Rule
	Observations []Observation
	Grants       []Grant
}
