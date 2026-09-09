package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/pflag"
)

// FQDNConfig is explicit while node and resolver qualification is pending.
// Resource limits have no production defaults: enablement requires a measured budget.
type FQDNConfig struct {
	Enabled                    bool
	Diagnostics                bool
	Port                       int
	MaxEndpoints               int
	MaxRulesPerEndpoint        int
	MaxObservationsPerEndpoint int
	MaxAddressesPerEndpoint    int
	MaxGrantsPerAddress        int
	MaxGrantsPerEndpoint       int
	MaxTotalObservations       int
	MaxTotalGrants             int
	MaxPending                 int
	MaxPendingBytes            int64
	MaxTCPSockets              int
	ExchangeTimeout            time.Duration
	TCPIdleTimeout             time.Duration
}

func (cfg *FQDNConfig) BindFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&cfg.Enabled, "enable-fqdn-egress", false, "Enable experimental endpoint-specific FQDN egress enforcement")
	fs.BoolVar(&cfg.Diagnostics, "fqdn-diagnostics", false, "Expose endpoint and domain diagnostics on the local agent socket")
	fs.IntVar(&cfg.Port, "fqdn-proxy-port", 15353, "Transparent DNS listener port")
	fs.IntVar(&cfg.MaxEndpoints, "fqdn-max-endpoints", 0, "Maximum enrolled FQDN endpoints; required when enabled")
	fs.IntVar(&cfg.MaxRulesPerEndpoint, "fqdn-max-rules-per-endpoint", 0, "Maximum compiled FQDN rules per endpoint")
	fs.IntVar(&cfg.MaxObservationsPerEndpoint, "fqdn-max-observations-per-endpoint", 0, "Maximum retained DNS observations per endpoint")
	fs.IntVar(&cfg.MaxAddressesPerEndpoint, "fqdn-max-addresses-per-endpoint", 0, "Maximum learned addresses per endpoint")
	fs.IntVar(&cfg.MaxGrantsPerAddress, "fqdn-max-grants-per-address", 0, "Maximum L4 contributions for a learned address")
	fs.IntVar(&cfg.MaxGrantsPerEndpoint, "fqdn-max-grants-per-endpoint", 0, "Maximum dynamic L4 grants per endpoint")
	fs.IntVar(&cfg.MaxTotalObservations, "fqdn-max-total-observations", 0, "Maximum DNS observations across the node")
	fs.IntVar(&cfg.MaxTotalGrants, "fqdn-max-total-grants", 0, "Maximum dynamic grants across the node")
	fs.IntVar(&cfg.MaxPending, "fqdn-max-pending", 0, "Maximum concurrent DNS exchanges")
	fs.Int64Var(&cfg.MaxPendingBytes, "fqdn-max-pending-bytes", 0, "Maximum bytes reserved for DNS exchanges")
	fs.IntVar(&cfg.MaxTCPSockets, "fqdn-max-tcp-sockets", 0, "Maximum accepted TCP DNS connections")
	fs.DurationVar(&cfg.ExchangeTimeout, "fqdn-exchange-timeout", 0, "Deadline for forwarding, programming, and publishing a DNS answer")
	fs.DurationVar(&cfg.TCPIdleTimeout, "fqdn-tcp-idle-timeout", 0, "Maximum idle time for a persistent TCP DNS connection")
}

func (cfg FQDNConfig) Validate(networkPolicy bool) error {
	if !cfg.Enabled {
		return nil
	}
	if !networkPolicy {
		return errors.New("FQDN egress requires --enable-network-policy=true")
	}
	if cfg.Port < 1024 || cfg.Port > 65535 {
		return errors.New("fqdn-proxy-port must be between 1024 and 65535")
	}
	for name, value := range map[string]int{
		"endpoints": cfg.MaxEndpoints, "rules-per-endpoint": cfg.MaxRulesPerEndpoint,
		"observations-per-endpoint": cfg.MaxObservationsPerEndpoint,
		"addresses-per-endpoint":    cfg.MaxAddressesPerEndpoint,
		"grants-per-address":        cfg.MaxGrantsPerAddress, "total-grants": cfg.MaxTotalGrants,
		"pending": cfg.MaxPending, "tcp-sockets": cfg.MaxTCPSockets,
	} {
		if value <= 0 {
			return fmt.Errorf("fqdn-max-%s must be explicitly configured and positive", name)
		}
	}
	// These are kernel ABI hard caps, not recommended operational budgets.
	if cfg.MaxEndpoints > 4096 || cfg.MaxTotalGrants > 65536 || cfg.MaxGrantsPerAddress > 24 {
		return errors.New("FQDN budgets exceed kernel hard caps: 4096 endpoints, 65536 grants, 24 L4 intervals per address")
	}
	if cfg.MaxPendingBytes < 2*65535 {
		return errors.New("fqdn-max-pending-bytes must reserve at least one maximum-size DNS request and response")
	}
	if cfg.ExchangeTimeout <= 0 || cfg.TCPIdleTimeout <= 0 {
		return errors.New("FQDN exchange and TCP idle timeouts must be explicitly configured and positive")
	}
	return nil
}
