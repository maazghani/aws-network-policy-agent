package config

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestFQDNEnablementRequiresNetworkPolicyAndExplicitBudget(t *testing.T) {
	var cfg ControllerConfig
	cfg.BindFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))
	if cfg.FQDN.Enabled {
		t.Fatal("FQDN enabled by default")
	}
	if err := cfg.ValidControllerFlags(); err != nil {
		t.Fatal(err)
	}
	cfg.FQDN.Enabled = true
	if err := cfg.ValidControllerFlags(); err == nil {
		t.Fatal("enabled without network policy")
	}
	cfg.EnableNetworkPolicy = true
	if err := cfg.ValidControllerFlags(); err == nil {
		t.Fatal("enabled without measured limits")
	}
	cfg.FQDN = FQDNConfig{Enabled: true, Port: 15353, MaxEndpoints: 64,
		MaxRulesPerEndpoint: 32, MaxObservationsPerEndpoint: 128, MaxAddressesPerEndpoint: 128,
		MaxGrantsPerAddress: 16, MaxGrantsPerEndpoint: 256, MaxTotalObservations: 4096, MaxTotalGrants: 4096, MaxPending: 32, MaxPendingBytes: 4 << 20,
		MaxTCPSockets: 16, ExchangeTimeout: 2 * time.Second, TCPIdleTimeout: 30 * time.Second}
	if err := cfg.ValidControllerFlags(); err != nil {
		t.Fatal(err)
	}
	valid := cfg.FQDN
	for _, test := range []struct {
		name  string
		clear func(*FQDNConfig)
	}{
		{"grants-per-endpoint", func(c *FQDNConfig) { c.MaxGrantsPerEndpoint = 0 }},
		{"total-observations", func(c *FQDNConfig) { c.MaxTotalObservations = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.clear(&candidate)
			if err := candidate.Validate(true); err == nil {
				t.Fatal("missing budget accepted before datapath initialization")
			}
		})
	}
	cfg.FQDN.MaxPendingBytes = 65535
	if err := cfg.ValidControllerFlags(); err == nil {
		t.Fatal("unbounded/unreservable DNS exchange accepted")
	}
}
