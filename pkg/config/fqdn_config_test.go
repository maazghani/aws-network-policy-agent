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
	cfg.FQDN.MaxPendingBytes = 65535
	if err := cfg.ValidControllerFlags(); err == nil {
		t.Fatal("unbounded/unreservable DNS exchange accepted")
	}
}
