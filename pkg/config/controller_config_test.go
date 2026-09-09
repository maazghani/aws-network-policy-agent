package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestFQDNPolicyFeatureGateDefaultsOff(t *testing.T) {
	var cfg ControllerConfig
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	cfg.BindFlags(fs)
	if cfg.EnableFQDNPolicy {
		t.Fatal("FQDN policy must be opt-in")
	}
	if err := fs.Parse([]string{"--enable-fqdn-policy"}); err != nil {
		t.Fatal(err)
	}
	if !cfg.EnableFQDNPolicy {
		t.Fatal("feature gate did not enable FQDN policy")
	}
}
