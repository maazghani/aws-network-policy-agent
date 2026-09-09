package fwruleprocessor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFQDNRulesNeverEnterSharedStaticLPMMap(t *testing.T) {
	for _, tt := range []struct {
		node, mask string
		ipv6       bool
	}{{"192.0.2.1", "/32", false}, {"2001:db8::1", "/128", true}} {
		processor := NewFirewallRuleProcessor(tt.node, tt.mask, tt.ipv6)
		baseline, err := processor.ComputeMapEntriesFromEndpointRules(nil)
		require.NoError(t, err)
		withDomains, err := processor.ComputeMapEntriesFromEndpointRules([]EbpfFirewallRules{{DomainName: "api.example.com", PolicyOwner: "tenant/pe/uid"}})
		require.NoError(t, err)
		require.Equal(t, baseline, withDomains)
	}
}
