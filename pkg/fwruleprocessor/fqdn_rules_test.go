package fwruleprocessor

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
)

func TestDomainRuleDoesNotEnterStaticMap(t *testing.T) {
	processor := NewFirewallRuleProcessor("192.0.2.1", "/32", false)
	withDomain, err := processor.ComputeMapEntriesFromEndpointRules([]EbpfFirewallRules{{
		DomainName:  "api.example.com",
		PolicyOwner: "default/policy-0",
		L4Info:      []v1alpha1.Port{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	withoutDomain, err := processor.ComputeMapEntriesFromEndpointRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(withDomain) != len(withoutDomain) {
		t.Fatalf("domain rule changed shared static map size: got %d, want %d", len(withDomain), len(withoutDomain))
	}
	for key, want := range withoutDomain {
		got, ok := withDomain[key]
		if !ok || string(got) != string(want) {
			t.Fatalf("domain rule changed shared static map entry %x", key)
		}
	}
}
