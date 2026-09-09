package controllers

import "testing"

func TestNormalizeDomainName(t *testing.T) {
	tests := map[string]string{
		"API.Example.COM.":   "api.example.com",
		"*.Service.LOCAL.":   "*.service.local",
		"already.normalized": "already.normalized",
	}
	for input, want := range tests {
		if got := normalizeDomainName(input); got != want {
			t.Errorf("normalizeDomainName(%q) = %q, want %q", input, got, want)
		}
	}
}
