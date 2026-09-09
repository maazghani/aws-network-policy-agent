package fqdn

import "testing"

func TestANPDomainGrammar(t *testing.T) {
	for input, want := range map[string]string{"API.Example.COM.": "api.example.com", "*.EXAMPLE.com.": "*.example.com", "a_b.example.com": "a_b.example.com"} {
		got, err := NormalizeName(input)
		if err != nil || got != want {
			t.Fatalf("%q: got %q %v", input, got, err)
		}
	}
	for _, bad := range []string{"*", "*example.com", "a.*.com", "example", ".example.com", "example..com", "example.com..", "-a.example.com", "a_.example.com", "K.example.com", "é.example.com", "example.com\x00"} {
		if _, err := NormalizeName(bad); err == nil {
			t.Errorf("accepted invalid domain %q", bad)
		}
	}
	for _, test := range []struct {
		pattern, question string
		want              bool
	}{
		{"*.example.com", "example.com", false}, {"*.example.com", "a.example.com", true}, {"*.example.com", "a.b.example.com", true}, {"*.example.com", "badexample.com", false}, {"api.example.com", "API.EXAMPLE.COM.", true}, {"api.example.com", "a.api.example.com", false},
	} {
		if got := MatchName(test.pattern, test.question); got != test.want {
			t.Errorf("MatchName(%q,%q)=%v", test.pattern, test.question, got)
		}
	}
}

func TestPortConstraints(t *testing.T) {
	r, err := normalizeRule(Rule{Owner: "owner", Name: "example.com", Ports: []PortRange{{Protocol: 6, StartPort: 443}, {Protocol: 17, StartPort: 8000, EndPort: 9000}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Ports[0].EndPort != 443 || r.Ports[1].EndPort != 9000 {
		t.Fatalf("constraints lost: %+v", r)
	}
	for _, bad := range []PortRange{{Protocol: 6, EndPort: 80}, {StartPort: 443}, {Protocol: 6, StartPort: 90, EndPort: 80}, {Protocol: 1}} {
		if _, err := normalizeRule(Rule{Owner: "owner", Name: "example.com", Ports: []PortRange{bad}}); err == nil {
			t.Errorf("accepted invalid port %+v", bad)
		}
	}
	r, err = normalizeRule(Rule{Owner: "owner", Name: "example.com"})
	if err != nil || len(r.Ports) != 1 || r.Ports[0] != (PortRange{}) {
		t.Fatalf("omitted ports are not all ports: %+v %v", r, err)
	}
}
