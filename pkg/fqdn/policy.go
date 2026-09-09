package fqdn

import (
	"fmt"
	"slices"
	"strings"
)

// NormalizeName implements the ANP ASCII domain grammar, including an optional
// leading wildcard. A wildcard matches descendant labels and excludes the apex.
func NormalizeName(name string) (string, error) {
	if len(name) > 256 {
		return "", fmt.Errorf("%w: domain exceeds maximum DNS length", ErrPolicy)
	}
	for i := range name {
		if name[i] >= 128 {
			return "", fmt.Errorf("%w: non-ASCII domain", ErrPolicy)
		}
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	labels := name
	if strings.HasPrefix(labels, "*.") {
		labels = labels[2:]
	}
	if len(labels) > 253 || !strings.Contains(labels, ".") {
		return "", fmt.Errorf("%w: domain %q", ErrPolicy, name)
	}
	for _, label := range strings.Split(labels, ".") {
		if len(label) == 0 || len(label) > 63 || !alphaNumeric(label[0]) || !alphaNumeric(label[len(label)-1]) {
			return "", fmt.Errorf("%w: domain %q", ErrPolicy, name)
		}
		for i := range label {
			if !alphaNumeric(label[i]) && label[i] != '-' && label[i] != '_' {
				return "", fmt.Errorf("%w: domain %q", ErrPolicy, name)
			}
		}
	}
	return name, nil
}

func alphaNumeric(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

// MatchName accepts normalized names; invalid inputs are never a match.
func MatchName(pattern, question string) bool {
	pattern, err := NormalizeName(pattern)
	if err != nil {
		return false
	}
	question, err = NormalizeName(question)
	if err != nil || strings.Contains(question, "*") {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(question, pattern[1:]) && len(question) > len(pattern)-1
	}
	return pattern == question
}

func normalizeRule(rule Rule) (Rule, error) {
	if rule.Owner == "" {
		return Rule{}, fmt.Errorf("%w: missing rule owner", ErrPolicy)
	}
	name, err := NormalizeName(rule.Name)
	if err != nil {
		return Rule{}, err
	}
	result := Rule{Owner: rule.Owner, Name: name}
	if len(rule.Ports) == 0 {
		result.Ports = []PortRange{{}}
		return result, nil
	}
	for _, port := range rule.Ports {
		if port.Protocol != 0 && port.Protocol != 6 && port.Protocol != 17 && port.Protocol != 132 {
			return Rule{}, fmt.Errorf("%w: unsupported protocol %d", ErrPolicy, port.Protocol)
		}
		if port.StartPort == 0 && port.EndPort != 0 || port.StartPort != 0 && port.Protocol == 0 {
			return Rule{}, fmt.Errorf("%w: invalid unspecified port/protocol", ErrPolicy)
		}
		if port.StartPort > 0 && port.EndPort == 0 {
			port.EndPort = port.StartPort
		}
		if port.EndPort < port.StartPort {
			return Rule{}, fmt.Errorf("%w: inverted port range", ErrPolicy)
		}
		result.Ports = append(result.Ports, port)
	}
	slices.SortFunc(result.Ports, func(a, b PortRange) int {
		if a.Protocol != b.Protocol {
			return int(a.Protocol) - int(b.Protocol)
		}
		if a.StartPort != b.StartPort {
			return int(a.StartPort) - int(b.StartPort)
		}
		return int(a.EndPort) - int(b.EndPort)
	})
	result.Ports = slices.Compact(result.Ports)
	return result, nil
}

func cloneRules(rules []Rule) []Rule {
	result := make([]Rule, len(rules))
	for i, r := range rules {
		result[i] = r
		result[i].Ports = slices.Clone(r.Ports)
	}
	return result
}

func sameRule(a, b Rule) bool {
	return a.Owner == b.Owner && a.Name == b.Name && slices.Equal(a.Ports, b.Ports)
}

func matching(rules []Rule, name string) []Rule {
	var result []Rule
	for _, r := range rules {
		if MatchName(r.Name, name) {
			result = append(result, r)
		}
	}
	return result
}
