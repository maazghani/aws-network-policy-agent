package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"sort"

	policyv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// PE chunks pack selectors and rules independently. Select the parent policy by
// a concrete pod association in ANY current chunk, then collect ALL its chunks.
// A deployment identifier is intentionally insufficient: replicas share static
// maps but must never share DNS authority.
func compileFQDNPolicy(pod *corev1.Pod, endpoints []policyv1.PolicyEndpoint, nodeIP string) (fqdn.Snapshot, error) {
	return compileFQDNPolicyBounded(pod, endpoints, nodeIP, fqdn.Limits{MaxRulesPerEndpoint: math.MaxInt, MaxGrantsPerAddress: math.MaxInt}, nil)
}

func compileFQDNPolicyBounded(pod *corev1.Pod, endpoints []policyv1.PolicyEndpoint, nodeIP string, limits fqdn.Limits, previous []fqdn.Rule) (fqdn.Snapshot, error) {
	var snapshot fqdn.Snapshot
	if pod.UID == "" || pod.Spec.HostNetwork || !pod.DeletionTimestamp.IsZero() {
		return snapshot, fmt.Errorf("%w: pod has no live UID or uses host networking", fqdn.ErrEndpoint)
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil || pod.Status.HostIP != nodeIP {
		return snapshot, fmt.Errorf("%w: pod is not assigned to this node", fqdn.ErrEndpoint)
	}
	selected := make(map[string]bool)
	for i := range endpoints {
		pe := &endpoints[i]
		if pe.Namespace != pod.Namespace || !pe.DeletionTimestamp.IsZero() {
			continue
		}
		if pe.Spec.PodSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(pe.Spec.PodSelector)
			if err != nil || !selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}
		for _, candidate := range pe.Spec.PodSelectorEndpoints {
			candidateIP, err := netip.ParseAddr(string(candidate.PodIP))
			if err == nil && candidate.Name == pod.Name && candidate.Namespace == pod.Namespace &&
				string(candidate.HostIP) == nodeIP && candidateIP == ip && string(candidate.PodIP) != nodeIP {
				selected[policyEndpointParent(pe)] = true
				break
			}
		}
	}
	var compileErr error
	oldOwners := make(map[string]bool, len(previous))
	for _, rule := range previous {
		oldOwners[rule.Owner] = true
	}
	admitted := make(map[string]bool)
	// Prefer surviving committed contributions when the new policy exceeds its
	// quota. The output and temporary port slices remain bounded throughout.
	for pass := 0; pass < 2; pass++ {
		for i := range endpoints {
			pe := &endpoints[i]
			if pe.Namespace != pod.Namespace || !pe.DeletionTimestamp.IsZero() || !selected[policyEndpointParent(pe)] {
				continue
			}
			for _, egress := range pe.Spec.Egress {
				if egress.DomainName == "" {
					continue
				}
				rule, err := compileFQDNRule(pe, egress, limits.MaxGrantsPerAddress)
				if err != nil {
					if compileErr == nil {
						compileErr = err
					}
					continue
				}
				if oldOwners[rule.Owner] != (pass == 0) || admitted[rule.Owner] {
					continue
				}
				if len(snapshot.Rules) >= limits.MaxRulesPerEndpoint {
					if compileErr == nil {
						compileErr = fqdn.ErrCapacity
					}
					continue
				}
				admitted[rule.Owner] = true
				snapshot.Rules = append(snapshot.Rules, rule)
			}
		}
	}
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].Owner < snapshot.Rules[j].Owner })
	return snapshot, compileErr
}

func compileFQDNRule(pe *policyv1.PolicyEndpoint, egress policyv1.EndpointInfo, maxPorts int) (fqdn.Rule, error) {
	if egress.CIDR != "" || len(egress.Except) != 0 {
		return fqdn.Rule{}, fmt.Errorf("%w: ambiguous domain entry in %s", fqdn.ErrPolicy, pe.Name)
	}
	if len(egress.Ports) > maxPorts {
		return fqdn.Rule{}, fqdn.ErrCapacity
	}
	name, err := fqdn.NormalizeName(string(egress.DomainName))
	if err != nil {
		return fqdn.Rule{}, fmt.Errorf("%s: %w", pe.Name, err)
	}
	ports, err := compileFQDNPorts(egress.Ports)
	if err != nil {
		return fqdn.Rule{}, fmt.Errorf("%s: %w", pe.Name, err)
	}
	rule := fqdn.Rule{Name: name, Ports: ports}
	encoded, _ := json.Marshal(rule)
	digest := sha256.Sum256(encoded)
	rule.Owner = policyEndpointOwner(pe) + "/" + hex.EncodeToString(digest[:])
	return rule, nil
}

func policyEndpointParent(pe *policyv1.PolicyEndpoint) string {
	for _, ref := range pe.OwnerReferences {
		if ref.Controller != nil && *ref.Controller && ref.UID != "" {
			return pe.Namespace + "/" + ref.Kind + "/" + string(ref.UID)
		}
	}
	return pe.Namespace + "/" + pe.Spec.PolicyRef.Name
}

func policyEndpointOwner(pe *policyv1.PolicyEndpoint) string {
	return policyEndpointParent(pe) + "/" + pe.Name + "/" + string(pe.UID)
}

func compileFQDNPorts(ports []policyv1.Port) ([]fqdn.PortRange, error) {
	if len(ports) == 0 {
		return nil, nil // Omitted list means all protocols and all ports.
	}
	result := make([]fqdn.PortRange, 0, len(ports))
	for _, port := range ports {
		protocol := corev1.ProtocolTCP
		if port.Protocol != nil {
			protocol = *port.Protocol
		}
		var rule fqdn.PortRange
		switch protocol {
		case corev1.ProtocolTCP:
			rule.Protocol = 6
		case corev1.ProtocolUDP:
			rule.Protocol = 17
		case corev1.ProtocolSCTP:
			rule.Protocol = 132
		default:
			return nil, fmt.Errorf("%w: unsupported transport %q", fqdn.ErrPolicy, protocol)
		}
		if port.Port != nil {
			if *port.Port < 1 || *port.Port > 65535 {
				return nil, fmt.Errorf("%w: invalid port %d", fqdn.ErrPolicy, *port.Port)
			}
			rule.StartPort, rule.EndPort = uint16(*port.Port), uint16(*port.Port)
		}
		if port.EndPort != nil {
			if port.Port == nil || *port.EndPort < *port.Port || *port.EndPort > 65535 {
				return nil, fmt.Errorf("%w: invalid port range", fqdn.ErrPolicy)
			}
			rule.EndPort = uint16(*port.EndPort)
		}
		result = append(result, rule)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.StartPort != b.StartPort {
			return a.StartPort < b.StartPort
		}
		return a.EndPort < b.EndPort
	})
	return result, nil
}
