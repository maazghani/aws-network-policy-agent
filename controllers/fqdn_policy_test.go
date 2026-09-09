package controllers

import (
	"testing"

	policyv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func fqdnTestPod(name, ip string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant", UID: types.UID(name + "-uid"), Labels: map[string]string{"app": "worker"}}, Status: corev1.PodStatus{PodIP: ip, HostIP: "192.0.2.1"}}
}

func fqdnTestPE(name, parent string, pod *corev1.Pod, domains ...string) policyv1.PolicyEndpoint {
	controller := true
	pe := policyv1.PolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant", UID: types.UID(name + "-uid"), OwnerReferences: []metav1.OwnerReference{{Kind: "ApplicationNetworkPolicy", Name: parent, UID: types.UID(parent + "-uid"), Controller: &controller}}}, Spec: policyv1.PolicyEndpointSpec{PolicyRef: policyv1.PolicyReference{Name: parent, Namespace: "tenant"}, PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}}}
	if pod != nil {
		pe.Spec.PodSelectorEndpoints = []policyv1.PodEndpoint{{Name: pod.Name, Namespace: pod.Namespace, PodIP: policyv1.NetworkAddress(pod.Status.PodIP), HostIP: policyv1.NetworkAddress(pod.Status.HostIP)}}
	}
	for _, domain := range domains {
		pe.Spec.Egress = append(pe.Spec.Egress, policyv1.EndpointInfo{DomainName: policyv1.DomainName(domain)})
	}
	return pe
}

func TestFQDNCompilerAssociatesConcretePodsAcrossPEChunks(t *testing.T) {
	first := fqdnTestPod("worker-abc-1", "10.0.0.1")
	sibling := fqdnTestPod("worker-abc-2", "10.0.0.2")
	policies := []policyv1.PolicyEndpoint{
		fqdnTestPE("p-selectors", "p", first),
		fqdnTestPE("p-addresses", "p", nil, "API.Example.COM."),
		fqdnTestPE("other-selectors", "other", sibling, "sibling.example.com"),
	}
	snapshot, err := compileFQDNPolicy(first, policies, "192.0.2.1")
	require.NoError(t, err)
	require.Len(t, snapshot.Rules, 1)
	require.Equal(t, "api.example.com", snapshot.Rules[0].Name)
	snapshot, err = compileFQDNPolicy(sibling, policies, "192.0.2.1")
	require.NoError(t, err)
	require.Len(t, snapshot.Rules, 1)
	require.Equal(t, "sibling.example.com", snapshot.Rules[0].Name)
	// A stale association for a reused pod name cannot enroll a different IP.
	first.Status.PodIP = "10.0.0.99"
	snapshot, err = compileFQDNPolicy(first, policies, "192.0.2.1")
	require.NoError(t, err)
	require.Empty(t, snapshot.Rules)
}

func TestFQDNCompilerKeepsIndependentOwnersAndRevokesMalformedContribution(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	policies := []policyv1.PolicyEndpoint{fqdnTestPE("a-0", "a", pod, "same.example.com"), fqdnTestPE("b-0", "b", pod, "same.example.com")}
	before, err := compileFQDNPolicy(pod, policies, "192.0.2.1")
	require.NoError(t, err)
	require.Len(t, before.Rules, 2)
	require.NotEqual(t, before.Rules[0].Owner, before.Rules[1].Owner)
	policies[0].Spec.Egress[0].DomainName = "bad*pattern.example.com"
	after, err := compileFQDNPolicy(pod, policies, "192.0.2.1")
	require.Error(t, err)
	require.Len(t, after.Rules, 1)
	require.Equal(t, before.Rules[1], after.Rules[0])
	// Policy and PE recreation change ownership even if names match.
	policies[1].OwnerReferences[0].UID = "new-policy-uid"
	policies[1].UID = "new-pe-uid"
	recreated, _ := compileFQDNPolicy(pod, policies[1:], "192.0.2.1")
	require.NotEqual(t, after.Rules[0].Owner, recreated.Rules[0].Owner)
}

func TestFQDNCompilerDoesNotCombineDifferentPolicyKinds(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	selecting := fqdnTestPE("np-selectors", "same-name", pod)
	selecting.OwnerReferences[0].Kind = "NetworkPolicy"
	selecting.OwnerReferences[0].UID = "namespace-network-policy"
	domain := fqdnTestPE("anp-rules", "same-name", nil, "denied.example.com")
	compiled, err := compileFQDNPolicy(pod, []policyv1.PolicyEndpoint{selecting, domain}, "192.0.2.1")
	require.NoError(t, err)
	require.Empty(t, compiled.Rules)
}

func TestFQDNPortsRetainTransportAndRanges(t *testing.T) {
	port, end := int32(443), int32(445)
	udp := corev1.ProtocolUDP
	tcpAll, err := compileFQDNPorts([]policyv1.Port{{}})
	require.NoError(t, err)
	require.EqualValues(t, 6, tcpAll[0].Protocol)
	require.Zero(t, tcpAll[0].StartPort)
	all, err := compileFQDNPorts(nil)
	require.NoError(t, err)
	require.Empty(t, all)
	rangePorts, err := compileFQDNPorts([]policyv1.Port{{Protocol: &udp, Port: &port, EndPort: &end}})
	require.NoError(t, err)
	require.EqualValues(t, 17, rangePorts[0].Protocol)
	require.EqualValues(t, 443, rangePorts[0].StartPort)
	require.EqualValues(t, 445, rangePorts[0].EndPort)
	_, err = compileFQDNPorts([]policyv1.Port{{EndPort: &end}})
	require.Error(t, err)
	invalid := int32(65536)
	_, err = compileFQDNPorts([]policyv1.Port{{Port: &invalid}})
	require.Error(t, err)
}

func TestFQDNCompilerRejectsUnverifiedPodLifetime(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	pod.UID = ""
	_, err := compileFQDNPolicy(pod, []policyv1.PolicyEndpoint{pe}, "192.0.2.1")
	require.Error(t, err)
}

func TestFQDNCompilerCapacityPreservesSurvivingOwners(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	old := fqdnTestPE("z-0", "z", pod, "surviving.example.com")
	previous, err := compileFQDNPolicy(pod, []policyv1.PolicyEndpoint{old}, "192.0.2.1")
	require.NoError(t, err)
	newPolicy := fqdnTestPE("a-0", "a", pod, "new.example.com", "another.example.com")
	limits := fqdn.Limits{MaxRulesPerEndpoint: 1, MaxGrantsPerAddress: 1}
	current, err := compileFQDNPolicyBounded(pod, []policyv1.PolicyEndpoint{newPolicy, old}, "192.0.2.1", limits, previous.Rules)
	require.ErrorIs(t, err, fqdn.ErrCapacity)
	require.Equal(t, previous.Rules, current.Rules)
	// An absent old owner cannot survive quota pressure on the replacement.
	current, err = compileFQDNPolicyBounded(pod, []policyv1.PolicyEndpoint{newPolicy}, "192.0.2.1", limits, previous.Rules)
	require.ErrorIs(t, err, fqdn.ErrCapacity)
	require.Len(t, current.Rules, 1)
	require.NotEqual(t, previous.Rules[0].Owner, current.Rules[0].Owner)
}
