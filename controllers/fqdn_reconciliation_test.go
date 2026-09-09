package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	policyv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type failingPolicyListClient struct{ client.Client }

func (c failingPolicyListClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("injected informer read failure")
}

type countingPolicyBPF struct {
	ebpf.MockBpfClient
	updates int
}

func (b *countingPolicyBPF) UpdateEbpfMaps(string, []fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules) error {
	b.updates++
	return nil
}

func TestPolicyListFailureCannotBecomeSuccessfulIsolationRemoval(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	_, _, k8sClient := newFQDNControllerTest(t, pod, &pe)
	bpf := &countingPolicyBPF{}
	r := NewPolicyEndpointsReconciler(failingPolicyListClient{k8sClient}, "192.0.2.1", bpf, false)
	require.Error(t, r.reconcilePolicyEndpoint(context.Background(), &pe))
	require.Zero(t, bpf.updates)
}

func TestDeletingPolicyEndpointStopsContributingStaticPermission(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod)
	pe.Spec.Egress = []policyv1.EndpointInfo{{CIDR: "0.0.0.0/0"}}
	deleted := metav1.NewTime(time.Now())
	pe.DeletionTimestamp = &deleted
	pe.Finalizers = []string{"test.example.com/hold"}
	_, _, k8sClient := newFQDNControllerTest(t, pod, &pe)
	r := NewPolicyEndpointsReconciler(k8sClient, "192.0.2.1", &ebpf.MockBpfClient{}, false)
	r.podIdentifierToPolicyEndpointMap.Store("worker-abc", []string{pe.Name})
	_, egress, _, _, err := r.deriveIngressAndEgressFirewallRules(context.Background(), "worker-abc", pe.Namespace, "", false)
	require.NoError(t, err)
	require.Empty(t, egress)
	parents, err := r.derivePolicyEndpointsOfParentNP(context.Background(), pe.Spec.PolicyRef.Name, pe.Namespace)
	require.NoError(t, err)
	require.Empty(t, parents)
}
