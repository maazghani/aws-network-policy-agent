package controllers

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	policyv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fqdnControllerBackend struct {
	staged      bool
	events      []string
	failReplace bool
	ifIndex     uint32
	stages      map[string][]string
}

func (b *fqdnControllerBackend) WithFence(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (b *fqdnControllerBackend) Bind(context.Context, fqdn.Endpoint) error {
	b.events = append(b.events, "bind")
	return nil
}
func (b *fqdnControllerBackend) Replace(_ context.Context, ep fqdn.Endpoint, _ uint64, _ []fqdn.Grant) error {
	b.events = append(b.events, "replace")
	if b.failReplace {
		return errors.New("injected map update failure")
	}
	if b.ifIndex != 0 && ep.IfIndex != b.ifIndex {
		return fqdn.ErrEndpoint
	}
	return nil
}
func (b *fqdnControllerBackend) Check(context.Context, fqdn.Endpoint, uint64, []fqdn.Grant) error {
	if b.staged {
		return fqdn.ErrNoPermission
	}
	return nil
}
func (b *fqdnControllerBackend) Delete(context.Context, fqdn.Endpoint) error {
	b.events = append(b.events, "delete")
	return nil
}
func (b *fqdnControllerBackend) ResolveFQDNEndpoint(_ context.Context, pod *corev1.Pod, identifier string) (fqdn.Endpoint, error) {
	index := b.ifIndex
	if index == 0 {
		index = 7
	}
	return fqdn.Endpoint{UID: string(pod.UID), Name: pod.Name, Namespace: pod.Namespace, PodIdentifier: identifier, IfIndex: index, IP: netip.MustParseAddr(pod.Status.PodIP)}, nil
}
func (b *fqdnControllerBackend) BeginFQDNPolicyUpdateFor(_ context.Context, transaction string, scope []string) error {
	if b.stages == nil {
		b.stages = make(map[string][]string)
	}
	b.stages[transaction] = scope
	b.staged = true
	b.events = append(b.events, "begin")
	return nil
}
func (b *fqdnControllerBackend) EndFQDNPolicyUpdateFor(_ context.Context, transaction string, success bool) error {
	if success {
		delete(b.stages, transaction)
	}
	if success && len(b.stages) == 0 {
		b.staged = false
		b.events = append(b.events, "ready")
	} else {
		b.events = append(b.events, "blocked")
	}
	return nil
}

func newFQDNControllerTest(t *testing.T, objects ...client.Object) (*FQDNPolicyHandler, *fqdnControllerBackend, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	backend := &fqdnControllerBackend{}
	engine, err := fqdn.NewEngine(fqdn.Config{PublicationTimeout: time.Second, Limits: fqdn.Limits{MaxEndpoints: 8, MaxRulesPerEndpoint: 8, MaxObservationsPerEndpoint: 8, MaxAddressesPerEndpoint: 8, MaxGrantsPerAddress: 8, MaxGrantsPerEndpoint: 8, MaxTotalObservations: 32, MaxTotalGrants: 32}}, backend)
	require.NoError(t, err)
	return NewFQDNPolicyHandler(k8sClient, "192.0.2.1", engine, backend), backend, k8sClient
}

func TestFQDNControllerStagesStaticAndDynamicChangesBeforeReadiness(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	h, backend, k8sClient := newFQDNControllerTest(t, pod, &pe)
	ctx := context.Background()
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error {
		require.True(t, backend.staged)
		backend.events = append(backend.events, "static")
		return nil
	}))
	require.Equal(t, []string{"begin", "static", "bind", "replace", "ready"}, backend.events)
	ep := h.endpoints[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]
	matched, err := h.engine.Matches(ep, "api.example.com")
	require.NoError(t, err)
	require.True(t, matched)
	// Final rule removal must revoke its authority without first removing DNS
	// steering while the stale static maps remain visible.
	require.NoError(t, k8sClient.Delete(ctx, &pe))
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error {
		matched, err := h.engine.Matches(ep, "api.example.com")
		require.NoError(t, err)
		require.False(t, matched)
		require.True(t, backend.staged)
		return nil
	}))
	retained, ok := h.engine.Lookup(ep.IfIndex, ep.IP)
	require.True(t, ok)
	require.Equal(t, ep, retained)
}

func TestFQDNControllerFailedTransactionCannotBeReopenedByAnotherPolicy(t *testing.T) {
	h, backend, _ := newFQDNControllerTest(t)
	ctx := context.Background()
	require.Error(t, h.apply(ctx, "tenant", "pe/failed", func() error { return errors.New("static deletion failed") }))
	require.True(t, backend.staged)
	require.NoError(t, h.apply(ctx, "tenant", "pe/unrelated", func() error { return nil }))
	require.True(t, backend.staged, "another PE in the same namespace cannot authorize stale static maps")
	require.NoError(t, h.apply(ctx, "tenant", "pe/failed", func() error { return nil }))
	require.False(t, backend.staged)
}

func TestFQDNControllerDeletionAndReusedIdentityDoNotRetainLifetime(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	h, _, k8sClient := newFQDNControllerTest(t, pod, &pe)
	ctx := context.Background()
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	name := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	before := h.endpoints[name]
	require.NoError(t, k8sClient.Delete(ctx, pod))
	// A Pod deletion must work with stale PE selectors and without requiring a
	// fresh static attachment or a namespace/CPE controller callback.
	_, err := h.Reconcile(ctx, ctrl.Request{NamespacedName: name})
	require.NoError(t, err)
	_, ok := h.engine.Lookup(before.IfIndex, before.IP)
	require.False(t, ok)
	pod.ResourceVersion = ""
	pod.UID = "replacement-uid"
	require.NoError(t, k8sClient.Create(ctx, pod))
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	after := h.endpoints[name]
	require.NotEqual(t, before.UID, after.UID)
	require.NotEqual(t, before.Lifetime, after.Lifetime)
}

func TestFQDNControllerFailedMapWriteLeavesReadinessBlocked(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	h, backend, _ := newFQDNControllerTest(t, pod, &pe)
	backend.failReplace = true
	require.Error(t, h.apply(context.Background(), "tenant", "pe/p-0", func() error { return nil }))
	require.True(t, backend.staged)
	require.Empty(t, h.endpoints)
}

func TestFQDNControllerRetriesAfterFailedPolicyReplacement(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	h, backend, _ := newFQDNControllerTest(t, pod, &pe)
	ctx := context.Background()
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	name := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	before := h.endpoints[name]
	backend.failReplace = true
	require.Error(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	require.True(t, backend.staged)
	require.Len(t, h.endpoints, 1)
	backend.failReplace = false
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	require.False(t, backend.staged)
	require.Equal(t, before.Lifetime, h.endpoints[name].Lifetime)
}

func TestFQDNControllerRejectedPortExpansionKeepsIndependentPermissionReady(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	removed := fqdnTestPE("z-0", "z", pod, "removed.example.com")
	port443, port80 := int32(443), int32(80)
	pe.Spec.Egress[0].Ports = []policyv1.Port{{Port: &port443}}
	removed.Spec.Egress[0].Ports = []policyv1.Port{{Port: &port443}}
	h, backend, k8sClient := newFQDNControllerTest(t, pod, &pe, &removed)
	var err error
	h.engine, err = fqdn.NewEngine(fqdn.Config{PublicationTimeout: time.Second, Limits: fqdn.Limits{MaxEndpoints: 8, MaxRulesPerEndpoint: 8, MaxObservationsPerEndpoint: 8, MaxAddressesPerEndpoint: 8, MaxGrantsPerAddress: 1, MaxGrantsPerEndpoint: 8, MaxTotalObservations: 32, MaxTotalGrants: 32}}, backend)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	ep := h.endpoints[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]
	now, err := (fqdn.BootClock{}).Now()
	require.NoError(t, err)
	address := netip.MustParseAddr("203.0.113.10")
	require.NoError(t, h.engine.Publish(ctx, ep, "api.example.com", []fqdn.Observation{{Name: "api.example.com", Address: address, ExpiresAt: now + uint64(time.Minute)}}, func(context.Context, []uint32) error { return nil }))
	require.NoError(t, h.engine.Publish(ctx, ep, "removed.example.com", []fqdn.Observation{{Name: "removed.example.com", Address: netip.MustParseAddr("203.0.113.20"), ExpiresAt: now + uint64(time.Minute)}}, func(context.Context, []uint32) error { return nil }))
	require.NoError(t, k8sClient.Delete(ctx, &removed))
	pe.Spec.Egress = append(pe.Spec.Egress, policyv1.EndpointInfo{DomainName: "api.example.com", Ports: []policyv1.Port{{Port: &port80}}})
	require.NoError(t, k8sClient.Update(ctx, &pe))
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	require.False(t, backend.staged)
	diagnostic, err := h.engine.Inspect(ep)
	require.NoError(t, err)
	require.Len(t, diagnostic.Grants, 1)
	require.Equal(t, address, diagnostic.Grants[0].Address)
	require.EqualValues(t, 443, diagnostic.Grants[0].StartPort)
	for _, rule := range diagnostic.Rules {
		require.NotEqual(t, "removed.example.com", rule.Name)
	}
}

func TestFQDNControllerRecreatedVethGetsNewLifetime(t *testing.T) {
	pod := fqdnTestPod("worker-abc-1", "10.0.0.1")
	pe := fqdnTestPE("p-0", "p", pod, "api.example.com")
	h, backend, _ := newFQDNControllerTest(t, pod, &pe)
	ctx := context.Background()
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	name := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	before := h.endpoints[name]
	backend.ifIndex = 8
	require.NoError(t, h.apply(ctx, "tenant", "pe/p-0", func() error { return nil }))
	after := h.endpoints[name]
	require.Equal(t, before.UID, after.UID)
	require.Equal(t, before.IP, after.IP)
	require.NotEqual(t, before.IfIndex, after.IfIndex)
	require.NotEqual(t, before.Lifetime, after.Lifetime)
	_, oldAlive := h.engine.Lookup(before.IfIndex, before.IP)
	require.False(t, oldAlive)
}
