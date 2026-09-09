package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

type fqdnMap interface {
	Get([]byte, []byte) error
	Put([]byte, []byte) error
	Delete([]byte) error
	Keys() ([]string, error)
	ID() uint32
}
type fqdnSDKMap struct{ m goebpfmaps.BpfMap }

func (m *fqdnSDKMap) Get(k, v []byte) error {
	return fqdnMapSyscall(m.m.MapFD, unix.BPF_MAP_LOOKUP_ELEM, k, v)
}
func (m *fqdnSDKMap) Put(k, v []byte) error {
	err := m.m.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&k[0])), uintptr(unsafe.Pointer(&v[0])), 0)
	runtime.KeepAlive(k)
	runtime.KeepAlive(v)
	return err
}
func (m *fqdnSDKMap) Delete(k []byte) error {
	return fqdnMapSyscall(m.m.MapFD, unix.BPF_MAP_DELETE_ELEM, k, nil)
}
func (m *fqdnSDKMap) Keys() ([]string, error) { return fqdnMapKeys(m.m) }
func (m *fqdnSDKMap) ID() uint32              { return m.m.MapID }

type fqdnBinding struct {
	endpoint     fqdn.Endpoint
	revision     uint64
	grants       map[fqdnGrantKey]fqdnGrantValue
	observations []fqdn.Grant
	policy       fqdn.Snapshot
	flowNames    map[fqdnFlowKey][]string
}

// FQDNBackend shares one bounded publication fence with the existing static map
// APIs. A successful response cannot race an agent-owned static-map refresh.
// Only NewFQDNBackend enables this path; existing BpfClient callers remain valid.
type FQDNBackend struct {
	readPolicy func(fqdn.Endpoint, netip.Addr) (fqdnStaticPolicy, error)
	client     *bpfClient
	staging    bool
	gate       chan struct{}
	maps       map[string]fqdnMap
	bound      map[uint32]*fqdnBinding
	verify     func(context.Context, fqdn.Endpoint) error
	now        func() (uint64, error)
}

var _ fqdn.Backend = (*FQDNBackend)(nil)

func NewFQDNBackend(client BpfClient) (_ *FQDNBackend, err error) {
	started := time.Now()
	defer func() { fqdn.Observe("recovery", started, err) }()
	c, ok := client.(*bpfClient)
	if !ok {
		return nil, errors.New("FQDN backend requires native BPF client")
	}
	if c.fqdn != nil {
		return c.fqdn, nil
	}
	b := &FQDNBackend{client: c, gate: make(chan struct{}, 1), maps: map[string]fqdnMap{}, bound: map[uint32]*fqdnBinding{}, now: fqdnBootNow}
	sizes := map[string][2]uint32{"fqdn_endpoints": {4, 40}, "fqdn_grants": {32, 384}, "fqdn_dns": {40, 32}, "fqdn_flows": {48, 40}, "fqdn_proxy": {4, 16}}
	for name, size := range sizes {
		v, ok := c.globalMaps.Load("/sys/fs/bpf/globals/aws/maps/global_" + name)
		if !ok {
			return nil, fmt.Errorf("FQDN required global map %s unavailable", name)
		}
		m, ok := v.(goebpfmaps.BpfMap)
		if !ok || m.MapFD == 0 || m.MapMetaData.KeySize != size[0] || m.MapMetaData.ValueSize != size[1] {
			return nil, fmt.Errorf("FQDN map %s has incompatible ABI", name)
		}
		info, err := goebpfmaps.GetBPFmapInfo(int(m.MapFD))
		if err != nil {
			return nil, err
		}
		m.MapID = info.Id
		b.maps[name] = &fqdnSDKMap{m: m}
	}
	b.verify = b.verifyAttachment
	// Restart cannot prove current UID/policy provenance. Leave selected
	// interfaces restrictive while deleting all unproven grants and flows.
	if err := b.reset(); err != nil {
		return nil, err
	}
	c.fqdn = b
	return b, nil
}
func fqdnBootNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

type fqdnFenceContextKey struct{}
type fqdnFenceToken struct {
	backend *FQDNBackend
	active  atomic.Bool
}

func (b *FQDNBackend) WithFence(ctx context.Context, fn func(context.Context) error) error {
	if token, ok := ctx.Value(fqdnFenceContextKey{}).(*fqdnFenceToken); ok && token.backend == b && token.active.Load() {
		return fn(ctx)
	}
	select {
	case b.gate <- struct{}{}:
		defer func() { <-b.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token := &fqdnFenceToken{backend: b}
	token.active.Store(true)
	defer token.active.Store(false)
	return fn(context.WithValue(ctx, fqdnFenceContextKey{}, token))
}
func (b *FQDNBackend) reset() error {
	zero := fqdnProxyValue{}
	if err := b.maps["fqdn_proxy"].Put(fqdnUint32(0), fqdnBytes(&zero)); err != nil {
		return fmt.Errorf("disable recovered DNS proxy: %w", err)
	}
	keys, err := b.maps["fqdn_endpoints"].Keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		var v fqdnEndpointValue
		if err := b.maps["fqdn_endpoints"].Get([]byte(key), fqdnBytes(&v)); err != nil {
			return err
		}
		v.Flags = fqdnEndpointSelected
		v.Generation = 0
		if err := b.maps["fqdn_endpoints"].Put([]byte(key), fqdnBytes(&v)); err != nil {
			return fmt.Errorf("invalidate recovered endpoint: %w", err)
		}
	}
	for _, name := range []string{"fqdn_grants", "fqdn_flows", "fqdn_dns"} {
		if err := b.clearMap(name, nil); err != nil {
			return err
		}
	}
	return nil
}
func (b *FQDNBackend) clearMap(name string, match func([]byte) bool) error {
	keys, err := b.maps[name].Keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if match != nil && !match([]byte(key)) {
			continue
		}
		if err := b.maps[name].Delete([]byte(key)); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}
	return nil
}
func (b *FQDNBackend) ResolveFQDNEndpoint(ctx context.Context, pod *corev1.Pod, podIdentifier string) (fqdn.Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return fqdn.Endpoint{}, err
	}
	if pod == nil || pod.UID == "" || pod.Spec.HostNetwork || b.client.isMultiNICEnabled {
		return fqdn.Endpoint{}, errors.New("FQDN requires a concrete single-interface non-hostNetwork pod")
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		return fqdn.Endpoint{}, err
	}
	ip = ip.Unmap()
	name, err := utils.GetHostVethName(pod.Name, pod.Namespace, 0, []string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})
	if err != nil {
		return fqdn.Endpoint{}, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fqdn.Endpoint{}, err
	}
	return fqdn.Endpoint{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, PodIdentifier: podIdentifier, IP: ip, IfIndex: uint32(link.Attrs().Index)}, nil
}
func (b *FQDNBackend) Bind(ctx context.Context, ep fqdn.Endpoint) error {
	if ep.Lifetime == 0 || ep.UID == "" || ep.IfIndex == 0 || !ep.IP.IsValid() {
		return fqdn.ErrEndpoint
	}
	if err := b.verify(ctx, ep); err != nil {
		return err
	}
	if previous := b.bound[ep.IfIndex]; previous != nil {
		if previous.endpoint == ep {
			return b.invalidateLegacyConntrack(ep)
		}
		if err := b.Delete(ctx, previous.endpoint); err != nil {
			return err
		}
	}
	v := fqdnEndpointValue{Lifetime: ep.Lifetime, Address: fqdnAddress(ep.IP), Family: fqdnFamily(ep.IP), Flags: fqdnEndpointSelected}
	if err := b.maps["fqdn_endpoints"].Put(fqdnUint32(ep.IfIndex), fqdnBytes(&v)); err != nil {
		return fmt.Errorf("bind restrictive endpoint: %w", err)
	}
	b.bound[ep.IfIndex] = &fqdnBinding{endpoint: ep, grants: map[fqdnGrantKey]fqdnGrantValue{}, flowNames: map[fqdnFlowKey][]string{}}
	// The selected datapath bypasses legacy conntrack from this point. Delete
	// legacy entries as well, preventing their later resurrection on rollback.
	return b.invalidateLegacyConntrack(ep)
}
func (b *FQDNBackend) binding(ep fqdn.Endpoint) (*fqdnBinding, error) {
	s := b.bound[ep.IfIndex]
	if s == nil || s.endpoint != ep {
		return nil, fqdn.ErrEndpoint
	}
	return s, nil
}
func (b *FQDNBackend) ReconcilePolicy(ctx context.Context, ep fqdn.Endpoint, policy fqdn.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := b.binding(ep)
	if err != nil {
		return err
	}
	s.policy = policy
	return nil
}
func (b *FQDNBackend) Replace(ctx context.Context, ep fqdn.Endpoint, revision uint64, grants []fqdn.Grant) (err error) {
	started := time.Now()
	defer func() { fqdn.Observe("programming", started, err) }()
	s, err := b.binding(ep)
	if err != nil {
		return err
	}
	if err = b.verify(ctx, ep); err != nil {
		return err
	}
	v := fqdnEndpointValue{Lifetime: ep.Lifetime, Generation: revision, Address: fqdnAddress(ep.IP), Family: fqdnFamily(ep.IP), Flags: fqdnEndpointSelected}
	// First invalidate old authority. Even failed replacement cannot preserve
	// removed permissions; if this restrictive write fails, report failure.
	if err = b.maps["fqdn_endpoints"].Put(fqdnUint32(ep.IfIndex), fqdnBytes(&v)); err != nil {
		return fmt.Errorf("invalidate before replacement: %w", err)
	}
	if flowProofChanges(s, revision, grants) {
		if err = b.reconcileFlows(ctx, s, revision); err != nil {
			return err
		}
	}
	desired := map[fqdnGrantKey]fqdnGrantValue{}
	counts := map[fqdnGrantKey]int{}
	for _, g := range grants {
		if len(g.Names) > fqdnMaxPorts {
			return fmt.Errorf("FQDN per-grant proof names: %w", fqdn.ErrCapacity)
		}
		if g.Address.Is4() != ep.IP.Is4() {
			return errors.New("FQDN grant address family mismatch")
		}
		k := fqdnGrantKey{Lifetime: ep.Lifetime, Generation: revision, Address: fqdnAddress(g.Address)}
		i := counts[k]
		if i >= fqdnMaxPorts {
			return fqdn.ErrCapacity
		}
		value := desired[k]
		value.Ports[i] = fqdnL4Grant{Deadline: g.Deadline, StartPort: g.StartPort, EndPort: g.EndPort, Protocol: g.Protocol}
		desired[k] = value
		counts[k]++
	}
	// Delete removed keys before additions, so full maps cannot defeat revocation.
	for k := range s.grants {
		if _, ok := desired[k]; !ok {
			if err = b.maps["fqdn_grants"].Delete(fqdnBytes(&k)); err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("remove grant: %w", err)
			}
			delete(s.grants, k)
		}
	}
	for k, value := range desired {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = b.maps["fqdn_grants"].Put(fqdnBytes(&k), fqdnBytes(&value)); err != nil {
			return fmt.Errorf("program grant: %w", err)
		}
		s.grants[k] = value
	}
	if err = b.verify(ctx, ep); err != nil {
		return err
	}
	s.revision = revision
	s.observations = append([]fqdn.Grant(nil), grants...)
	if !b.staging {
		v.Flags |= fqdnEndpointReady
	}
	if err = b.maps["fqdn_endpoints"].Put(fqdnUint32(ep.IfIndex), fqdnBytes(&v)); err != nil {
		return fmt.Errorf("activate grants: %w", err)
	}
	return nil
}
func (b *FQDNBackend) Check(ctx context.Context, ep fqdn.Endpoint, revision uint64, grants []fqdn.Grant) error {
	if b.staging {
		return errors.New("FQDN shared policy update in progress")
	}
	s, err := b.binding(ep)
	if err != nil || s.revision != revision {
		return fqdn.ErrEndpoint
	}
	if err = b.verify(ctx, ep); err != nil {
		return err
	}
	var v fqdnEndpointValue
	if err = b.maps["fqdn_endpoints"].Get(fqdnUint32(ep.IfIndex), fqdnBytes(&v)); err != nil {
		return err
	}
	if v.Lifetime != ep.Lifetime || v.Generation != revision || v.Flags != (fqdnEndpointSelected|fqdnEndpointReady) {
		return fqdn.ErrEndpoint
	}
	now, err := b.now()
	if err != nil {
		return err
	}
	addresses := map[netip.Addr]bool{}
	live := map[netip.Addr]bool{}
	for _, g := range grants {
		if _, ok := addresses[g.Address]; !ok {
			addresses[g.Address] = false
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if g.Deadline <= now {
			continue
		}
		live[g.Address] = true
		k := fqdnGrantKey{Lifetime: ep.Lifetime, Generation: revision, Address: fqdnAddress(g.Address)}
		var active fqdnGrantValue
		if err = b.maps["fqdn_grants"].Get(fqdnBytes(&k), fqdnBytes(&active)); err != nil {
			return err
		}
		present := false
		for _, p := range active.Ports {
			if p.Deadline >= g.Deadline && p.Protocol == g.Protocol && p.StartPort == g.StartPort && p.EndPort == g.EndPort {
				present = true
				break
			}
		}
		if !present {
			return errors.New("FQDN active grant readback differs")
		}
		admitted, err := b.effectiveGrant(ctx, ep, g)
		if err != nil {
			return err
		}
		addresses[g.Address] = addresses[g.Address] || admitted
	}
	for address, allowed := range addresses {
		if !allowed {
			if !live[address] {
				return fqdn.ErrExpired
			}
			return fqdn.ErrNoPermission
		}
	}
	return ctx.Err()
}
func (b *FQDNBackend) Delete(ctx context.Context, ep fqdn.Endpoint) error {
	s, err := b.binding(ep)
	if err != nil {
		return b.deleteRetiredLifetime(ctx, ep)
	}
	v := fqdnEndpointValue{Lifetime: ep.Lifetime, Generation: s.revision, Address: fqdnAddress(ep.IP), Family: fqdnFamily(ep.IP), Flags: fqdnEndpointSelected}
	if err = b.maps["fqdn_endpoints"].Put(fqdnUint32(ep.IfIndex), fqdnBytes(&v)); err != nil {
		return fmt.Errorf("revoke endpoint lifetime: %w", err)
	}
	// The tombstone stays until a proven replacement is bound. Physical key
	// deletion would restore the unselected path on a still-present interface.
	for k := range s.grants {
		if err = b.maps["fqdn_grants"].Delete(fqdnBytes(&k)); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		delete(s.grants, k)
	}
	if err = b.clearMap("fqdn_flows", func(key []byte) bool { var k fqdnFlowKey; copy(fqdnBytes(&k), key); return k.Lifetime == ep.Lifetime }); err != nil {
		return err
	}
	if err = b.clearMap("fqdn_dns", func(key []byte) bool {
		var value fqdnDNSValue
		if e := b.maps["fqdn_dns"].Get(key, fqdnBytes(&value)); e != nil {
			return false
		}
		return value.Lifetime == ep.Lifetime
	}); err != nil {
		return err
	}
	delete(b.bound, ep.IfIndex)
	return ctx.Err()
}
func (b *FQDNBackend) SetProxyReady(ctx context.Context, port, mark uint32, ready bool) error {
	return b.WithFence(ctx, func(context.Context) error {
		v := fqdnProxyValue{Port: port, Mark: mark, ReplyMark: fqdn.DNSReplyMark}
		if ready {
			if port == 0 || port > 65535 || mark == 0 {
				return errors.New("invalid FQDN proxy configuration")
			}
			v.Ready = 1
		}
		return b.maps["fqdn_proxy"].Put(fqdnUint32(0), fqdnBytes(&v))
	})
}
func (b *FQDNBackend) LookupDNSIdentity(ctx context.Context, source, destination netip.AddrPort, protocol uint8) (ep fqdn.Endpoint, err error) {
	err = b.WithFence(ctx, func(ctx context.Context) error {
		key := fqdnTuple{Source: fqdnAddress(source.Addr().Unmap()), Destination: fqdnAddress(destination.Addr().Unmap()), SourcePort: source.Port(), DestinationPort: destination.Port(), Protocol: protocol, Family: uint8(fqdnFamily(source.Addr().Unmap()))}
		var v fqdnDNSValue
		if err := b.maps["fqdn_dns"].Get(fqdnBytes(&key), fqdnBytes(&v)); err != nil {
			return fmt.Errorf("DNS exchange lacks trusted TC provenance: %w", err)
		}
		now, err := b.now()
		if err != nil {
			return err
		}
		s := b.bound[v.IfIndex]
		if s == nil || s.endpoint.Lifetime != v.Lifetime || s.revision != v.Generation || v.Deadline <= now || s.endpoint.IP != source.Addr().Unmap() {
			return fqdn.ErrEndpoint
		}
		ep = s.endpoint
		if err := b.Check(ctx, ep, s.revision, nil); err != nil {
			return err
		}
		policy, err := b.loadStaticPolicy(ep, destination.Addr().Unmap())
		if err != nil {
			return err
		}
		if !policy.verdict(protocol, destination.Port(), false) {
			return fqdn.ErrNoPermission
		}
		return nil
	})
	return
}
func (b *FQDNBackend) verifyAttachment(ctx context.Context, ep fqdn.Endpoint) (err error) {
	started := time.Now()
	defer func() { fqdn.Observe("attachment", started, err) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, ok := b.client.policyEndpointeBPFContext.Load(ep.PodIdentifier)
	if !ok {
		return errors.New("FQDN active BPF context missing")
	}
	pe := raw.(BPFContext)
	link, err := netlink.LinkByIndex(int(ep.IfIndex))
	if err != nil {
		return err
	}
	expected, err := utils.GetHostVethName(ep.Name, ep.Namespace, 0, []string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})
	if err != nil || link.Attrs().Name != expected {
		return errors.New("FQDN interface lifetime/name changed")
	}
	for _, direction := range []struct {
		parent uint32
		fd     int
	}{{netlink.HANDLE_MIN_INGRESS, pe.egressPgmInfo.Program.ProgFD}, {netlink.HANDLE_MIN_EGRESS, pe.ingressPgmInfo.Program.ProgFD}} {
		if direction.fd <= 0 {
			return errors.New("FQDN active program missing")
		}
		info, err := progs.GetBPFprogInfo(direction.fd)
		if err != nil {
			return err
		}
		filters, err := netlink.FilterList(link, direction.parent)
		if err != nil {
			return err
		}
		attached := false
		for _, f := range filters {
			if filter, ok := f.(*netlink.BpfFilter); ok && filter.Id == int(info.ID) && filter.DirectAction {
				attached = true
			}
		}
		if !attached {
			return errors.New("FQDN expected TC program is not attached")
		}
		p := progs.BpfProgram{}
		ids, err := p.GetBPFProgAssociatedMapsIDs(direction.fd)
		if err != nil {
			return err
		}
		required := []string{"fqdn_endpoints", "fqdn_flows", "fqdn_dns", "fqdn_proxy"}
		if direction.parent == netlink.HANDLE_MIN_INGRESS {
			required = append(required, "fqdn_grants")
		}
		static := pe.egressPgmInfo.Maps
		staticNames := []string{utils.TC_EGRESS_MAP, utils.TC_CLUSTER_POLICY_EGRESS_MAP, utils.TC_EGRESS_POD_STATE_MAP}
		if direction.parent == netlink.HANDLE_MIN_EGRESS {
			static = pe.ingressPgmInfo.Maps
			staticNames = []string{utils.TC_INGRESS_MAP, utils.TC_CLUSTER_POLICY_INGRESS_MAP, utils.TC_INGRESS_POD_STATE_MAP}
		}
		for _, name := range staticNames {
			m, ok := static[name]
			if !ok {
				return fmt.Errorf("FQDN active static map %s absent", name)
			}
			info, err := goebpfmaps.GetBPFmapInfo(int(m.MapFD))
			if err != nil {
				return err
			}
			found := false
			for _, id := range ids {
				if id == info.Id {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("FQDN program static map %s changed", name)
			}
		}
		for _, name := range required {
			found := false
			for _, id := range ids {
				if id == b.maps[name].ID() {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("FQDN active program uses another %s map", name)
			}
		}
	}
	return nil
}

// withFQDNStaticFence is used by the established static BPF APIs. The timeout
// bounds waiting; callers receive an enforcement error instead of silent success.
func (l *bpfClient) withFQDNStaticFence(fn func() error) error {
	if l.fqdn == nil {
		return fn()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.fqdn.WithFence(ctx, func(context.Context) error { return fn() })
}
func (l *bpfClient) revokeFQDNPOD(namespace, name string) error {
	if l.fqdn == nil {
		return nil
	}
	var result error
	for _, s := range l.fqdn.bound {
		if s.endpoint.Namespace == namespace && s.endpoint.Name == name {
			result = errors.Join(result, l.fqdn.Delete(context.Background(), s.endpoint))
		}
	}
	return result
}
