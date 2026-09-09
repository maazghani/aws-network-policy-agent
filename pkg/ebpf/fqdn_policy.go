package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"unsafe"

	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"golang.org/x/sys/unix"
)

type fqdnStaticPort struct{ Protocol, Start, End uint32 }
type fqdnClusterPort struct{ Protocol, Priority, Start, End uint32 }
type fqdnStaticPolicy struct {
	ports     [24]fqdnStaticPort
	cluster   [24]fqdnClusterPort
	state     uint8
	hasStatic bool
}

func (b *FQDNBackend) loadStaticPolicy(ep fqdn.Endpoint, address netip.Addr) (fqdnStaticPolicy, error) {
	if b.readPolicy != nil {
		return b.readPolicy(ep, address)
	}
	return b.staticPolicy(ep, address)
}

func (b *FQDNBackend) staticPolicy(ep fqdn.Endpoint, address netip.Addr) (fqdnStaticPolicy, error) {
	var p fqdnStaticPolicy
	raw, ok := b.client.policyEndpointeBPFContext.Load(ep.PodIdentifier)
	if !ok {
		return p, fqdn.ErrEndpoint
	}
	pe := raw.(BPFContext)
	key := binary.NativeEndian.AppendUint32(nil, uint32(address.BitLen()))
	a := fqdnAddress(address)
	key = append(key, a[:address.BitLen()/8]...)
	read := func(name string, key, value []byte) error {
		m, ok := pe.egressPgmInfo.Maps[name]
		if !ok || m.MapFD == 0 {
			return errors.New("FQDN static map unavailable")
		}
		return fqdnMapSyscall(m.MapFD, unix.BPF_MAP_LOOKUP_ELEM, key, value)
	}
	err := read(utils.TC_EGRESS_MAP, key, fqdnBytes(&p.ports))
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return p, err
	}
	p.hasStatic = err == nil
	err = read(utils.TC_CLUSTER_POLICY_EGRESS_MAP, key, fqdnBytes(&p.cluster))
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return p, err
	}
	state := []byte{0}
	if err = read(utils.TC_EGRESS_POD_STATE_MAP, fqdnUint32(0), state); err != nil {
		return p, err
	}
	p.state = state[0]
	// Both state entries must exist, matching the selected TC path's readiness.
	if err = read(utils.TC_EGRESS_POD_STATE_MAP, fqdnUint32(1), []byte{0}); err != nil {
		return p, err
	}
	return p, nil
}
func fqdnPortMatch(proto uint32, start, end uint32, protocol uint8, port uint16) bool {
	return (proto == 254 || proto == uint32(protocol)) && (start == 0 || uint32(port) == start || (end > 0 && uint32(port) >= start && uint32(port) <= end))
}
func (p fqdnStaticPolicy) verdict(protocol uint8, port uint16, dynamic bool) bool {
	adminPriority, adminAction, basePriority, baseAction := uint32(65536), uint32(2), uint32(65536), uint32(2)
	for _, r := range p.cluster {
		// Match the existing datapath: ANY_IP_PROTOCOL in cluster policy ignores ports.
		if r.Protocol != 254 && !fqdnPortMatch(r.Protocol, r.Start, r.End, protocol, port) {
			continue
		}
		priority, action := r.Priority/10, r.Priority%10
		if priority < adminPriority || (priority == adminPriority && action < adminAction) {
			adminPriority, adminAction = priority, action
		}
		if priority > 1000 && (priority < basePriority || (priority == basePriority && action < baseAction)) {
			basePriority, baseAction = priority, action
		}
	}
	if adminPriority <= 1000 && adminAction != 2 {
		return adminAction == 1
	}
	// Namespace allows are a union. A namespace static deny is isolation, not a
	// terminal decision ahead of a valid namespace FQDN contribution.
	if dynamic {
		return true
	}
	for _, r := range p.ports {
		if r.Protocol == 255 {
			break
		}
		if fqdnPortMatch(r.Protocol, r.Start, r.End, protocol, port) {
			return true
		}
	}
	if p.hasStatic || p.state == uint8(POLICIES_APPLIED) {
		return false
	}
	if baseAction != 2 {
		return baseAction == 1
	}
	return p.state == uint8(DEFAULT_ALLOW)
}
func (b *FQDNBackend) effectiveGrant(ctx context.Context, ep fqdn.Endpoint, g fqdn.Grant) (bool, error) {
	policy, err := b.loadStaticPolicy(ep, g.Address)
	if err != nil {
		return false, err
	}
	// Decisions change only at interval boundaries. Exhaustively checking these
	// partitions avoids expanding an all-port grant into 65,536 operations.
	lo, hi := uint32(g.StartPort), uint32(g.EndPort)
	if lo == 0 {
		lo, hi = 0, 65535
	} else if hi == 0 {
		hi = lo
	}
	boundaries := []uint32{lo}
	for _, r := range policy.cluster {
		if r.Start >= lo && r.Start <= hi {
			boundaries = append(boundaries, r.Start)
		}
		if r.End < hi && r.End >= lo {
			boundaries = append(boundaries, r.End+1)
		}
		if r.Start < hi && r.Start >= lo {
			boundaries = append(boundaries, r.Start+1)
		}
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	first, last := int(g.Protocol), int(g.Protocol)
	if g.Protocol == 0 {
		first, last = 0, 255
	}
	for proto := first; proto <= last; proto++ {
		for _, port := range boundaries {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if policy.verdict(uint8(proto), uint16(port), true) {
				return true, nil
			}
		}
	}
	return false, nil
}
func (b *FQDNBackend) ResolverAllowed(ctx context.Context, ep fqdn.Endpoint, resolver netip.AddrPort, protocol uint8) (bool, error) {
	var allowed bool
	err := b.WithFence(ctx, func(ctx context.Context) error {
		if _, err := b.binding(ep); err != nil {
			return err
		}
		if err := b.verify(ctx, ep); err != nil {
			return err
		}
		p, err := b.loadStaticPolicy(ep, resolver.Addr().Unmap())
		if err != nil {
			return err
		}
		allowed = p.verdict(protocol, resolver.Port(), false)
		return nil
	})
	return allowed, err
}
func (b *FQDNBackend) reconcileFlows(ctx context.Context, s *fqdnBinding, revision uint64) error {
	keys, err := b.maps["fqdn_flows"].Keys()
	if err != nil {
		return err
	}
	now, err := b.now()
	if err != nil {
		return err
	}
	names := map[fqdnFlowKey][]string{}
	for _, raw := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		var key fqdnFlowKey
		copy(fqdnBytes(&key), raw)
		if key.Lifetime != s.endpoint.Lifetime {
			continue
		}
		var value fqdnFlowValue
		if err := b.maps["fqdn_flows"].Get([]byte(raw), fqdnBytes(&value)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		// Capture names while old DNS observations are still retained; then retain
		// them only for bounded kernel flow entries, never an unbounded DNS archive.
		proof := append([]string(nil), s.flowNames[key]...)
		address := fqdnIP(key.Tuple.Destination, key.Tuple.Family)
		for _, g := range s.observations {
			if g.Address == address && (g.Protocol == 0 || g.Protocol == key.Tuple.Protocol) && (g.StartPort == 0 || key.Tuple.DestinationPort == g.StartPort || (g.EndPort > 0 && key.Tuple.DestinationPort >= g.StartPort && key.Tuple.DestinationPort <= g.EndPort)) {
				proof = appendUniqueNames(proof, g.Names)
			}
		}
		policy, err := b.loadStaticPolicy(s.endpoint, address)
		if err != nil {
			return err
		}
		authorized := policy.verdict(key.Tuple.Protocol, key.Tuple.DestinationPort, false)
		if !authorized {
			dynamic := false
			for _, name := range proof {
				for _, rule := range s.policy.Rules {
					if !fqdn.MatchName(rule.Name, name) {
						continue
					}
					for _, port := range rule.Ports {
						if (port.Protocol == 0 || port.Protocol == key.Tuple.Protocol) && (port.StartPort == 0 || port.StartPort == key.Tuple.DestinationPort || (port.EndPort > 0 && key.Tuple.DestinationPort >= port.StartPort && key.Tuple.DestinationPort <= port.EndPort)) {
							dynamic = true
						}
					}
				}
			}
			authorized = dynamic && policy.verdict(key.Tuple.Protocol, key.Tuple.DestinationPort, true)
		}
		if value.Deadline <= now {
			if err := b.maps["fqdn_flows"].Delete([]byte(raw)); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			continue
		}
		if !authorized || value.Generation == 0 {
			value.Generation = 0
			if err := b.maps["fqdn_flows"].Put([]byte(raw), fqdnBytes(&value)); err != nil {
				return err
			}
			continue
		}
		if value.Generation != revision {
			value.Generation = revision
			if err := b.maps["fqdn_flows"].Put([]byte(raw), fqdnBytes(&value)); err != nil {
				return err
			}
		}
		names[key] = proof
	}
	s.flowNames = names
	return nil
}
func appendUniqueNames(to, from []string) []string {
	for _, s := range from {
		found := false
		for _, v := range to {
			if s == v {
				found = true
				break
			}
		}
		if !found && len(to) < 24 {
			to = append(to, s)
		}
	}
	return to
}

// The SDK is used for loading, identity, iteration and writes. Its lookup/delete
// helpers stringify errno; this small syscall wrapper retains ENOENT so absent
// permissions cannot be confused with failed kernel reads during the barrier.
func fqdnMapSyscall(fd uint32, command int, key, value []byte) error {
	attr := struct {
		FD, Pad           uint32
		Key, Value, Flags uint64
	}{FD: fd, Key: uint64(uintptr(unsafe.Pointer(&key[0])))}
	if len(value) > 0 {
		attr.Value = uint64(uintptr(unsafe.Pointer(&value[0])))
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}
