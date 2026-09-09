package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"time"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"golang.org/x/sys/unix"
)

func (b *FQDNBackend) invalidateLegacyConntrack(ep fqdn.Endpoint) error {
	raw, ok := b.client.globalMaps.Load(CONNTRACK_MAP_PIN_PATH)
	if !ok {
		return errors.New("legacy conntrack map unavailable during FQDN enrollment")
	}
	// Maps loaded and recovered by the existing SDK retain native key layout.
	m, ok := raw.(goebpfmaps.BpfMap)
	if !ok {
		return errors.New("invalid conntrack map")
	}
	keys, err := m.GetAllMapKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		matches := false
		if ep.IP.Is4() {
			var k utils.ConntrackKey
			copy(fqdnBytes(&k), key)
			matches = k.Ifindex == ep.IfIndex && k.Owner_ip == utils.ConvIPv4ToInt(ep.IP.AsSlice())
		} else {
			var k utils.ConntrackKeyV6
			copy(fqdnBytes(&k), key)
			matches = k.Ifindex == ep.IfIndex && k.Owner_ip == ep.IP.As16()
		}
		if matches {
			if err := fqdnMapSyscall(m.MapFD, unix.BPF_MAP_DELETE_ELEM, []byte(key), nil); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
	}
	return nil
}
func (b *FQDNBackend) BeginFQDNPolicyUpdate(ctx context.Context) error {
	return b.WithFence(ctx, func(context.Context) error {
		b.staging = true
		var result error
		for _, s := range b.bound {
			v := fqdnEndpointValue{Lifetime: s.endpoint.Lifetime, Generation: s.revision, Address: fqdnAddress(s.endpoint.IP), Family: fqdnFamily(s.endpoint.IP), Flags: fqdnEndpointSelected}
			result = errors.Join(result, b.maps["fqdn_endpoints"].Put(fqdnUint32(s.endpoint.IfIndex), fqdnBytes(&v)))
		}
		return result
	})
}
func (b *FQDNBackend) EndFQDNPolicyUpdate(ctx context.Context, success bool) error {
	return b.WithFence(ctx, func(ctx context.Context) error {
		if !success {
			return nil
		}
		// Validate every endpoint and all dependent established flows before making
		// any selected endpoint ready after a shared Admin/namespace update.
		for _, s := range b.bound {
			if err := b.verify(ctx, s.endpoint); err != nil {
				return err
			}
			if err := b.reconcileFlows(ctx, s, s.revision); err != nil {
				return err
			}
		}
		for _, s := range b.bound {
			v := fqdnEndpointValue{Lifetime: s.endpoint.Lifetime, Generation: s.revision, Address: fqdnAddress(s.endpoint.IP), Family: fqdnFamily(s.endpoint.IP), Flags: fqdnEndpointSelected | fqdnEndpointReady}
			if err := b.maps["fqdn_endpoints"].Put(fqdnUint32(s.endpoint.IfIndex), fqdnBytes(&v)); err != nil {
				return fmt.Errorf("complete FQDN policy stage: %w", err)
			}
		}
		b.staging = false
		return nil
	})
}

// releaseInactiveInterface is called only after a successful CNI attachment.
// A tombstone with no live userspace binding belongs to a retired lifetime;
// this verified new attachment can restore the ordinary unselected path.
func (b *FQDNBackend) releaseInactiveInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	index := uint32(link.Attrs().Index)
	if b.bound[index] != nil {
		return nil
	}
	err = b.maps["fqdn_endpoints"].Delete(fqdnUint32(index))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// RunGC bounds physically retained tombstones and flow proofs. Expiry is
// enforced in BPF even if this loop stops. Missing netlink visibility is an
// error and never authorizes removing an endpoint that might still exist.
func (b *FQDNBackend) RunGC(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gcCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := b.WithFence(gcCtx, b.gc)
			cancel()
			if err != nil {
				log().Errorf("FQDN kernel garbage collection: %v", err)
			}
		}
	}
}
func (b *FQDNBackend) gc(ctx context.Context) error {
	now, err := b.now()
	if err != nil {
		return err
	}
	for _, name := range []string{"fqdn_dns", "fqdn_flows"} {
		keys, err := b.maps[name].Keys()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			var deadline uint64
			if name == "fqdn_dns" {
				var v fqdnDNSValue
				if err := b.maps[name].Get([]byte(key), fqdnBytes(&v)); err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					return err
				}
				deadline = v.Deadline
			} else {
				var v fqdnFlowValue
				if err := b.maps[name].Get([]byte(key), fqdnBytes(&v)); err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					return err
				}
				deadline = v.Deadline
			}
			if deadline <= now {
				if err := b.maps[name].Delete([]byte(key)); err != nil && !errors.Is(err, unix.ENOENT) {
					return err
				}
			}
		}
	}
	keys, err := b.maps["fqdn_endpoints"].Keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if len(key) != 4 {
			return errors.New("invalid endpoint key")
		}
		index := binary.NativeEndian.Uint32([]byte(key))
		_, err := netlink.LinkByIndex(int(index))
		if err == nil {
			continue
		}
		var absent netlink.LinkNotFoundError
		if !errors.As(err, &absent) {
			return err
		}
		// No interface exists at this index now. The same fence prevents our own
		// attach/bind operations from racing retirement of the old lifetime.
		if s := b.bound[index]; s != nil {
			if err := b.Delete(ctx, s.endpoint); err != nil {
				return err
			}
		}
		if err := b.maps["fqdn_endpoints"].Delete([]byte(key)); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}
