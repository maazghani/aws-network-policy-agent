package ebpf

import (
	"encoding/binary"
	"net/netip"
	"unsafe"
)

const (
	fqdnEndpointSelected = 1
	fqdnEndpointReady    = 2
	fqdnMaxPorts         = 24
)

// These layouts mirror c/fqdn.h; addresses are network bytes, integers native.
type fqdnEndpointValue struct {
	Lifetime, Generation uint64
	Address              [16]byte
	Family, Flags        uint32
}
type fqdnGrantKey struct {
	Lifetime, Generation uint64
	Address              [16]byte
}
type fqdnL4Grant struct {
	Deadline           uint64
	StartPort, EndPort uint16
	Protocol           uint8
	Pad                [3]byte
}
type fqdnGrantValue struct{ Ports [fqdnMaxPorts]fqdnL4Grant }
type fqdnTuple struct {
	Source, Destination         [16]byte
	SourcePort, DestinationPort uint16
	Protocol, Family            uint8
	Pad                         [2]byte
}
type fqdnDNSValue struct {
	Lifetime, Generation, Deadline uint64
	IfIndex, Pad                   uint32
}
type fqdnProxyValue struct{ Port, Mark, Ready, ReplyMark uint32 }
type fqdnFlowKey struct {
	Lifetime uint64
	Tuple    fqdnTuple
}
type fqdnFlowValue struct {
	Generation, Deadline, LastSeen uint64
	SYNSequence, PeerSequence      uint32
	State                          uint8
	Pad                            [7]byte
}

func fqdnAddress(ip netip.Addr) (a [16]byte) {
	if ip.Is4() {
		v := ip.As4()
		copy(a[:4], v[:])
	} else if ip.Is6() {
		a = ip.As16()
	}
	return
}
func fqdnFamily(ip netip.Addr) uint32 {
	if ip.Is4() {
		return 4
	}
	return 6
}
func fqdnIP(a [16]byte, family uint8) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte(a[:4]))
	}
	return netip.AddrFrom16(a)
}
func fqdnBytes[T any](v *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(v)), int(unsafe.Sizeof(*v)))
}
func fqdnUint32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
