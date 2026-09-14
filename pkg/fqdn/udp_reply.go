package fqdn

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// 1232 fits one UDP datagram inside IPv6's required minimum 1280-byte MTU.
// Larger DNS answers retain TC and retry over TCP instead of IP fragmentation.
const maxDNSUDPPayload = 1232

func dnsUDPLimit(request []byte) int {
	message, err := unpackDNS(request)
	if err != nil {
		return 512
	}
	limit := 512
	for _, record := range message.Additionals {
		if record.Header.Type == dnsmessage.TypeOPT {
			limit = max(512, int(record.Header.Class))
			break
		}
	}
	return min(limit, maxDNSUDPPayload)
}

func fitDNSUDP(request, response []byte) ([]byte, error) {
	if len(response) <= dnsUDPLimit(request) {
		return response, nil
	}
	message, err := unpackDNS(response)
	if err != nil {
		return nil, err
	}
	message.Truncated = true
	message.Answers, message.Authorities, message.Additionals = nil, nil, nil
	return message.Pack()
}

// A raw reply avoids binding the resolver's local UDP port. NodeLocal DNSCache
// may already own that exact address:53 without SO_REUSEPORT. IP headers and the
// mandatory IPv6 UDP checksum are explicit; SO_MARK scopes OUTPUT NOTRACK.
func dnsUDPReplyPacket(source, destination netip.AddrPort, payload []byte) ([]byte, error) {
	if !source.IsValid() || !destination.IsValid() || source.Addr().Is4() != destination.Addr().Is4() || source.Addr().Is4In6() || destination.Addr().Is4In6() || source.Addr().Zone() != "" || destination.Addr().Zone() != "" || source.Port() != 53 || len(payload) > maxDNSUDPPayload {
		return nil, errors.New("invalid transparent UDP reply")
	}
	headerLength := 40
	if source.Addr().Is4() {
		headerLength = 20
	}
	packet := make([]byte, headerLength+8+len(payload))
	udp := packet[headerLength:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	var pseudo []byte
	if source.Addr().Is4() {
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		s, d := source.Addr().As4(), destination.Addr().As4()
		copy(packet[12:16], s[:])
		copy(packet[16:20], d[:])
		binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20], nil))
		pseudo = make([]byte, 12)
		copy(pseudo[:8], packet[12:20])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	} else {
		packet[0], packet[6], packet[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(udp)))
		s, d := source.Addr().As16(), destination.Addr().As16()
		copy(packet[8:24], s[:])
		copy(packet[24:40], d[:])
		pseudo = make([]byte, 40)
		copy(pseudo[:32], packet[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
		pseudo[39] = 17
	}
	checksum := internetChecksum(pseudo, udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet, nil
}

func internetChecksum(first, second []byte) uint16 {
	var sum uint32
	for _, data := range [][]byte{first, second} {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
