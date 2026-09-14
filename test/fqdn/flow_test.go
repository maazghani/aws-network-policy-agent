//go:build linux && fqdn_integration

package fqdn_test

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// flowChecks executes a complete synthetic TCP handshake in both production TC
// directions. Linux TCP would prevent deliberately reused/invalid sequence
// tuples; BPF_PROG_TEST_RUN makes those authority boundaries reproducible.
func (f *fixture) flowChecks(t *testing.T) {
	var ingressFD int
	for name, program := range f.progs {
		if strings.Contains(name, "ingress") {
			ingressFD = program.Program.ProgFD
		}
	}
	if ingressFD == 0 {
		t.Fatal("production ingress program unavailable for flow lifecycle test")
	}
	ip := address(f.target)
	prefix := uint32(128)
	if f.family == 4 {
		ip, prefix = ip[:4], 32
	}
	staticKey := append(u32(prefix), ip...)
	// Invoked before the fixture's static-allow cases.
	generation := f.generation
	defer func() {
		f.generation = generation
		f.endpoint(3)
	}()
	// The stream must depend on the dynamic grant. A broad static allow would
	// make an expiry/revocation assertion incapable of testing FQDN provenance.
	f.update("egress_map", staticKey, make([]byte, 24*12))
	f.endpoint(3)
	f.grant(f.target, 6, 443, 443, bootNS(t)+uint64(time.Minute))

	const clientPort, serverPort = uint16(43001), uint16(443)
	const clientISN, serverISN = uint32(5000), uint32(9000)
	packet := func(reverse bool, flags byte, sequence, acknowledgement uint32, data string) []byte {
		transport := make([]byte, 20+len(data))
		src, dst := f.pod, f.target
		sport, dport := clientPort, serverPort
		if reverse {
			src, dst = dst, src
			sport, dport = dport, sport
		}
		binary.BigEndian.PutUint16(transport, sport)
		binary.BigEndian.PutUint16(transport[2:], dport)
		binary.BigEndian.PutUint32(transport[4:], sequence)
		binary.BigEndian.PutUint32(transport[8:], acknowledgement)
		transport[12], transport[13] = 0x50, flags
		copy(transport[20:], data)
		return f.parserPacket(src, dst, 6, transport)
	}
	check := func(name string, reverse bool, flags byte, sequence, acknowledgement uint32, data string, want uint32) {
		t.Run(name, func(t *testing.T) {
			fd := f.egressFD
			if reverse {
				fd = ingressFD
			}
			if got := f.rawPacketVerdict(t, fd, packet(reverse, flags, sequence, acknowledgement, data)); got != want {
				t.Fatalf("real TC TCP verdict %d, want %d (reverse=%v flags=%02x)", got, want, reverse, flags)
			}
		})
	}
	check("unsolicited ACK cannot establish authority", false, 0x10, clientISN+1, serverISN+1, "", 2)
	check("unsolicited SYN ACK cannot establish authority", true, 0x12, serverISN, clientISN+1, "", 2)
	check("fresh SYN with live grant", false, 0x02, clientISN, 0, "", 0)
	check("SYN ACK must acknowledge admitted sequence", true, 0x12, serverISN, clientISN+2, "", 2)
	check("verified SYN ACK crosses ingress isolation", true, 0x12, serverISN, clientISN+1, "", 0)
	check("final ACK must acknowledge server sequence", false, 0x10, clientISN+1, serverISN+2, "", 2)
	check("verified final ACK establishes TCP", false, 0x10, clientISN+1, serverISN+1, "", 0)

	f.grant(f.target, 6, 443, 443, bootNS(t)-1)
	check("expired DNS preserves established outbound data", false, 0x18, clientISN+1, serverISN+1, "ping", 0)
	check("expired DNS preserves established reverse data", true, 0x18, serverISN+1, clientISN+5, "pong", 0)
	check("expired same tuple SYN requires new grant", false, 0x02, clientISN+100, 0, "", 2)
	check("rejected reused SYN does not replace established proof", false, 0x10, clientISN+5, serverISN+5, "", 0)

	f.generation++
	f.endpoint(3)
	check("generation revokes established outbound", false, 0x10, clientISN+5, serverISN+5, "", 2)
	check("generation revokes established reverse", true, 0x10, serverISN+5, clientISN+5, "", 2)
}
