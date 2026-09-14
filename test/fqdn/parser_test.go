//go:build linux && fqdn_integration

package fqdn_test

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// parserChecks runs crafted packets through the loaded production programs.
// Permitted control packets and broad static egress make a malformed-packet drop
// decisive: denial cannot be credited to missing destination permission.
func (f *fixture) parserChecks(t *testing.T) {
	f.endpoint(3)
	f.static(f.target, 254, 0)
	f.grant(f.target, 17, 443, 443, bootNS(t)+uint64(time.Minute))
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, 41000)
	binary.BigEndian.PutUint16(udp[2:], 443)
	binary.BigEndian.PutUint16(udp[4:], 8)
	run := func(name string, packet []byte, want uint32) {
		t.Run(name, func(t *testing.T) {
			if got := f.rawPacketVerdict(t, f.egressFD, packet); got != want {
				t.Fatalf("real TC parser verdict %d, want %d", got, want)
			}
		})
	}
	build := func(protocol uint8, payload []byte) []byte { return f.parserPacket(f.pod, f.target, protocol, payload) }
	run("valid UDP", build(17, udp), 0)
	shortUDP := append([]byte(nil), udp...)
	binary.BigEndian.PutUint16(shortUDP[4:], 7)
	run("UDP length below header", build(17, shortUDP), 2)
	longUDP := append([]byte(nil), udp...)
	binary.BigEndian.PutUint16(longUDP[4:], 100)
	run("UDP length beyond IP payload", build(17, longUDP), 2)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, 41001)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12], tcp[13] = 0x40, 2
	run("TCP data offset below header", build(6, tcp), 2)
	tcp[12] = 0x60
	run("TCP data offset beyond IP payload", build(6, tcp), 2)

	if f.family == 4 {
		withOptions := func(options []byte) []byte {
			p := build(17, udp)
			p = append(p[:34:34], append(options, p[34:]...)...)
			p[14] = 0x40 | byte((20+len(options))/4)
			binary.BigEndian.PutUint16(p[16:], uint16(len(p)-14))
			return p
		}
		f.static(f.target, 17, 443)
		run("IPv4 NOP options use actual transport offset", withOptions([]byte{1, 1, 1, 1}), 0)
		run("IPv4 EOL options", withOptions([]byte{0, 0, 0, 0}), 0)
		wrongPort := withOptions([]byte{1, 1, 1, 1})
		binary.BigEndian.PutUint16(wrongPort[40:], 446)
		run("IPv4 options cannot substitute permitted port", wrongPort, 2)
		f.static(f.target, 254, 0)
		run("IPv4 zero option length", withOptions([]byte{7, 0, 0, 0}), 2)
		run("IPv4 option extends beyond IHL", withOptions([]byte{7, 8, 0, 0}), 2)
		run("IPv4 loose source route", withOptions([]byte{131, 3, 4, 0}), 2)
		run("IPv4 strict source route", withOptions([]byte{137, 3, 4, 0}), 2)
		for name, field := range map[string]uint16{"IPv4 first fragment": 0x2000, "IPv4 non-initial fragment": 1} {
			p := build(17, udp)
			binary.BigEndian.PutUint16(p[20:], field)
			run(name, p, 2)
		}
		p := build(17, udp)
		p[14] = 0x44
		run("IPv4 invalid IHL", p, 2)
		p = build(17, udp)
		binary.BigEndian.PutUint16(p[16:], 19)
		run("IPv4 total length below header", p, 2)
		p = build(17, udp)
		binary.BigEndian.PutUint16(p[16:], uint16(len(p)))
		run("IPv4 total length beyond skb", p, 2)
		p = build(17, udp)
		p[14] = 0x4f
		run("IPv4 truncated options", p, 2)
		return
	}

	extension := func(kind uint8, header []byte) []byte {
		return build(kind, append(append([]byte(nil), header...), udp...))
	}
	f.static(f.target, 17, 443)
	run("IPv6 hop-by-hop options", extension(0, []byte{17, 0, 0, 0, 0, 0, 0, 0}), 0)
	run("IPv6 destination options", extension(60, []byte{17, 0, 0, 0, 0, 0, 0, 0}), 0)
	run("IPv6 PadN fills extension exactly", extension(60, []byte{17, 0, 1, 4, 0, 0, 0, 0}), 0)
	run("IPv6 AH minimum header", extension(51, []byte{17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 0)
	wrongPort := extension(60, []byte{17, 0, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(wrongPort[64:], 446)
	run("IPv6 extension cannot substitute permitted port", wrongPort, 2)
	f.static(f.target, 254, 0)
	run("IPv6 AH truncated header", extension(51, []byte{17, 0, 0, 0, 0, 0, 0, 0}), 2)
	run("IPv6 malformed option length", extension(60, []byte{17, 0, 1, 255, 0, 0, 0, 0}), 2)
	run("IPv6 option missing length byte", extension(60, []byte{17, 0, 0, 0, 0, 0, 0, 1}), 2)
	run("IPv6 home address rewriting", extension(60, []byte{17, 0, 201, 0, 0, 0, 0, 0}), 2)
	run("IPv6 jumbo payload option", extension(0, []byte{17, 0, 194, 0, 0, 0, 0, 0}), 2)
	run("IPv6 routing header", extension(43, []byte{17, 0, 0, 0, 0, 0, 0, 0}), 2)
	run("IPv6 atomic fragment", extension(44, []byte{17, 0, 0, 0, 0, 0, 0, 0}), 2)
	run("IPv6 non-initial fragment", extension(44, []byte{17, 0, 0, 8, 0, 0, 0, 0}), 2)
	run("IPv6 extension exceeds payload", extension(60, []byte{17, 8, 0, 0, 0, 0, 0, 0}), 2)
	for _, count := range []int{6, 7} {
		chain := make([]byte, count*8)
		for i := 0; i < count; i++ {
			chain[i*8] = 60
		}
		chain[(count-1)*8] = 17
		want := uint32(0)
		name := "IPv6 six extension headers"
		if count == 7 {
			want, name = 2, "IPv6 extension traversal bound"
		}
		run(name, build(60, append(chain, udp...)), want)
	}
	for _, count := range []int{32, 33} {
		header := make([]byte, 40)
		header[0], header[1] = 17, 4
		// All but the last option are Pad1; a final PadN fills the header.
		last := 2 + count - 1
		header[last], header[last+1] = 1, byte(len(header)-last-2)
		want, name := uint32(0), "IPv6 32 option bound permits complete header"
		if count == 33 {
			want, name = 2, "IPv6 option traversal bound"
		}
		run(name, extension(60, header), want)
	}
	// skb BPF_PROG_TEST_RUN rejects input beyond its page-sized allocation.
	// Linux v6.8 net/bpf/test_run.c:bpf_test_init limits input to PAGE_SIZE
	// minus the headroom and tailroom supplied by bpf_prog_test_run_skb.
	// https://github.com/torvalds/linux/blob/v6.8/net/bpf/test_run.c#L636-L646
	// Exercise the maximum header length and six-header traversal separately.
	for _, test := range []struct {
		name          string
		count, length int
	}{
		{"IPv6 maximum length extension", 1, 2048},
		{"IPv6 six long extensions", 6, 512},
	} {
		chain := make([]byte, test.count*test.length)
		for i := 0; i < test.count; i++ {
			header := chain[i*test.length : (i+1)*test.length]
			header[0], header[1] = 60, byte(test.length/8-1)
			for offset := 2; offset < len(header); {
				size := min(257, len(header)-offset)
				header[offset], header[offset+1] = 1, byte(size-2)
				offset += size
			}
		}
		chain[(test.count-1)*test.length] = 17
		run(test.name, build(60, append(chain, udp...)), 0)
	}
	p := build(17, udp)
	binary.BigEndian.PutUint16(p[18:], 0)
	run("IPv6 unsupported jumbogram", p, 2)
	p = build(17, udp)
	binary.BigEndian.PutUint16(p[18:], 100)
	run("IPv6 payload beyond skb", p, 2)

	var ingressFD int
	for name, program := range f.progs {
		if strings.Contains(name, "ingress") {
			ingressFD = program.Program.ProgFD
		}
	}
	if ingressFD == 0 {
		t.Fatal("production ingress program unavailable for PMTU test")
	}
	icmp := make([]byte, 48) // ICMP header plus quoted invoking IPv6 header.
	icmp[0], icmp[8] = 2, 0x60
	binary.BigEndian.PutUint32(icmp[4:], 1280)
	checkIngress := func(name string, payload []byte, hopLimit byte, want uint32) {
		t.Run(name, func(t *testing.T) {
			packet := f.parserPacket(f.target, f.pod, 58, payload)
			packet[21] = hopLimit
			if got := f.rawPacketVerdict(t, ingressFD, packet); got != want {
				t.Fatalf("real isolated ingress TC verdict %d, want %d", got, want)
			}
		})
	}
	checkIngress("IPv6 Packet Too Big survives ingress isolation", icmp, 64, 0)
	checkIngress("IPv6 truncated Packet Too Big", icmp[:8], 64, 2)
	icmp[1] = 255
	checkIngress("IPv6 invalid Packet Too Big code", icmp, 64, 2)
	nd := make([]byte, 24)
	nd[0] = 135
	checkIngress("IPv6 Neighbor Solicitation", nd, 255, 0)
	checkIngress("IPv6 truncated Neighbor Solicitation", nd[:8], 255, 2)
	checkIngress("IPv6 off-link Neighbor Solicitation", nd, 64, 2)
}

func (f *fixture) parserPacket(src, dst netip.Addr, protocol uint8, payload []byte) []byte {
	ipSize, etherType := 20, uint16(0x0800)
	if f.family == 6 {
		ipSize, etherType = 40, 0x86dd
	}
	packet := make([]byte, 14+ipSize+len(payload))
	binary.BigEndian.PutUint16(packet[12:], etherType)
	ip := packet[14:]
	if f.family == 4 {
		ip[0], ip[8], ip[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(ip[2:], uint16(ipSize+len(payload)))
		copy(ip[12:], address(src)[:4])
		copy(ip[16:], address(dst)[:4])
	} else {
		ip[0], ip[6], ip[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
		copy(ip[8:], address(src))
		copy(ip[24:], address(dst))
	}
	copy(ip[ipSize:], payload)
	return packet
}

func (f *fixture) rawPacketVerdict(t *testing.T, fd int, packet []byte) uint32 {
	t.Helper()
	output := make([]byte, len(packet)+256)
	ctx := make([]byte, 192)
	binary.NativeEndian.PutUint32(ctx[36:], f.ifindex)
	binary.NativeEndian.PutUint32(ctx[40:], f.ifindex)
	attr := struct {
		FD, Ret, SizeIn, SizeOut                uint32
		DataIn, DataOut                         uint64
		Repeat, Duration, CtxSizeIn, CtxSizeOut uint32
		CtxIn, CtxOut                           uint64
		Flags, CPU, Batch, Pad                  uint32
	}{FD: uint32(fd), SizeIn: uint32(len(packet)), SizeOut: uint32(len(output)), DataIn: uint64(uintptr(unsafe.Pointer(&packet[0]))), DataOut: uint64(uintptr(unsafe.Pointer(&output[0]))), Repeat: 1, CtxSizeIn: uint32(len(ctx)), CtxIn: uint64(uintptr(unsafe.Pointer(&ctx[0])))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(packet)
	runtime.KeepAlive(output)
	runtime.KeepAlive(ctx)
	if errno != 0 {
		t.Fatalf("real TC parser test run: %v", errno)
	}
	return attr.Ret
}
