//go:build linux && fqdn_integration

// These tests load the production ELF programs with the production AWS loader.
// Run through scripts/fqdn-kernel-tests.sh, which isolates pins and networking.
package fqdn_test

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	bpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"golang.org/x/sys/unix"
)

type fixture struct {
	t                     *testing.T
	family                int
	ns, host              string
	pod, resolver, target netip.Addr
	ifindex               uint32
	progs                 map[string]elfparser.BpfData
	maps                  map[string]bpfmaps.BpfMap
	egressFD              int
	lifetime, generation  uint64
}

func TestMain(m *testing.M) {
	if os.Getenv("FQDN_TEST_HELPER") == "dns" {
		os.Exit(probeDNS())
	}
	if os.Getenv("FQDN_TEST_HELPER") == "server" {
		os.Exit(serveEcho())
	}
	if os.Getenv("FQDN_TEST_HELPER") != "" {
		os.Exit(probe())
	}
	os.Exit(m.Run())
}

func TestKernelPrerequisites(t *testing.T) {
	if os.Getenv("FQDN_TEST_ISOLATED") != "1" {
		t.Fatal("use scripts/fqdn-kernel-tests.sh: requires private mount/network namespaces and real BPF capabilities; this test does not skip unavailable kernel qualification")
	}
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var caps [2]unix.CapUserData
	if err := unix.Capget(&hdr, &caps[0]); err != nil {
		t.Fatal(err)
	}
	if caps[0].Effective&(1<<unix.CAP_NET_ADMIN) == 0 {
		t.Fatal("missing CAP_NET_ADMIN")
	}
	if caps[0].Effective&(1<<unix.CAP_NET_RAW) == 0 {
		t.Fatal("missing CAP_NET_RAW for NodeLocal-compatible UDP replies")
	}
	if caps[0].Effective&(1<<unix.CAP_SYS_ADMIN) == 0 {
		t.Fatal("missing CAP_SYS_ADMIN for isolated qualification")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || st.Type != unix.BPF_FS_MAGIC {
		t.Fatalf("private bpffs unavailable: %v", err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("FQDN_TEST_ISOLATED") != "1" {
		t.Fatal("run scripts/fqdn-kernel-tests.sh")
	}
	family, err := strconv.Atoi(os.Getenv("FQDN_TEST_FAMILY"))
	if err != nil || (family != 4 && family != 6) {
		t.Fatal("FQDN_TEST_FAMILY must be 4 or 6")
	}
	hash := sha1.Sum([]byte("fqdn-namespace.client"))
	f := &fixture{t: t, family: family, ns: "fqdn-pod", host: fmt.Sprintf("eni%x", hash)[:14], lifetime: 100, generation: 1, maps: map[string]bpfmaps.BpfMap{}, progs: map[string]elfparser.BpfData{}}
	pod, host, resolver, target, prefix := "192.0.2.2", "192.0.2.1", "198.18.0.53", "198.18.0.80", "24"
	if family == 6 {
		pod, host, resolver, target, prefix = "fd00:1::2", "fd00:1::1", "fd00:2::53", "fd00:2::80", "64"
	}
	f.pod, f.resolver, f.target = netip.MustParseAddr(pod), netip.MustParseAddr(resolver), netip.MustParseAddr(target)
	f.command("ip", "netns", "add", f.ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", f.ns).Run() })
	f.command("ip", "link", "add", f.host, "type", "veth", "peer", "name", "eth0", "netns", f.ns)
	f.command("ip", "link", "set", f.host, "up")
	f.command("ip", "addr", "add", host+"/"+prefix, "dev", f.host, "nodad")
	f.command("ip", "netns", "exec", f.ns, "ip", "link", "set", "lo", "up")
	f.command("ip", "netns", "exec", f.ns, "ip", "link", "set", "eth0", "up")
	f.command("ip", "netns", "exec", f.ns, "ip", "addr", "add", pod+"/"+prefix, "dev", "eth0", "nodad")
	f.command("ip", "netns", "exec", f.ns, "ip", fmt.Sprintf("-%d", family), "route", "add", "default", "via", host)
	hostMask := "32"
	if family == 6 {
		hostMask = "128"
	}
	// The resolver is behind another veth. It is deliberately non-local to the
	// host so DNS steering must install a policy route, not benefit from lo's
	// ordinary local-address route.
	resolverNS := f.ns + "-dns"
	f.command("ip", "netns", "add", resolverNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", resolverNS).Run() })
	f.command("ip", "link", "add", "fqdn-resolver", "type", "veth", "peer", "name", "eth0", "netns", resolverNS)
	f.command("ip", "link", "set", "fqdn-resolver", "up")
	resolverHost := "198.18.0.1"
	if family == 6 {
		resolverHost = "fd00:2::1"
	}
	f.command("ip", "addr", "add", resolverHost+"/"+prefix, "dev", "fqdn-resolver", "nodad")
	f.command("ip", "netns", "exec", resolverNS, "ip", "link", "set", "lo", "up")
	f.command("ip", "netns", "exec", resolverNS, "ip", "link", "set", "eth0", "up")
	f.command("ip", "netns", "exec", resolverNS, "ip", "addr", "add", resolver+"/"+prefix, "dev", "eth0", "nodad")
	f.command("ip", "netns", "exec", resolverNS, "ip", fmt.Sprintf("-%d", family), "route", "add", "default", "via", resolverHost)
	f.command("sysctl", "-qw", "net.ipv4.ip_forward=1")
	if family == 6 {
		f.command("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
	}
	f.startResolver(resolverNS)
	f.command("ip", "addr", "add", target+"/"+hostMask, "dev", "lo", "nodad")
	iface, err := net.InterfaceByName(f.host)
	if err != nil {
		t.Fatal(err)
	}
	f.ifindex = uint32(iface.Index)
	loader := elfparser.New(elfparser.Config{NamespacedMaps: []string{"ingress_map", "egress_map", "cp_ingress_map", "cp_egress_map", "ingress_pod_state_map", "egress_pod_state_map"}})
	if err := loader.IncreaseRlimit(); err != nil {
		t.Logf("memlock limit unchanged (kernel may use memcg): %v", err)
	}
	for _, name := range []string{fmt.Sprintf("v%devents", family), fmt.Sprintf("tc.v%dingress", family), fmt.Sprintf("tc.v%degress", family)} {
		programs, maps, err := loader.LoadBpfFile(filepath.Join(os.Getenv("FQDN_TEST_REPO"), "pkg/ebpf/c", name+".bpf.o"), "fqdn-test")
		if err != nil {
			t.Fatalf("load real production %s: %v", name, err)
		}
		for n, m := range maps {
			f.maps[n] = m
		}
		for n, p := range programs {
			f.progs[n] = p
			for mn, m := range p.Maps {
				f.maps[mn] = m
			}
		}
	}
	attach := tc.New([]string{"eni"})
	for name, p := range f.progs {
		if strings.Contains(name, "egress") {
			f.egressFD = p.Program.ProgFD
			err = attach.TCIngressAttach(f.host, p.Program.ProgFD, "fqdn-egress")
		} else if strings.Contains(name, "ingress") {
			err = attach.TCEgressAttach(f.host, p.Program.ProgFD, "fqdn-ingress")
		}
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
	}
	if f.egressFD == 0 {
		t.Fatal("production egress program not loaded")
	}
	// Namespace isolation in both directions; no implicit resolver allowance.
	for _, direction := range []string{"ingress", "egress"} {
		f.update(direction+"_pod_state_map", u32(0), []byte{0})
		f.update(direction+"_pod_state_map", u32(1), []byte{1})
	}
	f.endpoint(3)
	return f
}

func (f *fixture) command(name string, args ...string) []byte {
	f.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, v); return b }
func address(ip netip.Addr) []byte {
	b := make([]byte, 16)
	if ip.Is4() {
		a := ip.As4()
		copy(b, a[:])
	} else {
		a := ip.As16()
		copy(b, a[:])
	}
	return b
}
func bootNS(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}
func (f *fixture) update(name string, key, value []byte) {
	f.t.Helper()
	m, ok := f.maps[name]
	if !ok {
		f.t.Fatalf("production map %s absent (have %v)", name, f.maps)
	}
	if len(key) != int(m.MapMetaData.KeySize) || len(value) != int(m.MapMetaData.ValueSize) {
		f.t.Fatalf("ABI mismatch %s: key %d/%d value %d/%d", name, len(key), m.MapMetaData.KeySize, len(value), m.MapMetaData.ValueSize)
	}
	err := m.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])), unix.BPF_ANY)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if err != nil {
		f.t.Fatalf("update real %s: %v", name, err)
	}
}

func (f *fixture) lookup(name string, key []byte, size int) ([]byte, error) {
	m, ok := f.maps[name]
	if !ok {
		return nil, fmt.Errorf("missing map %s", name)
	}
	value := make([]byte, size)
	err := m.GetMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value[0])))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return value, err
}

func (f *fixture) endpoint(flags uint32) {
	b := make([]byte, 40)
	binary.NativeEndian.PutUint64(b, f.lifetime)
	binary.NativeEndian.PutUint64(b[8:], f.generation)
	copy(b[16:], address(f.pod))
	binary.NativeEndian.PutUint32(b[32:], uint32(f.family))
	binary.NativeEndian.PutUint32(b[36:], flags)
	f.update("fqdn_endpoints", u32(f.ifindex), b)
}

func (f *fixture) grant(ip netip.Addr, protocol uint8, first, last uint16, deadline uint64) {
	k := make([]byte, 32)
	binary.NativeEndian.PutUint64(k, f.lifetime)
	binary.NativeEndian.PutUint64(k[8:], f.generation)
	copy(k[16:], address(ip))
	v := make([]byte, 24*16)
	binary.NativeEndian.PutUint64(v, deadline)
	binary.NativeEndian.PutUint16(v[8:], first)
	binary.NativeEndian.PutUint16(v[10:], last)
	v[12] = protocol
	f.update("fqdn_grants", k, v)
}

func (f *fixture) static(ip netip.Addr, protocol, port uint32) {
	ipBytes := address(ip)
	mask := uint32(32)
	if f.family == 6 {
		mask = 128
	} else {
		ipBytes = ipBytes[:4]
	}
	k := append(u32(mask), ipBytes...)
	v := make([]byte, 24*12)
	binary.NativeEndian.PutUint32(v, protocol)
	binary.NativeEndian.PutUint32(v[4:], port)
	f.update("egress_map", k, v)
}

// BPF_PROG_TEST_RUN executes the loaded production TC program. The synthetic
// packet is useful for exact tuple/flag/expiry boundaries which a host TCP stack
// cannot reliably generate; socket steering is tested separately over veths.
func (f *fixture) packetVerdict(src, dst netip.Addr, protocol uint8, sport, dport uint16, flags uint8, ifindex uint32) uint32 {
	f.t.Helper()
	transport := make([]byte, 8)
	if protocol == 6 {
		transport = make([]byte, 20)
		transport[12] = 0x50
		transport[13] = flags
		binary.BigEndian.PutUint32(transport[4:], 1234)
	} else {
		binary.BigEndian.PutUint16(transport[4:], 8)
	}
	binary.BigEndian.PutUint16(transport, sport)
	binary.BigEndian.PutUint16(transport[2:], dport)
	eth := make([]byte, 14)
	var ip []byte
	if f.family == 4 {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip = make([]byte, 20)
		ip[0] = 0x45
		ip[8] = 64
		ip[9] = protocol
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(transport)))
		copy(ip[12:], address(src)[:4])
		copy(ip[16:], address(dst)[:4])
	} else {
		binary.BigEndian.PutUint16(eth[12:], 0x86dd)
		ip = make([]byte, 40)
		ip[0] = 0x60
		ip[6] = protocol
		ip[7] = 64
		binary.BigEndian.PutUint16(ip[4:], uint16(len(transport)))
		copy(ip[8:], address(src))
		copy(ip[24:], address(dst))
	}
	packet := append(append(eth, ip...), transport...)
	output := make([]byte, len(packet)+256)
	ctx := make([]byte, 192)
	binary.NativeEndian.PutUint32(ctx[36:], ifindex)
	binary.NativeEndian.PutUint32(ctx[40:], ifindex)
	attr := struct {
		FD, Ret, SizeIn, SizeOut                uint32
		DataIn, DataOut                         uint64
		Repeat, Duration, CtxSizeIn, CtxSizeOut uint32
		CtxIn, CtxOut                           uint64
		Flags, CPU, Batch, Pad                  uint32
	}{FD: uint32(f.egressFD), SizeIn: uint32(len(packet)), SizeOut: uint32(len(output)), DataIn: uint64(uintptr(unsafe.Pointer(&packet[0]))), DataOut: uint64(uintptr(unsafe.Pointer(&output[0]))), Repeat: 1, CtxSizeIn: uint32(len(ctx)), CtxIn: uint64(uintptr(unsafe.Pointer(&ctx[0])))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(packet)
	runtime.KeepAlive(output)
	runtime.KeepAlive(ctx)
	if errno != 0 {
		f.t.Fatalf("real TC program test run: %v", errno)
	}
	return attr.Ret
}

type probeResult struct {
	Success                       bool
	Connected                     bool
	Payload, Local, Remote, Error string
	LatenciesNS                   []int64
}

func serveEcho() int {
	address := os.Getenv("FQDN_PROBE_ADDRESS")
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer tcp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(dnsFixtureAnswer(b[:n], true), peer)
		}
	}()
	fmt.Println("READY")
	for {
		c, err := tcp.Accept()
		if err != nil {
			return 1
		}
		go func() { defer c.Close(); serveDNSOrEchoTCP(c) }()
	}
}

func (f *fixture) startResolver(namespace string) {
	exe, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", namespace, exe)
	if namespace == "" {
		cmd = exec.Command(exe)
	}
	cmd.Env = append(os.Environ(), "FQDN_TEST_HELPER=server", "FQDN_PROBE_ADDRESS="+net.JoinHostPort(f.resolver.String(), "53"), "FQDN_DNS_ANSWER="+f.target.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- "no resolver startup marker"
		}
	}()
	select {
	case status := <-ready:
		if status != "READY" {
			f.t.Fatal(status)
		}
	case <-time.After(5 * time.Second):
		f.t.Fatal("controlled resolver startup timed out")
	}
}

func probe() int {
	result := probeResult{}
	network, destination := os.Getenv("FQDN_PROBE_NETWORK"), os.Getenv("FQDN_PROBE_ADDRESS")
	count, _ := strconv.Atoi(os.Getenv("FQDN_PROBE_COUNT"))
	if count < 1 {
		count = 1
	}
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(result) }()
	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{Port: 32053}
	}
	c, err := dialer.Dial(network, destination)
	if err != nil {
		result.Error = err.Error()
		return 0
	}
	defer c.Close()
	result.Local, result.Remote = c.LocalAddr().String(), c.RemoteAddr().String()
	result.Connected = true
	for i := 0; i < count; i++ {
		_ = c.SetDeadline(time.Now().Add(750 * time.Millisecond))
		start := time.Now()
		payload := []byte("fqdn-kernel-probe")
		if _, err = c.Write(payload); err != nil {
			result.Error = err.Error()
			return 0
		}
		b := make([]byte, len(payload))
		if strings.HasPrefix(network, "tcp") {
			_, err = io.ReadFull(c, b)
		} else {
			_, err = c.Read(b)
		}
		if err != nil {
			result.Error = err.Error()
			return 0
		}
		if !bytes.Equal(b, payload) {
			result.Error = "unexpected response: " + string(b)
			return 0
		}
		result.LatenciesNS = append(result.LatenciesNS, time.Since(start).Nanoseconds())
		result.Payload = string(b)
	}
	result.Success = true
	return 0
}

func (f *fixture) probe(network string, ip netip.Addr, port int, count int) probeResult {
	f.t.Helper()
	exe, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", f.ns, exe)
	cmd.Env = append(os.Environ(), "FQDN_TEST_HELPER=probe", "FQDN_PROBE_NETWORK="+network, "FQDN_PROBE_ADDRESS="+net.JoinHostPort(ip.String(), strconv.Itoa(port)), fmt.Sprintf("FQDN_PROBE_COUNT=%d", count))
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("pod probe infrastructure failed: %v %s", err, out)
	}
	var result probeResult
	if err = json.Unmarshal(out, &result); err != nil {
		f.t.Fatalf("pod probe malformed result: %v %s", err, out)
	}
	return result
}
