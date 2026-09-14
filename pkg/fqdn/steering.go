//go:build linux

package fqdn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These values are exclusively owned by this experimental feature. An
// incompatible existing rule or route is a startup error, never overwritten.
const DefaultDNSMark uint32 = 0x80000000
const DNSReplyMark uint32 = 0x40000000
const DefaultDNSRouteTable = 20153
const DefaultDNSRulePriority = 1053
const dnsRouteProtocol = 153

func transparentControl(family int, receive bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			set := func(level, opt, value int) {
				if socketErr == nil {
					socketErr = unix.SetsockoptInt(int(fd), level, opt, value)
				}
			}
			set(unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			set(unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// This distinct mark scopes OUTPUT NOTRACK. It never selects the
			// inbound policy route and is never used on upstream resolver sockets.
			set(unix.SOL_SOCKET, unix.SO_MARK, int(DNSReplyMark))
			if family == 4 {
				set(unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				if receive {
					set(unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
					set(unix.SOL_IP, unix.IP_PKTINFO, 1)
				}
			} else {
				set(unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
				set(unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				if receive {
					set(unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
					set(unix.SOL_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
			}
		})
		if err != nil {
			return err
		}
		return socketErr
	}
}

func listenerAddress(family, port int) (string, string, error) {
	switch family {
	case 4:
		return "4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil
	case 6:
		return "6", net.JoinHostPort("::1", fmt.Sprint(port)), nil
	default:
		return "", "", errors.New("DNS proxy requires IPv4 or IPv6 cluster mode")
	}
}

func ListenTransparentUDP(ctx context.Context, family, port int) (*net.UDPConn, error) {
	suffix, address, err := listenerAddress(family, port)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: transparentControl(family, true)}
	conn, err := lc.ListenPacket(ctx, "udp"+suffix, address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func ListenTransparentTCP(ctx context.Context, family, port int) (net.Listener, error) {
	suffix, address, err := listenerAddress(family, port)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: transparentControl(family, false)}
	return lc.Listen(ctx, "tcp"+suffix, address)
}

// originalDestination uses the kernel's pre-steering destination, not data
// supplied by the workload. The trusted BPF tuple map must additionally attest
// the originating interface, assigned source IP, and current endpoint lifetime.
func originalDestination(oob []byte, family int) (netip.AddrPort, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, message := range messages {
		if family == 4 && message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR {
			if len(message.Data) < 8 {
				return netip.AddrPort{}, errors.New("short IPv4 original destination")
			}
			addr := netip.AddrFrom4([4]byte(message.Data[4:8]))
			return netip.AddrPortFrom(addr, uint16(message.Data[2])<<8|uint16(message.Data[3])), nil
		}
		if family == 6 && message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR {
			if len(message.Data) < 24 {
				return netip.AddrPort{}, errors.New("short IPv6 original destination")
			}
			addr := netip.AddrFrom16([16]byte(message.Data[8:24]))
			return netip.AddrPortFrom(addr, uint16(message.Data[2])<<8|uint16(message.Data[3])), nil
		}
	}
	return netip.AddrPort{}, errors.New("missing trusted DNS original destination")
}

func sendTransparentUDP(ctx context.Context, family int, source, destination netip.AddrPort, response []byte) error {
	packet, err := dnsUDPReplyPacket(source, destination, response)
	if err != nil {
		return err
	}
	fd, err := openDNSReplySocket(family)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var address unix.Sockaddr
	if family == 4 {
		address = &unix.SockaddrInet4{Addr: destination.Addr().As4()}
	} else {
		address = &unix.SockaddrInet6{Addr: destination.Addr().As16()}
	}
	// The descriptor is nonblocking. A full kernel queue fails this publication
	// instead of extending the fence or holding an unbounded sender goroutine.
	if err = ctx.Err(); err != nil {
		return err
	}
	return unix.Sendto(fd, packet, unix.MSG_DONTWAIT, address)
}

func openDNSReplySocket(family int) (int, error) {
	af := unix.AF_INET
	if family == 6 {
		af = unix.AF_INET6
	} else if family != 4 {
		return -1, errors.New("invalid DNS reply family")
	}
	fd, err := unix.Socket(af, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return -1, err
	}
	set := func(level, option, value int) {
		if err == nil {
			err = unix.SetsockoptInt(fd, level, option, value)
		}
	}
	set(unix.SOL_SOCKET, unix.SO_MARK, int(DNSReplyMark))
	if family == 4 {
		set(unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		set(unix.SOL_IP, unix.IP_HDRINCL, 1)
	} else {
		set(unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		set(unix.SOL_IPV6, unix.IPV6_HDRINCL, 1)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

type dnsSteering struct {
	rule   *netlink.Rule
	route  *netlink.Route
	filter *dnsNoTrack
}

type dnsNoTrack struct {
	tables      *iptables.IPTables
	ingressMark uint32
}

func noTrackRules(chain string, mark uint32, portFlag string) [][]string {
	var rules [][]string
	for _, protocol := range []string{"udp", "tcp"} {
		rules = append(rules, []string{"-p", protocol, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", mark, mark), "-m", protocol, portFlag, "53", "-m", "comment", "--comment", "aws-nodeagent-fqdn", "-j", "CT", "--notrack"})
	}
	return rules
}

func noTrackJump(chain string, mark uint32) []string {
	return []string{"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", mark, mark), "-m", "comment", "--comment", "aws-nodeagent-fqdn", "-j", chain}
}

func installDNSForwardGuard(family int, mark uint32) error {
	protocol := iptables.ProtocolIPv4
	if family == 6 {
		protocol = iptables.ProtocolIPv6
	}
	tables, err := iptables.New(iptables.IPFamily(protocol), iptables.Timeout(2))
	if err != nil {
		return err
	}
	// The mark is owned exclusively by TC DNS interception. Match it even if
	// a subsequent NAT rule changes the port, so a missing route or NOTRACK
	// rule cannot turn interception into ordinary forwarding.
	return tables.InsertUnique("filter", "FORWARD", 1, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", mark, mark), "-m", "comment", "--comment", "aws-nodeagent-fqdn-failclosed", "-j", "DROP")
}

func installDNSNoTrack(family int, mark uint32) (*dnsNoTrack, error) {
	protocol := iptables.ProtocolIPv4
	if family == 6 {
		protocol = iptables.ProtocolIPv6
	}
	tables, err := iptables.New(iptables.IPFamily(protocol), iptables.Timeout(2))
	if err != nil {
		return nil, err
	}
	rules := &dnsNoTrack{tables: tables, ingressMark: mark}
	for _, spec := range []struct {
		chain, parent, port string
		mark                uint32
	}{{"AWS-NP-FQDN-PRE", "PREROUTING", "--dport", mark}, {"AWS-NP-FQDN-OUT", "OUTPUT", "--sport", DNSReplyMark}} {
		exists, err := tables.ChainExists("raw", spec.chain)
		if err != nil {
			return nil, err
		}
		if !exists {
			if err = tables.NewChain("raw", spec.chain); err != nil {
				return nil, err
			}
		}
		wanted := noTrackRules(spec.chain, spec.mark, spec.port)
		current, err := tables.List("raw", spec.chain)
		if err != nil {
			return nil, err
		}
		for _, line := range current {
			if line == "-N "+spec.chain {
				continue
			}
			line = strings.ReplaceAll(line, "\"aws-nodeagent-fqdn\"", "aws-nodeagent-fqdn")
			owned := false
			for _, rule := range wanted {
				if line == "-A "+spec.chain+" "+strings.Join(rule, " ") {
					owned = true
					break
				}
			}
			if !owned {
				return nil, fmt.Errorf("DNS raw chain %s contains an unowned rule", spec.chain)
			}
		}
		for _, rule := range wanted {
			if err = tables.AppendUnique("raw", spec.chain, rule...); err != nil {
				return nil, err
			}
		}
		// Raw NOTRACK runs before conntrack and kube-proxy Service DNAT. A
		// marked packet must retain the resolver tuple assigned by TC.
		if err = tables.InsertUnique("raw", spec.parent, 1, noTrackJump(spec.chain, spec.mark)...); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func (n *dnsNoTrack) close() error {
	if n == nil {
		return nil
	}
	var failures []error
	for _, spec := range []struct {
		chain, parent, port string
		mark                uint32
	}{{"AWS-NP-FQDN-PRE", "PREROUTING", "--dport", n.ingressMark}, {"AWS-NP-FQDN-OUT", "OUTPUT", "--sport", DNSReplyMark}} {
		failures = append(failures, n.tables.DeleteIfExists("raw", spec.parent, noTrackJump(spec.chain, spec.mark)...))
		for _, rule := range noTrackRules(spec.chain, spec.mark, spec.port) {
			failures = append(failures, n.tables.DeleteIfExists("raw", spec.chain, rule...))
		}
		failures = append(failures, n.tables.DeleteChain("raw", spec.chain))
	}
	return errors.Join(failures...)
}

func installDNSSteering(family int, mark uint32, table, priority int) (*dnsSteering, error) {
	// Deliberately retained across listener shutdown and setup failures. It is
	// inert for unselected traffic and protects still-enrolled endpoints while
	// controller/host plumbing recover. Drain nodes before feature removal.
	if err := installDNSForwardGuard(family, mark); err != nil {
		return nil, err
	}
	handle, err := newDNSRouteHandle()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	af, network := unix.AF_INET, "0.0.0.0/0"
	if family == 6 {
		af, network = unix.AF_INET6, "::/0"
	}
	lo, err := handle.LinkByName("lo")
	if err != nil {
		return nil, err
	}
	_, destination, _ := net.ParseCIDR(network)
	route := &netlink.Route{LinkIndex: lo.Attrs().Index, Dst: destination, Scope: netlink.SCOPE_HOST, Table: table, Type: unix.RTN_LOCAL, Protocol: dnsRouteProtocol, Family: af}
	routes, err := handle.RouteListFiltered(af, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	existingRoute := false
	for _, candidate := range routes {
		if candidate.Protocol != dnsRouteProtocol || candidate.LinkIndex != route.LinkIndex || candidate.Type != route.Type || (candidate.Dst != nil && candidate.Dst.String() != network) {
			return nil, fmt.Errorf("DNS route table %d contains an unowned route", table)
		}
		existingRoute = true
	}
	rule := netlink.NewRule()
	rule.Family, rule.Mark, rule.Table, rule.Priority, rule.Protocol = af, mark, table, priority, dnsRouteProtocol
	mask := mark
	rule.Mask = &mask
	rules, err := handle.RuleList(af)
	if err != nil {
		return nil, err
	}
	existingRule := false
	for _, candidate := range rules {
		if candidate.Priority != priority && candidate.Table != table && candidate.Mark&mark == 0 {
			continue
		}
		if candidate.Protocol != dnsRouteProtocol || candidate.Priority != priority || candidate.Table != table || candidate.Mark != mark || candidate.Mask == nil || *candidate.Mask != mark || candidate.Src != nil || candidate.Dst != nil || candidate.IifName != "" || candidate.OifName != "" {
			return nil, errors.New("DNS routing mark, table or priority conflicts with an existing rule")
		}
		existingRule = true
	}
	// A local route alone cannot bypass DNS classification. Install it before
	// the rule, and publish BPF readiness only after both listeners exist.
	if !existingRoute {
		if err := handle.RouteAdd(route); err != nil {
			return nil, err
		}
	}
	if !existingRule {
		if err := handle.RuleAdd(rule); err != nil {
			if !existingRoute {
				_ = handle.RouteDel(route)
			}
			return nil, err
		}
	}
	filter, err := installDNSNoTrack(family, mark)
	if err != nil {
		if !existingRule {
			_ = handle.RuleDel(rule)
		}
		if !existingRoute {
			_ = handle.RouteDel(route)
		}
		return nil, err
	}
	return &dnsSteering{rule: rule, route: route, filter: filter}, nil
}

func (s *dnsSteering) close() error {
	if s == nil {
		return nil
	}
	handle, err := newDNSRouteHandle()
	if err != nil {
		return errors.Join(err, s.filter.close())
	}
	defer handle.Close()
	return errors.Join(handle.RuleDel(s.rule), handle.RouteDel(s.route), s.filter.close())
}

func newDNSRouteHandle() (*netlink.Handle, error) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = handle.SetSocketTimeout(2 * time.Second); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}
