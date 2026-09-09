//go:build linux

package fqdn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// DNSBridge attests trusted TC metadata, never merely a pod source address.
// Resolver authorization is checked by TC before a TCP SYN can reach the socket.
type DNSBridge interface {
	LookupDNSIdentity(context.Context, netip.AddrPort, netip.AddrPort, uint8) (Endpoint, error)
	SetProxyReady(context.Context, uint32, uint32, bool) error
}

// ProxyConfig intentionally requires measured, explicit resource limits.
// MaxPendingBytes covers request and response wire buffers; parsed records are
// additionally bounded by maxDNSRecords and MaxPending. At most two transient
// sockets exist per pending UDP exchange, in addition to MaxTCPSockets client
// and upstream sockets. TCP requests are processed sequentially per connection.
type ProxyConfig struct {
	Port, Family                    int
	Mark                            uint32
	RouteTable, RulePriority        int
	MaxPending                      int
	MaxPendingBytes                 int64
	MaxTCPSockets                   int
	ExchangeTimeout, TCPIdleTimeout time.Duration
}

type ProxyStats struct {
	Pending, TCPSockets                                        int
	PendingBytes                                               int64
	UpstreamFailures, AuthenticationFailures, CapacityFailures uint64
}

type Proxy struct {
	engine                                                     *Engine
	bridge                                                     DNSBridge
	config                                                     ProxyConfig
	mu                                                         sync.Mutex
	udp                                                        *net.UDPConn
	tcp                                                        net.Listener
	steering                                                   *dnsSteering
	cancel                                                     context.CancelFunc
	connections                                                map[net.Conn]struct{}
	wg                                                         sync.WaitGroup
	pending                                                    chan struct{}
	tcpSlots                                                   chan struct{}
	pendingBytes                                               int64
	ready                                                      atomic.Bool
	upstreamFailures, authenticationFailures, capacityFailures atomic.Uint64
}

func NewProxy(engine *Engine, bridge DNSBridge, config ProxyConfig) (*Proxy, error) {
	if engine == nil || bridge == nil {
		return nil, errors.New("DNS proxy requires engine and trusted datapath bridge")
	}
	if config.Port < 1 || config.Port > 65535 || config.Port == 53 || (config.Family != 4 && config.Family != 6) || config.MaxPending <= 0 || config.MaxPendingBytes < int64(maxDNSMessage+12) || config.MaxTCPSockets <= 0 || config.ExchangeTimeout <= 0 || config.TCPIdleTimeout <= 0 {
		return nil, errors.New("invalid DNS proxy configuration or missing resource limits")
	}
	if config.Mark == 0 {
		config.Mark = DefaultDNSMark
	}
	if config.RouteTable == 0 {
		config.RouteTable = DefaultDNSRouteTable
	}
	if config.RulePriority == 0 {
		config.RulePriority = DefaultDNSRulePriority
	}
	if config.Mark&(config.Mark-1) != 0 || config.Mark&DNSReplyMark != 0 || config.RouteTable <= 255 || config.RulePriority <= 0 {
		return nil, errors.New("DNS proxy requires one reserved mark bit, private routing table and positive rule priority")
	}
	return &Proxy{engine: engine, bridge: bridge, config: config, connections: make(map[net.Conn]struct{}), pending: make(chan struct{}, config.MaxPending), tcpSlots: make(chan struct{}, config.MaxTCPSockets)}, nil
}

func (p *Proxy) Ready() bool { return p.ready.Load() }

// Reconcile restores exclusively owned host rules while keeping established DNS
// sockets open. The forwarding guard blocks selected DNS during a missing-route
// repair. Conflicts or repair failures withdraw readiness and require Start to
// repeat the complete checked setup; they never fall back to direct forwarding.
func (p *Proxy) Reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel == nil || !p.ready.Load() {
		return errors.New("DNS proxy is not running")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	steering, err := installDNSSteering(p.config.Family, p.config.Mark, p.config.RouteTable, p.config.RulePriority)
	if err == nil {
		p.steering = steering
		return nil
	}
	p.ready.Store(false)
	bounded, cancel := context.WithTimeout(context.Background(), p.config.ExchangeTimeout)
	defer cancel()
	return errors.Join(err, p.bridge.SetProxyReady(bounded, uint32(p.config.Port), p.config.Mark, false))
}

func (p *Proxy) Stats() ProxyStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ProxyStats{Pending: len(p.pending), PendingBytes: p.pendingBytes, TCPSockets: len(p.tcpSlots), UpstreamFailures: p.upstreamFailures.Load(), AuthenticationFailures: p.authenticationFailures.Load(), CapacityFailures: p.capacityFailures.Load()}
}

// Start publishes readiness only after every prerequisite exists. A crash makes
// socket lookup fail and TC drops selected DNS even if the map ready bit remains.
func (p *Proxy) Start(parent context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		return errors.New("DNS proxy already started")
	}
	if err := p.bridge.SetProxyReady(parent, uint32(p.config.Port), p.config.Mark, false); err != nil {
		return err
	}
	steering, err := installDNSSteering(p.config.Family, p.config.Mark, p.config.RouteTable, p.config.RulePriority)
	if err != nil {
		return err
	}
	udp, err := ListenTransparentUDP(parent, p.config.Family, p.config.Port)
	if err != nil {
		_ = steering.close()
		return err
	}
	tcp, err := ListenTransparentTCP(parent, p.config.Family, p.config.Port)
	if err != nil {
		_ = udp.Close()
		_ = steering.close()
		return err
	}
	// NodeLocal DNSCache can exclusively own resolverIP:53. Raw UDP replies
	// avoid that bind conflict; verify the required capability before readiness.
	replyFD, err := openDNSReplySocket(p.config.Family)
	if err != nil {
		_ = tcp.Close()
		_ = udp.Close()
		_ = steering.close()
		return err
	}
	_ = unix.Close(replyFD)
	if err = p.bridge.SetProxyReady(parent, uint32(p.config.Port), p.config.Mark, true); err != nil {
		_ = tcp.Close()
		_ = udp.Close()
		_ = steering.close()
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	p.udp, p.tcp, p.steering, p.cancel = udp, tcp, steering, cancel
	p.ready.Store(true)
	p.wg.Add(2)
	go p.serveUDP(ctx, udp)
	go p.serveTCP(ctx, tcp)
	go func() { <-ctx.Done(); _ = p.Close() }()
	return nil
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.cancel == nil {
		p.mu.Unlock()
		return nil
	}
	cancel, udp, tcp, steering := p.cancel, p.udp, p.tcp, p.steering
	p.cancel = nil
	p.ready.Store(false)
	p.mu.Unlock()
	ctx, finish := context.WithTimeout(context.Background(), p.config.ExchangeTimeout)
	defer finish()
	// Keep owned routing in place if restrictive publication fails. Listener
	// removal still makes BPF socket lookup fail closed; return the error.
	unready := p.bridge.SetProxyReady(ctx, uint32(p.config.Port), p.config.Mark, false)
	cancel()
	err := errors.Join(unready, udp.Close(), tcp.Close())
	p.mu.Lock()
	for conn := range p.connections {
		_ = conn.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	if unready == nil {
		err = errors.Join(err, steering.close())
	}
	return err
}

func (p *Proxy) reserve(size int64) bool {
	select {
	case p.pending <- struct{}{}:
	default:
		p.capacityFailures.Add(1)
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if size > p.config.MaxPendingBytes-p.pendingBytes {
		<-p.pending
		p.capacityFailures.Add(1)
		return false
	}
	p.pendingBytes += size
	return true
}
func (p *Proxy) release(size int64) { p.mu.Lock(); p.pendingBytes -= size; p.mu.Unlock(); <-p.pending }

func (p *Proxy) authenticate(ctx context.Context, source, destination netip.AddrPort, protocol uint8) (endpoint Endpoint, retErr error) {
	started := time.Now()
	defer func() { Observe("authenticate", started, retErr) }()
	if destination.Port() != 53 || !source.IsValid() || !destination.IsValid() {
		p.authenticationFailures.Add(1)
		return Endpoint{}, errors.New("invalid intercepted DNS tuple")
	}
	ep, err := p.bridge.LookupDNSIdentity(ctx, source, destination, protocol)
	if err != nil {
		p.authenticationFailures.Add(1)
		return Endpoint{}, err
	}
	current, ok := p.engine.Lookup(ep.IfIndex, source.Addr().Unmap())
	if !ok || current.UID != ep.UID || current.Lifetime != ep.Lifetime || current.IP != source.Addr().Unmap() {
		p.authenticationFailures.Add(1)
		return Endpoint{}, ErrEndpoint
	}
	return current, nil
}

func (p *Proxy) serveUDP(ctx context.Context, listener *net.UDPConn) {
	defer p.wg.Done()
	buffer, oob := make([]byte, maxDNSMessage), make([]byte, 256)
	for {
		n, on, flags, source, err := listener.ReadMsgUDPAddrPort(buffer, oob)
		if err != nil {
			if ctx.Err() == nil {
				p.ready.Store(false)
			}
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		destination, err := originalDestination(oob[:on], p.config.Family)
		if err != nil {
			p.authenticationFailures.Add(1)
			continue
		}
		reservation := int64(n + maxDNSMessage)
		if !p.reserve(reservation) {
			continue
		}
		request := append([]byte(nil), buffer[:n]...)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.release(reservation)
			exchange, cancel := context.WithTimeout(ctx, p.config.ExchangeTimeout)
			defer cancel()
			ep, err := p.authenticate(exchange, source, destination, 17)
			if err != nil {
				return
			}
			response, err := p.exchangeUDP(exchange, destination, request)
			write := func(c context.Context, wire []byte) error {
				var err error
				wire, err = fitDNSUDP(request, wire)
				if err != nil {
					return err
				}
				return sendTransparentUDP(c, p.config.Family, destination, source, wire)
			}
			if err == nil {
				err = p.publish(exchange, ep, source, destination, 17, request, response, write)
			}
			if err != nil && exchange.Err() == nil {
				if failure := dnsFailure(request); failure != nil {
					_ = write(exchange, failure)
				}
			}
		}()
	}
}

func (p *Proxy) exchangeUDP(ctx context.Context, destination netip.AddrPort, request []byte) (wire []byte, retErr error) {
	started := time.Now()
	defer func() { Observe("upstream", started, retErr) }()
	query, err := unpackDNS(request)
	if err != nil || query.Response || query.OpCode != 0 {
		return nil, errors.New("invalid DNS request")
	}
	network := "udp4"
	if p.config.Family == 6 {
		network = "udp6"
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, destination.String())
	if err != nil {
		p.upstreamFailures.Add(1)
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err = conn.Write(request); err != nil {
		p.upstreamFailures.Add(1)
		return nil, err
	}
	response := make([]byte, maxDNSMessage)
	n, err := conn.Read(response)
	if err != nil {
		p.upstreamFailures.Add(1)
		return nil, err
	}
	// A truncated response is forwarded under the publication fence without
	// learning. The client's TCP retry traverses the same authorization path.
	return response[:n], nil
}

func (p *Proxy) publish(ctx context.Context, ep Endpoint, source, destination netip.AddrPort, protocol uint8, request, response []byte, write func(context.Context, []byte) error) (retErr error) {
	started := time.Now()
	defer func() { Observe("publish", started, retErr) }()
	if protocol == 17 {
		var err error
		response, err = fitDNSUDP(request, response)
		if err != nil {
			return err
		}
	}
	now, err := (BootClock{}).Now()
	if err != nil {
		return err
	}
	answer, err := ParseDNSAnswer(request, response, now, p.config.Family)
	if err != nil {
		return err
	}
	return p.engine.PublishDNS(ctx, ep, answer.Question, answer.Observations, func(fence context.Context, matched bool, ttls []uint32) error {
		// Revalidate both trusted tuple provenance and endpoint enrollment while
		// holding the admission fence, immediately before any positive bytes.
		current, err := p.authenticate(fence, source, destination, protocol)
		if err != nil {
			return err
		}
		if current.Lifetime != ep.Lifetime || current.UID != ep.UID {
			return ErrEndpoint
		}
		wire := response
		if matched {
			wire, err = answer.Pack(ttls)
			if err != nil {
				return err
			}
		}
		return write(fence, wire)
	})
}

func (p *Proxy) serveTCP(ctx context.Context, listener net.Listener) {
	defer p.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				p.ready.Store(false)
			}
			return
		}
		select {
		case p.tcpSlots <- struct{}{}:
		default:
			p.capacityFailures.Add(1)
			_ = conn.Close()
			continue
		}
		p.mu.Lock()
		p.connections[conn] = struct{}{}
		p.mu.Unlock()
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { _ = conn.Close(); p.mu.Lock(); delete(p.connections, conn); p.mu.Unlock(); <-p.tcpSlots }()
			p.handleTCP(ctx, conn)
		}()
	}
}

func (p *Proxy) handleTCP(ctx context.Context, client net.Conn) {
	source, err := netip.ParseAddrPort(client.RemoteAddr().String())
	if err != nil {
		return
	}
	destination, err := netip.ParseAddrPort(client.LocalAddr().String())
	if err != nil {
		return
	}
	identityCtx, cancel := context.WithTimeout(ctx, p.config.ExchangeTimeout)
	ep, err := p.authenticate(identityCtx, source, destination, 6)
	cancel()
	if err != nil {
		return
	}
	var upstream net.Conn
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = client.SetReadDeadline(time.Now().Add(p.config.TCPIdleTimeout))
		var header [2]byte
		if _, err = io.ReadFull(client, header[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[:]))
		if length < 12 {
			return
		}
		reservation := int64(length + maxDNSMessage)
		if !p.reserve(reservation) {
			return
		}
		request := make([]byte, length)
		if _, err = io.ReadFull(client, request); err != nil {
			p.release(reservation)
			return
		}
		exchange, finish := context.WithTimeout(ctx, p.config.ExchangeTimeout)
		err = func() error {
			current, err := p.authenticate(exchange, source, destination, 6)
			if err != nil {
				return err
			}
			if current.UID != ep.UID || current.Lifetime != ep.Lifetime {
				return ErrEndpoint
			}
			query, err := unpackDNS(request)
			if err != nil || query.Response || query.OpCode != 0 {
				return errors.New("invalid TCP DNS request")
			}
			if upstream == nil {
				network := "tcp4"
				if p.config.Family == 6 {
					network = "tcp6"
				}
				upstream, err = (&net.Dialer{}).DialContext(exchange, network, destination.String())
				if err != nil {
					p.upstreamFailures.Add(1)
					return err
				}
			}
			deadline, _ := exchange.Deadline()
			_ = upstream.SetDeadline(deadline)
			stop := context.AfterFunc(exchange, func() { _ = upstream.Close() })
			defer stop()
			if err = writeDNSFrame(upstream, request); err != nil {
				p.upstreamFailures.Add(1)
				return err
			}
			response, err := readDNSFrame(upstream)
			if err != nil {
				p.upstreamFailures.Add(1)
				return err
			}
			return p.publish(exchange, ep, source, destination, 6, request, response, func(fence context.Context, wire []byte) error {
				deadline, _ := fence.Deadline()
				if err := client.SetWriteDeadline(deadline); err != nil {
					return err
				}
				stop := context.AfterFunc(fence, func() { _ = client.SetWriteDeadline(time.Now()) })
				defer stop()
				if err := fence.Err(); err != nil {
					return err
				}
				return writeDNSFrame(client, wire)
			})
		}()
		if err != nil && exchange.Err() == nil {
			if failure := dnsFailure(request); failure != nil {
				deadline, _ := exchange.Deadline()
				_ = client.SetWriteDeadline(deadline)
				_ = writeDNSFrame(client, failure)
			}
		}
		finish()
		p.release(reservation)
		if err != nil {
			return
		}
	}
}

func readDNSFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < 12 {
		return nil, errors.New("invalid DNS TCP frame length")
	}
	wire := make([]byte, length)
	_, err := io.ReadFull(reader, wire)
	return wire, err
}

func writeDNSFrame(writer io.Writer, wire []byte) error {
	if len(wire) < 12 || len(wire) > maxDNSMessage {
		return fmt.Errorf("invalid DNS TCP frame length %d", len(wire))
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(wire)))
	for _, part := range [][]byte{header[:], wire} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
