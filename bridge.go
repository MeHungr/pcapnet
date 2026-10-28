package pcapnet

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// packetBridge moves complete IPv4 packets between one gVisor link and one
// owned transport. Workers share cancellation but process each direction alone.
type packetBridge struct {
	lifetime  context.Context
	link      *channel.Endpoint  // Link owned by the parent VirtualStack
	transport PacketTransport    // Transport closed with this bridge
	config    Config             // Normalized virtual address and MTU settings
	cancel    context.CancelFunc // Stops both packet workers
	workers   sync.WaitGroup     // Joins workers before stack resources are freed
	once      sync.Once          // Serializes bridge shutdown
	closeErr  error              // Stable transport cleanup result
	mu        sync.Mutex         // Protects the first worker failure
	workerErr error              // First unexpected packet worker failure
	onFailure func(error)        // Notifies the owner outside the bridge lock
}

// NewVirtualStackWithTransport creates a stack and starts its packet bridge.
// Successful construction transfers exclusive transport ownership to the stack;
// on error, the caller retains ownership and must close the transport itself.
// PCAP transport and stack MTUs must match. Other transports carry packets up to
// the configured virtual MTU without adding any transport-specific requirement.
// Callers must not concurrently close or attach the transport during construction.
// A subsequent worker failure shuts down the stack automatically; Err preserves
// its cause. A transport failing immediately can begin shutdown before return.
func NewVirtualStackWithTransport(cfg Config, transport PacketTransport) (*VirtualStack, error) {
	return newVirtualStackWithTransport(cfg, transport, nil)
}

// configure runs before bridge publication, so server listeners are installed
// before a packet failure can start stack destruction.
func newVirtualStackWithTransport(cfg Config, transport PacketTransport, configure func(*VirtualStack)) (*VirtualStack, error) {
	// Reject typed nil implementations as well as a nil interface before any
	// methods are invoked or ownership is transferred.
	if nilPacketTransport(transport) {
		return nil, fmt.Errorf("a packet transport is required")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if p, ok := transport.(*PCAPTransport); ok {
		if err := p.operationErr(context.Background()); err != nil {
			return nil, fmt.Errorf("attach PCAP transport: %w", err)
		}
		if p.resources.config.MTU != cfg.MTU {
			return nil, fmt.Errorf("stack MTU %d does not match PCAP transport MTU %d", cfg.MTU, p.resources.config.MTU)
		}
	}
	switch p := transport.(type) {
	case *ClientTransport:
		if p.ctx.Err() != nil || cfg.VirtualIP != p.assignment.VirtualIP || cfg.PeerSubnet != netip.PrefixFrom(p.assignment.ServerIP, 32) || cfg.MTU != p.assignment.MTU {
			return nil, fmt.Errorf("stack configuration does not match client assignment")
		}
	case *ServerTransport:
		if p.ctx.Err() != nil || cfg.VirtualIP != p.config.VirtualIP || cfg.PeerSubnet != p.config.AddressPool || cfg.MTU != p.config.MTU {
			return nil, fmt.Errorf("stack configuration does not match server allocation policy")
		}
	}
	v, err := NewVirtualStack(cfg)
	if err != nil {
		return nil, err
	}

	if p, ok := transport.(*ServerTransport); ok {
		p.mu.Lock()
		p.expire = v.expireVirtualPeer
		p.mu.Unlock()
	}

	if configure != nil {
		configure(v)
	}

	// All fallible validation is complete. The bridge now owns the transport
	// and begins moving packets using the stack's lifetime context.
	// A transport can fail as soon as a worker starts. Hold the owner lock
	// until bridge publication is complete so the failure callback cannot
	// initiate shutdown while v.bridge is still being assigned.
	v.mu.Lock()
	v.bridge = startPacketBridge(v.closeCtx, v.Link, cfg, transport, v.workerFailed)
	v.mu.Unlock()
	return v, nil
}

// nilPacketTransport detects nil values hidden behind an interface. User-defined
// transport implementations can have any nil-capable underlying Go type.
func nilPacketTransport(transport PacketTransport) bool {
	return nilInterface(transport)
}

// nilInterface rejects typed nil implementations before invoking their methods.
func nilInterface(implementation any) bool {
	if implementation == nil {
		return true
	}
	value := reflect.ValueOf(implementation)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// startPacketBridge starts both directions only after the stack is initialized.
// A worker failure cancels its sibling, retains its cause, and notifies the owner.
func startPacketBridge(parent context.Context, link *channel.Endpoint, cfg Config, transport PacketTransport, onFailure func(error)) *packetBridge {
	ctx, cancel := context.WithCancel(parent)
	b := &packetBridge{lifetime: ctx, link: link, transport: transport, config: cfg, cancel: cancel, onFailure: onFailure}
	b.workers.Add(2)
	go func() {
		defer b.workers.Done()
		b.workerStopped(ctx, b.egress(ctx))
	}()
	go func() {
		defer b.workers.Done()
		b.workerStopped(ctx, b.ingress(ctx))
	}()
	return b
}

// workerStopped preserves the first unexpected failure and stops its sibling.
// Shutdown cancellation is expected and does not replace a transport failure.
func (b *packetBridge) workerStopped(ctx context.Context, err error) {
	firstFailure := false
	if err != nil && ctx.Err() == nil {
		b.mu.Lock()
		if b.workerErr == nil {
			b.workerErr = err
			firstFailure = true
		}
		b.mu.Unlock()
	}
	b.cancel()
	if firstFailure && b.onFailure != nil {
		b.onFailure(err)
	}
}

// egress drains gVisor packets and gives the transport an independent byte slice.
// Packet views and references are released before any blocking transport call.
func (b *packetBridge) egress(ctx context.Context) error {
	for {
		pkt := b.link.ReadContext(ctx)
		if pkt == nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("bridge link closed unexpectedly: %w", ErrClosed)
		}
		if barrier, ok := pkt.Owner.(*egressBarrier); ok {
			close(barrier.done)
			pkt.DecRef()
			continue
		}
		mark := pkt.Mark
		view := pkt.ToView()
		data := append([]byte(nil), view.AsSlice()...)
		view.Release()
		pkt.DecRef()

		if !b.validPacket(data, false) {
			continue
		}
		var err error
		if server, ok := b.transport.(*ServerTransport); ok {
			err = server.sendMarked(ctx, data, mark)
		} else {
			err = b.transport.Send(ctx, data)
		}
		if err != nil {
			return fmt.Errorf("bridge send: %w", err)
		}
	}
}

// ingress accepts packets for the local address from the remote subnet and
// injects them into gVisor. The transport supplies owned bytes; gVisor retains a reference
// while processing after our local packet reference is released.
func (b *packetBridge) ingress(ctx context.Context) error {
	for {
		var data []byte
		var err error
		var queued sessionPacket
		server, serverMode := b.transport.(*ServerTransport)
		if serverMode {
			queued, err = server.receiveSessionPacket(ctx)
			data = queued.data
		} else {
			data, err = b.transport.Receive(ctx)
		}
		if err != nil {
			return fmt.Errorf("bridge receive: %w", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !b.validPacket(data, true) {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		if serverMode {
			server.injectGeneration(queued, func(_ []byte, mark uint32) {
				pkt.Mark = mark
				b.link.InjectInbound(ipv4.ProtocolNumber, pkt)
			})
		} else {
			b.link.InjectInbound(ipv4.ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
}

// validPacket enforces IPv4 framing, MTU, and direction-specific virtual peers.
// Checksums and TCP behavior remain the responsibility of the receiving stack.
func (b *packetBridge) validPacket(data []byte, inbound bool) bool {
	if validateInnerIPv4(data, b.config.MTU) != nil {
		return false
	}
	source := netip.AddrFrom4([4]byte(data[12:16]))
	destination := netip.AddrFrom4([4]byte(data[16:20]))
	local, remote := source, destination
	if inbound {
		local, remote = destination, source
	}
	return local == b.config.VirtualIP && remote != local && validVirtualIP(remote) && b.config.PeerSubnet.Contains(remote)
}

// Close cancels both workers, closes the owned transport to unblock pending I/O,
// and joins workers. It must be called by the owner, never by a bridge worker.
func (b *packetBridge) Close() error {
	b.once.Do(func() {
		b.cancel()
		b.closeErr = b.transport.Close()
		b.workers.Wait()
	})
	return b.closeErr
}

// failure returns the first unexpected worker error under the bridge lock.
func (b *packetBridge) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.workerErr
}
