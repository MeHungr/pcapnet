package pcapnet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestAllocatedTCPEthernetEcho traverses allocation, the session framing, both
// gVisor stacks, real UDP serialization/parsing, and compiled BPF filters. Native
// capture is simulated; optional host socket reservations use counted fakes.
func TestAllocatedTCPEthernetEcho(t *testing.T) {
	for _, reserve := range []bool{false, true} {
		t.Run(fmt.Sprint(reserve), func(t *testing.T) {
			leftMAC, rightMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
			left := &ethernetCapture{inbound: make(chan []byte, 1024), local: leftMAC, remote: rightMAC, done: make(chan struct{})}
			right := &ethernetCapture{inbound: make(chan []byte, 1024), local: rightMAC, remote: leftMAC, done: make(chan struct{})}
			left.peer, right.peer = right, left
			local, remote := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
			leftPort, rightPort := &fakeReservation{}, &fakeReservation{}
			leftCfg := PCAPConfig{DeviceName: "left", LocalPort: 45000, Peer: netip.AddrPortFrom(remote, 45001), ReserveUDPPort: reserve}
			rightCfg := PCAPConfig{DeviceName: "right", LocalPort: 45001, Peer: netip.AddrPortFrom(local, 45000), ReserveUDPPort: reserve}
			leftOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, leftCfg, local, left, leftPort)}
			rightOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, rightCfg, remote, right, rightPort), interfaceForIP: func(netip.Addr) (*net.Interface, error) {
				return &net.Interface{Name: "right", HardwareAddr: rightMAC, MTU: 1500}, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			udpClient, err := newUDPConn(ctx, UDPConfig{DeviceName: "left", LocalPort: 45000, ReserveUDPPort: reserve}, leftCfg.Peer, leftOps)
			if err != nil {
				t.Fatal(err)
			}
			defer udpClient.Close()
			udpServer, err := newUDPConn(ctx, UDPConfig{DeviceName: "right", LocalIP: remote, LocalPort: 45001, ReserveUDPPort: reserve}, netip.AddrPort{}, rightOps)
			if err != nil {
				t.Fatal(err)
			}
			defer udpServer.Close()
			serverEndpoint, _ := NewPlainUDPEndpoint(udpServer)
			clientEndpoint, _ := NewPlainUDPEndpoint(udpClient)
			server, err := NewTCPServer(serverEndpoint, testServerConfig(), 6767)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			stop := context.AfterFunc(ctx, func() { server.Close() })
			defer stop()
			transport, a, err := AllocateClient(ctx, clientEndpoint, Peer{AddrPort: leftCfg.Peer}, 1200)
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewVirtualStackWithTransport(Config{VirtualIP: a.VirtualIP, PeerSubnet: netip.PrefixFrom(a.ServerIP, 32), MTU: a.MTU}, transport)
			if err != nil {
				transport.Close()
				t.Fatal(err)
			}
			defer v.Close()
			payload := bytes.Repeat([]byte("allocated-echo"), 1024)
			result := make(chan error, 1)
			go func() {
				conn, err := server.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.CopyN(conn, conn, int64(len(payload)))
				result <- err
			}()
			conn, err := v.Dial(ctx, a.ServerIP.String(), 6767)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, reply) {
				t.Fatal("echo mismatch")
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			v.Close()
			if err := v.Err(); err != nil {
				t.Fatal(err)
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			want := 0
			if reserve {
				want = 1
			}
			if leftPort.closes != want || rightPort.closes != want {
				t.Fatal("reservation cleanup mismatch")
			}
		})
	}
}
