package pcapnet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestDirectUDPEthernetEcho exercises direct physical UDP with the actual BPF,
// serialization, parsing, dial, and listener code, without gVisor or a bridge.
func TestDirectUDPEthernetEcho(t *testing.T) {
	for _, mode := range []struct {
		reserve bool
		magic   []byte
	}{{false, nil}, {true, nil}, {false, []byte{0, 0xff, 'P'}}, {true, []byte{0, 0xff, 'P'}}} {
		reserve, magic := mode.reserve, mode.magic
		t.Run(fmt.Sprintf("reserve=%v/magic=%x", reserve, magic), func(t *testing.T) {
			leftMAC, rightMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
			left := &ethernetCapture{inbound: make(chan []byte, 1024), local: leftMAC, remote: rightMAC, done: make(chan struct{})}
			right := &ethernetCapture{inbound: make(chan []byte, 1024), local: rightMAC, remote: leftMAC, done: make(chan struct{})}
			left.peer, right.peer = right, left
			leftPort, rightPort := &fakeReservation{}, &fakeReservation{}
			local := netip.MustParseAddr("192.0.2.1")
			remote := netip.MustParseAddr("192.0.2.2")
			leftPhysical := PCAPConfig{DeviceName: "left", LocalPort: 45000, Peer: netip.AddrPortFrom(remote, 45001), ReserveUDPPort: reserve}
			rightPhysical := PCAPConfig{DeviceName: "right", LocalPort: 45001, Peer: netip.AddrPortFrom(local, 45000), ReserveUDPPort: reserve}
			leftOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, leftPhysical, local, left, leftPort)}
			rightOps := udpSetupOps{pcapSetupOps: ethernetSetup(t, rightPhysical, remote, right, rightPort), interfaceForIP: func(netip.Addr) (*net.Interface, error) {
				return &net.Interface{Name: "right", HardwareAddr: rightMAC, MTU: 1500}, nil
			}}
			client, err := newUDPConn(context.Background(), UDPConfig{DeviceName: "left", LocalPort: 45000, ReserveUDPPort: reserve, MagicHeader: magic}, leftPhysical.Peer, leftOps)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := newUDPConn(context.Background(), UDPConfig{DeviceName: "right", LocalIP: remote, LocalPort: 45001, ReserveUDPPort: reserve, MagicHeader: magic}, netip.AddrPort{}, rightOps)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			for _, size := range []int{0, 1, 1472 - len(magic)} {
				message := bytes.Repeat([]byte{byte(size)}, size)
				if n, err := client.Write(message); n != size || err != nil {
					t.Fatalf("write: %d %v", n, err)
				}
				buffer := make([]byte, 1500)
				n, addr, err := server.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], message) || addr.String() != "192.0.2.1:45000" {
					t.Fatalf("listener read: %d %v %v", n, addr, err)
				}
				if _, err := server.WriteTo(buffer[:n], addr); err != nil {
					t.Fatal(err)
				}
				n, err = client.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:n], message) {
					t.Fatalf("echo: %d %v", n, err)
				}
			}
			if err := client.Close(); err != nil {
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
