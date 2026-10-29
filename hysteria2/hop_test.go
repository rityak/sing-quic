package hysteria2

import (
	"net"
	"sync"
	"testing"

	"github.com/metacubex/sing/common/logger"
)

type fakeHopConn struct {
	mu   sync.Mutex
	addr net.Addr
}

func (c *fakeHopConn) RemoteAddr() net.Addr { c.mu.Lock(); defer c.mu.Unlock(); return c.addr }
func (c *fakeHopConn) SetRemoteAddr(a net.Addr) {
	c.mu.Lock()
	c.addr = a
	c.mu.Unlock()
}
func (c *fakeHopConn) port() uint16 { return uint16(c.RemoteAddr().(*net.UDPAddr).Port) }

// A refused port moves the connection to a port not refused yet and keeps it;
// when every port was refused since the last regular hop it closes; during the
// handshake a refusal closes, as without hopping (miray T-158).
func TestPortHopperRefused(t *testing.T) {
	ports := []uint16{20000, 20001, 20002}
	h := newPortHopper(ports, logger.NOP())
	if h.refused() {
		t.Fatal("kept a connection refused during its handshake")
	}
	conn := &fakeHopConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20000}}
	h.attach(conn)
	seen := map[uint16]bool{20000: true}
	for i := 0; i < len(ports)-1; i++ {
		if !h.refused() {
			t.Fatalf("refusal %d closed the connection with ports left", i+1)
		}
		if seen[conn.port()] {
			t.Fatalf("hopped to %d, refused already", conn.port())
		}
		seen[conn.port()] = true
		if ip := conn.RemoteAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(192, 0, 2, 1)) {
			t.Fatalf("the address changed: %v", ip)
		}
	}
	if h.refused() {
		t.Fatal("kept the connection with every port refused")
	}
	h.hop(true) // a regular hop forgets the refusals
	if !h.refused() {
		t.Fatal("a refusal after a regular hop closed the connection")
	}
}
