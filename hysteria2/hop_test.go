package hysteria2

import (
	"net"
	"sync"
	"testing"
	"time"

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

// A closed port of the range moves the connection back to the port that worked
// and is left out of later hops; a refusal of the port that worked closes it, as
// a restarted server; during the handshake a refusal closes, as without hopping
// (miray T-158).
func TestPortHopperRefused(t *testing.T) {
	h := newPortHopper([]uint16{20000, 20001}, logger.NOP())
	if h.refused() {
		t.Fatal("kept a connection refused during its handshake")
	}
	conn := &fakeHopConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20000}}
	h.attach(conn)
	h.moveTo(20001) // a regular hop landed on the closed port
	h.lastGood = 20000
	if !h.refused() || conn.port() != 20000 {
		t.Fatalf("refused closed port: kept the connection on %d, want back on 20000", conn.port())
	}
	if !h.refused() {
		t.Fatal("an ICMP still in flight from the closed port closed the connection")
	}
	for i := 0; i < 20; i++ {
		if h.hop(); conn.port() != 20000 {
			t.Fatalf("a regular hop went to the refused port %d", conn.port())
		}
	}
	h.graceUntil = time.Time{}
	if h.refused() {
		t.Fatal("the port that worked refuses, the connection was kept")
	}
	if ip := conn.RemoteAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("the address changed: %v", ip)
	}
}

// Once every other port was refused, regular hops use them all again.
func TestPortHopperForgets(t *testing.T) {
	h := newPortHopper([]uint16{20000, 20001}, logger.NOP())
	conn := &fakeHopConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20000}}
	h.attach(conn)
	h.refusedPorts[20000], h.refusedPorts[20001] = struct{}{}, struct{}{}
	h.hop()
	if len(h.refusedPorts) != 0 {
		t.Fatalf("refused ports kept: %v", h.refusedPorts)
	}
}
