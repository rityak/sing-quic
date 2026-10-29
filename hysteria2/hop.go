package hysteria2

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/randv2"
	"github.com/metacubex/sing/common/logger"
)

// refusedGrace: refusals this soon after moving back are the ICMP of packets
// still in flight to the refused port, not of the port moved to.
const refusedGrace = time.Second

// portHopper moves a connection between the server's ports: on the hop interval,
// and at once when the current port is refused, an ICMP port unreachable on the
// socket (miray T-158). quic-go closed the connection on the refusal, so one
// closed port of the range lost it. Now the connection moves back to the last
// port that worked, and the refused one is left out of later hops; only when
// that port refuses too is the server down and the connection closed, as a
// restart was told at once before (T-116).
type portHopper struct {
	ports  []uint16
	logger logger.Logger

	access       sync.Mutex
	conn         hopConn
	lastGood     uint16 // the port left by the last regular hop, or the handshake's
	graceUntil   time.Time
	refusedPorts map[uint16]struct{}
}

// hopConn is what the hopper moves: a *quic.Conn.
type hopConn interface {
	RemoteAddr() net.Addr
	SetRemoteAddr(net.Addr)
}

func newPortHopper(ports []uint16, logger logger.Logger) *portHopper {
	return &portHopper{ports: ports, logger: logger, refusedPorts: map[uint16]struct{}{}}
}

// attach starts hopping the connection once its handshake is done: a port refused
// during the handshake fails the dial, as without hopping.
func (h *portHopper) attach(conn hopConn) {
	h.access.Lock()
	defer h.access.Unlock()
	h.conn = conn
	h.lastGood, _ = h.port()
}

func (h *portHopper) port() (uint16, bool) {
	addr, ok := h.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return 0, false
	}
	return uint16(addr.Port), true
}

func (h *portHopper) moveTo(port uint16) net.Addr {
	current, ok := h.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return h.conn.RemoteAddr()
	}
	target := *current // only the port changes
	target.Port = int(port)
	h.conn.SetRemoteAddr(&target)
	return &target
}

// hop is the regular hop: the port left worked, the next is a random one not
// refused yet (all of them again once every other one was refused).
func (h *portHopper) hop() net.Addr {
	h.access.Lock()
	defer h.access.Unlock()
	if current, ok := h.port(); ok {
		h.lastGood = current
	}
	candidates := make([]uint16, 0, len(h.ports))
	for _, port := range h.ports {
		if _, bad := h.refusedPorts[port]; !bad {
			candidates = append(candidates, port)
		}
	}
	if len(candidates) == 0 {
		h.refusedPorts = map[uint16]struct{}{}
		candidates = h.ports
	}
	return h.moveTo(candidates[randv2.IntN(len(candidates))])
}

// refused is quic.Config.ConnectionRefused: the current port is closed.
func (h *portHopper) refused() bool {
	h.access.Lock()
	defer h.access.Unlock()
	if h.conn == nil {
		return false
	}
	now := time.Now()
	if now.Before(h.graceUntil) {
		return true
	}
	current, ok := h.port()
	if !ok || current == h.lastGood {
		return false // the port that worked refuses: the server is down
	}
	h.refusedPorts[current] = struct{}{}
	h.graceUntil = now.Add(refusedGrace)
	h.logger.Debug("Port refused, back to ", h.moveTo(h.lastGood))
	return true
}
