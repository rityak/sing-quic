package hysteria2

import (
	"net"
	"sync"

	"github.com/metacubex/randv2"
	"github.com/metacubex/sing/common/logger"
)

// portHopper moves a connection between the server's ports: on the hop interval,
// and at once when the current port is refused, an ICMP port unreachable on the
// socket (miray T-158). One closed port of the range then costs a round trip,
// not the connection, which quic-go closed on the refusal; only when every port
// was refused since the last regular hop (the server is down) does it close.
type portHopper struct {
	ports    []uint16
	distinct int
	logger   logger.Logger

	access       sync.Mutex
	conn         hopConn
	refusedPorts map[uint16]struct{}
}

// hopConn is what the hopper moves: a *quic.Conn.
type hopConn interface {
	RemoteAddr() net.Addr
	SetRemoteAddr(net.Addr)
}

func newPortHopper(ports []uint16, logger logger.Logger) *portHopper {
	set := map[uint16]struct{}{}
	for _, port := range ports {
		set[port] = struct{}{}
	}
	return &portHopper{ports: ports, distinct: len(set), logger: logger, refusedPorts: map[uint16]struct{}{}}
}

// attach starts hopping the connection once its handshake is done: a port refused
// during the handshake fails the dial, as without hopping.
func (h *portHopper) attach(conn hopConn) {
	h.access.Lock()
	h.conn = conn
	h.access.Unlock()
}

// hop moves to a random port; a regular hop (fresh) forgets the refused ports.
func (h *portHopper) hop(fresh bool) net.Addr {
	h.access.Lock()
	defer h.access.Unlock()
	if fresh {
		h.refusedPorts = map[uint16]struct{}{}
	}
	return h.hopLocked()
}

func (h *portHopper) hopLocked() net.Addr {
	current, ok := h.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return h.conn.RemoteAddr()
	}
	candidates := make([]uint16, 0, len(h.ports))
	for _, port := range h.ports {
		if _, bad := h.refusedPorts[port]; !bad {
			candidates = append(candidates, port)
		}
	}
	if len(candidates) == 0 {
		return current
	}
	target := *current // only the port changes
	target.Port = int(candidates[randv2.IntN(len(candidates))])
	h.conn.SetRemoteAddr(&target)
	return &target
}

// refused is quic.Config.ConnectionRefused: the current port is closed.
func (h *portHopper) refused() bool {
	h.access.Lock()
	defer h.access.Unlock()
	if h.conn == nil {
		return false
	}
	if current, ok := h.conn.RemoteAddr().(*net.UDPAddr); ok {
		h.refusedPorts[uint16(current.Port)] = struct{}{}
	}
	if len(h.refusedPorts) >= h.distinct {
		return false // every port refused: the server is down, as T-116 tells at once
	}
	h.logger.Debug("Port refused, hopped to ", h.hopLocked())
	return true
}
