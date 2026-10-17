//go:build !linux

package hysteria2

import "net"

// GSO and GRO through Salamander are Linux only (miray T-087).
func newSalamanderOOB(*SalamanderPacketConn) net.PacketConn { return nil }
