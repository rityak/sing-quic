//go:build linux

package hysteria2

import (
	"bytes"
	"net"
	"testing"
	"unsafe"

	"github.com/metacubex/quic-go"
	"golang.org/x/sys/unix"
)

type capturedConn struct {
	quic.OOBCapablePacketConn
	b, oob []byte
}

func (c *capturedConn) WriteMsgUDP(b, oob []byte, _ *net.UDPAddr) (int, int, error) {
	c.b, c.oob = append([]byte(nil), b...), append([]byte(nil), oob...)
	return len(b), len(oob), nil
}

func sizeCmsg(typ int32, size int, n int) []byte {
	b := make([]byte, unix.CmsgSpace(n))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.SOL_UDP, typ
	h.SetLen(unix.CmsgLen(n))
	if n == 2 {
		*(*uint16)(unsafe.Pointer(&b[unix.CmsgSpace(0)])) = uint16(size)
	} else {
		*(*int32)(unsafe.Pointer(&b[unix.CmsgSpace(0)])) = int32(size)
	}
	return b
}

// T-087: a GSO run written through Salamander has a salt per segment and the
// segment size moved by it; the same bytes received as a GRO run reveal back.
func TestSalamanderGSORoundTrip(t *testing.T) {
	data := make([]byte, 3*1000+500)
	for i := range data {
		data[i] = byte(i)
	}
	cc := &capturedConn{}
	c := &salamanderOOBConn{SalamanderPacketConn: &SalamanderPacketConn{PacketConn: cc, password: []byte("pw")}, oob: cc}
	oob := sizeCmsg(unix.UDP_SEGMENT, 1000, 2)
	if _, _, err := c.WriteMsgUDP(data, oob, nil); err != nil {
		t.Fatal(err)
	}
	if len(cc.b) != len(data)+4*salamanderSaltLen {
		t.Fatalf("wire %d bytes, want %d", len(cc.b), len(data)+4*salamanderSaltLen)
	}
	if got := *(*uint16)(unsafe.Pointer(&cmsgBody(cc.oob, unix.SOL_UDP, unix.UDP_SEGMENT)[0])); got != 1000+salamanderSaltLen {
		t.Fatalf("segment size on the wire %d", got)
	}
	if *(*uint16)(unsafe.Pointer(&cmsgBody(oob, unix.SOL_UDP, unix.UDP_SEGMENT)[0])) != 1000 {
		t.Fatal("the caller's control message was changed")
	}
	// every segment is a plain Salamander datagram
	plain := NewSalamanderConn(&recordConn{last: cc.b[:1000+salamanderSaltLen]}, []byte("pw"))
	buf := make([]byte, 2048)
	if n, _, _ := plain.(interface {
		ReadFrom([]byte) (int, net.Addr, error)
	}).ReadFrom(buf); !bytes.Equal(buf[:n], data[:1000]) {
		t.Fatal("first segment is not a Salamander datagram")
	}

	gro := sizeCmsg(unix.UDP_GRO, 1000+salamanderSaltLen, 4)
	in := append([]byte(nil), cc.b...)
	n := c.reveal(in, gro)
	if !bytes.Equal(in[:n], data) {
		t.Fatalf("revealed %d bytes, not the %d written", n, len(data))
	}
	if got := *(*int32)(unsafe.Pointer(&cmsgBody(gro, unix.SOL_UDP, unix.UDP_GRO)[0])); got != 1000 {
		t.Fatalf("GRO size after reveal %d", got)
	}
}
