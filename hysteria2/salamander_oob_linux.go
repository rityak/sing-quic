//go:build linux

package hysteria2

import (
	"crypto/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/metacubex/quic-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// salamanderOOBConn keeps quic-go on its fast path under Salamander (miray T-087):
// quic-go sees the real socket (SyscallConn), so GSO, batch reads and GRO stay
// on; every GSO or GRO segment gets its own salt, and the segment size in the
// control message is moved by the salt length.
type salamanderOOBConn struct {
	*SalamanderPacketConn
	oob   quic.OOBCapablePacketConn
	batch *ipv4.PacketConn
}

func newSalamanderOOB(s *SalamanderPacketConn) net.PacketConn {
	c, ok := s.PacketConn.(quic.OOBCapablePacketConn)
	if !ok || os.Getenv("MIRAY_SALAMANDER_OOB") == "off" {
		return nil
	}
	return &salamanderOOBConn{SalamanderPacketConn: s, oob: c, batch: ipv4.NewPacketConn(c)}
}

func (c *salamanderOOBConn) SyscallConn() (syscall.RawConn, error) { return c.oob.SyscallConn() }
func (c *salamanderOOBConn) SetReadBuffer(n int) error              { return c.oob.SetReadBuffer(n) }

var salamanderGSOBuffers = sync.Pool{New: func() any { return new([]byte) }}

func (c *salamanderOOBConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	size := len(b)
	var cmsg [64]byte
	var segment []byte
	if len(oob) > 0 && len(oob) <= len(cmsg) {
		oob = cmsg[:copy(cmsg[:], oob)] // the size is rewritten below, the caller's buffer stays as is
		segment = cmsgBody(oob, unix.SOL_UDP, unix.UDP_SEGMENT)
		if len(segment) >= 2 {
			if s := int(*(*uint16)(unsafe.Pointer(&segment[0]))); s > 0 {
				size = s
			}
		}
	}
	if size <= 0 {
		size = len(b)
	}
	count := (len(b) + size - 1) / size
	bp := salamanderGSOBuffers.Get().(*[]byte)
	defer salamanderGSOBuffers.Put(bp)
	need := len(b) + (count+1)*salamanderSaltLen
	if cap(*bp) < need {
		*bp = make([]byte, need)
	}
	buf := (*bp)[:need]
	salts := buf[len(buf)-count*salamanderSaltLen:]
	if _, err = rand.Read(salts); err != nil {
		return
	}
	out := 0
	for off := 0; off < len(b); off += size {
		end := off + size
		if end > len(b) {
			end = len(b)
		}
		salt := salts[:salamanderSaltLen]
		salts = salts[salamanderSaltLen:]
		out += copy(buf[out:], salt)
		key := c.key(salt)
		xorKey(buf[out:out+end-off], b[off:end], &key)
		out += end - off
	}
	if len(segment) >= 2 {
		*(*uint16)(unsafe.Pointer(&segment[0])) = uint16(size + salamanderSaltLen)
	}
	_, oobn, err = c.oob.WriteMsgUDP(buf[:out], oob, addr)
	if err != nil {
		return 0, oobn, err
	}
	return len(b), oobn, nil
}

func (c *salamanderOOBConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.oob.ReadMsgUDP(b, oob)
	if err == nil {
		n = c.reveal(b[:n], oob[:oobn])
	}
	return
}

// ReadBatch is quic-go's batch read (recvmmsg), with every datagram revealed in place.
func (c *salamanderOOBConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := c.batch.ReadBatch(ms, flags)
	for i := 0; i < n; i++ {
		ms[i].N = c.reveal(ms[i].Buffers[0][:ms[i].N], ms[i].OOB[:ms[i].NN])
	}
	return n, err
}

// reveal removes the salt and the XOR from every segment of data (one, or a GRO
// run of equal ones with a shorter last) and moves them together; the GRO size
// in oob is rewritten. It returns the new length.
func (c *salamanderOOBConn) reveal(data, oob []byte) int {
	size := len(data)
	gro := cmsgBody(oob, unix.SOL_UDP, unix.UDP_GRO)
	if len(gro) >= 4 {
		if s := int(*(*int32)(unsafe.Pointer(&gro[0]))); s > 0 {
			size = s
		}
	}
	if size <= salamanderSaltLen {
		return 0
	}
	out := 0
	for off := 0; off < len(data); off += size {
		end := off + size
		if end > len(data) {
			end = len(data)
		}
		if end-off <= salamanderSaltLen {
			continue
		}
		key := c.key(data[off : off+salamanderSaltLen])
		payload := data[off+salamanderSaltLen : end]
		xorKey(payload, payload, &key)
		out += copy(data[out:], payload)
	}
	if len(gro) >= 4 {
		*(*int32)(unsafe.Pointer(&gro[0])) = int32(size - salamanderSaltLen)
	}
	return out
}

// cmsgBody finds the data of a control message, as a slice into oob.
func cmsgBody(oob []byte, level, typ int32) []byte {
	for len(oob) > 0 {
		hdr, body, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return nil
		}
		if hdr.Level == level && hdr.Type == typ {
			return body
		}
		oob = rest
	}
	return nil
}
