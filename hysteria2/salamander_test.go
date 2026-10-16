package hysteria2

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// recordConn keeps the last datagram written and hands it back on read.
type recordConn struct {
	net.PacketConn
	last []byte
}

func (c *recordConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.last = append([]byte(nil), p...)
	return len(p), nil
}

func (c *recordConn) ReadFrom(p []byte) (int, net.Addr, error) { return copy(p, c.last), nil, nil }

// the original byte loop, the reference for the wire format
func salamanderReference(password, salt, data []byte) []byte {
	key := blake2b.Sum256(append(append([]byte(nil), password...), salt...))
	out := make([]byte, len(data))
	for i, c := range data {
		out[i] = c ^ key[i%blake2b.Size256]
	}
	return out
}

// T-086: the vectorized XOR and the stack key give the same bytes as before.
func TestSalamanderWireFormat(t *testing.T) {
	for _, password := range [][]byte{[]byte("short"), bytes.Repeat([]byte("p"), 60)} { // 60+8 > 64: heap path
		for _, size := range []int{1, 31, 32, 33, 1200, 1452} {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i * 7)
			}
			rc := &recordConn{}
			conn := NewSalamanderConn(rc, password)
			if _, err := conn.WriteTo(payload, nil); err != nil {
				t.Fatal(err)
			}
			wire := rc.last
			if len(wire) != size+salamanderSaltLen {
				t.Fatalf("wire %d bytes for %d", len(wire), size)
			}
			if !bytes.Equal(salamanderReference(password, wire[:salamanderSaltLen], wire[salamanderSaltLen:]), payload) {
				t.Fatalf("password %d bytes, payload %d: the reference does not decode what was written", len(password), size)
			}
			// and the other way: what the reference writes reads back
			rc.last = append(append([]byte(nil), wire[:salamanderSaltLen]...), salamanderReference(password, wire[:salamanderSaltLen], payload)...)
			buf := make([]byte, 2048)
			n, _, err := conn.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("password %d bytes, payload %d: read %d bytes, err %v", len(password), size, n, err)
			}
		}
	}
}
