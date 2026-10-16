package hysteria2

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slices"
)

const salamanderSaltLen = 8

const ObfsTypeSalamander = "salamander"

type SalamanderPacketConn struct {
	net.PacketConn
	password []byte
}

func NewSalamanderConn(conn net.PacketConn, password []byte) net.PacketConn {
	return &SalamanderPacketConn{
		PacketConn: conn,
		password:   slices.Clip(password),
	}
}

// key is blake2b-256(password || salt); a usual password needs no heap copy (miray T-086).
func (s *SalamanderPacketConn) key(salt []byte) [blake2b.Size256]byte {
	var b [64]byte
	if len(s.password)+len(salt) > len(b) {
		return blake2b.Sum256(append(s.password, salt...))
	}
	n := copy(b[:], s.password)
	n += copy(b[n:], salt)
	return blake2b.Sum256(b[:n])
}

// xorKey sets dst to src XOR the key repeated, a key length at a time (vectorized,
// instead of a byte loop with a modulo). dst and src overlap exactly or not at all.
func xorKey(dst, src []byte, key *[blake2b.Size256]byte) {
	for len(src) > 0 {
		n := subtle.XORBytes(dst, src, key[:])
		dst, src = dst[n:], src[n:]
	}
}

func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return
	}
	key := s.key(p[:salamanderSaltLen])
	data := p[salamanderSaltLen:n]
	xorKey(data, data, &key)
	return copy(p, data), addr, nil
}

var salamanderBuffers = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	bp := salamanderBuffers.Get().(*[]byte)
	defer salamanderBuffers.Put(bp)
	b := *bp
	if size := len(p) + salamanderSaltLen; cap(b) >= size {
		b = b[:size]
	} else {
		b = make([]byte, size)
	}
	if _, err = rand.Read(b[:salamanderSaltLen]); err != nil {
		return
	}
	key := s.key(b[:salamanderSaltLen])
	xorKey(b[salamanderSaltLen:], p, &key)
	if _, err = s.PacketConn.WriteTo(b, addr); err != nil {
		return
	}
	return len(p), nil
}
