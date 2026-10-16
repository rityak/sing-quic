package hysteria2

import (
	"bytes"
	"testing"

	"github.com/metacubex/sing/common/buf"
)

// T-079: the hand-written header round-trips and rejects cut messages.
func TestUDPMessagePackDecode(t *testing.T) {
	in := &udpMessage{sessionID: 0x01020304, packetID: 0x0506, fragmentID: 1, fragmentTotal: 3,
		destination: "example.com:443", data: buf.As([]byte("payload"))}
	packed := in.pack()
	defer packed.Release()
	if packed.Len() != in.headerSize()+len("payload") {
		t.Fatalf("packed %d bytes, header says %d", packed.Len(), in.headerSize()+len("payload"))
	}

	var out udpMessage
	if err := decodeUDPMessage(&out, packed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if out.sessionID != in.sessionID || out.packetID != in.packetID || out.fragmentID != in.fragmentID ||
		out.fragmentTotal != in.fragmentTotal || out.destination != in.destination || !bytes.Equal(out.data.Bytes(), []byte("payload")) {
		t.Fatalf("decoded %+v", out)
	}
	for cut := 0; cut < in.headerSize(); cut++ {
		if err := decodeUDPMessage(&out, packed.Bytes()[:cut]); err == nil {
			t.Fatalf("message cut to %d bytes decoded", cut)
		}
	}
	long := append([]byte{0, 0, 0, 1, 0, 1, 0, 1, 0x48, 0x01}, make([]byte, 0x801)...) // address of 2049 bytes
	if err := decodeUDPMessage(&out, long); err == nil {
		t.Fatal("address longer than MaxAddressLength decoded")
	}
}
