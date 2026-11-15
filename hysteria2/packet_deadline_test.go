package hysteria2

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
)

func TestUDPPacketWriteDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ln, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := quic.DialAddr(ctx, ln.Addr().String(), testTLSConfig(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "")
	peer, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseWithError(0, "")
	pc := newUDPPacketConn(ctx, c, func() {}, 1200)
	defer pc.Close()
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if err := pc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("expired"), address); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	for _, deadline := range []time.Time{time.Now().Add(time.Second), {}} {
		if err := pc.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo([]byte("live"), address); err != nil {
			t.Fatal(err)
		}
		packet, err := peer.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var decoded udpMessage
		if err := decodeUDPMessage(&decoded, packet); err != nil || string(decoded.data.Bytes()) != "live" {
			t.Fatalf("datagram=%q err=%v", packet, err)
		}
		decoded.releaseMessage()
	}
	pc.Close()
	if _, err := pc.WriteTo([]byte("closed"), address); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
