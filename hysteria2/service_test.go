package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func testTLSConfig(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos: []string{"h3"}, ServerName: "test", InsecureSkipVerify: true}
}

// A client that sends its upload with FIN and stops reading before the response (STOP_SENDING, as
// sing-box's client does on Close) still has its upload forwarded: the response write fails, but
// HandshakeSuccess must not report it, or the relay drops the data (the protocol's own server ignores it).
func TestServerConnHandshakeSuccessAfterStopSending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(t), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := quic.DialAddr(ctx, ln.Addr().String(), testTLSConfig(t), &quic.Config{})
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return
		}
		_, _ = stream.Write([]byte("upload"))
		stream.CancelRead(0)
		_ = stream.Close()
		<-ctx.Done()
	}()
	conn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "upload" {
		t.Fatalf("upload: %q, %v", data, err)
	}
	select { // the write side ends when STOP_SENDING arrives
	case <-stream.Context().Done():
	case <-ctx.Done():
		t.Fatal("no STOP_SENDING")
	}
	if err := (&serverConn{Stream: stream}).HandshakeSuccess(); err != nil {
		t.Fatalf("HandshakeSuccess after STOP_SENDING: %v", err)
	}
}
