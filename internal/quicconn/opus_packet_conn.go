// Package quicconn bridges quic-go to the rtpconn Opus audio track.
//
// Architecture:
//
//	QUIC (quic-go) ↔ OpusPacketConn ↔ rtpconn (20ms pacer) ↔ SFU Opus track
//
// quic-go needs a net.PacketConn (datagram interface). Since each write to
// rtpconn already queues one RTP frame in the 20ms pacer, and each HandleRTP
// delivers one complete payload, the mapping is direct:
//
//	WriteTo(datagram) → WriteFrame(datagram) → pacer → 1 RTP frame
//	ReadFrom()        ← ReadPacket()         ← 1 RTP payload
package quicconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/rtpconn"
)

// opusAddr is a fake net.Addr satisfying the net.PacketConn interface.
// Both sides of the QUIC connection use static fake addresses since the
// underlying transport is a point-to-point WebRTC channel.
type opusAddr struct{ name string }

func (a opusAddr) Network() string { return "opus" }
func (a opusAddr) String() string  { return a.name }

var (
	localOpusAddr  net.Addr = opusAddr{"opus://local:0"}
	remoteOpusAddr net.Addr = opusAddr{"opus://remote:0"}
)

// OpusPacketConn adapts rtpconn.Conn to net.PacketConn for quic-go.
// Each WriteTo call queues exactly one QUIC datagram into the 20ms pacer.
// Each ReadFrom call returns exactly one decoded RTP payload (one datagram).
type OpusPacketConn struct {
	conn   *rtpconn.Conn
	local  net.Addr
	remote net.Addr
}

// NewServer creates an OpusPacketConn for the server side of the QUIC connection.
func NewServer(conn *rtpconn.Conn) *OpusPacketConn {
	return &OpusPacketConn{conn: conn, local: localOpusAddr, remote: remoteOpusAddr}
}

// NewClient creates an OpusPacketConn for the client side of the QUIC connection.
func NewClient(conn *rtpconn.Conn) *OpusPacketConn {
	return &OpusPacketConn{conn: conn, local: localOpusAddr, remote: remoteOpusAddr}
}

// RemoteAddr returns the static fake remote address used for QUIC Dial().
func RemoteAddr() net.Addr { return remoteOpusAddr }

// ReadFrom reads one complete QUIC datagram from the Opus track.
// Blocks until a frame arrives. Implements net.PacketConn.
func (c *OpusPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, err := c.conn.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, pkt)
	return n, c.remote, nil
}

// WriteTo queues one QUIC datagram into the 20ms pacer.
// The addr parameter is ignored (point-to-point channel).
// Implements net.PacketConn.
func (c *OpusPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.conn.WriteFrame(p)
}

// Close closes the underlying rtpconn.
func (c *OpusPacketConn) Close() error { return c.conn.Close() }

// LocalAddr returns the fake local address.
func (c *OpusPacketConn) LocalAddr() net.Addr { return c.local }

// SetDeadline is a no-op — deadlines are managed by QUIC itself.
func (c *OpusPacketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (c *OpusPacketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (c *OpusPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// ─── TLS Helpers ──────────────────────────────────────────────────────────────

// ServerTLSConfig generates an ephemeral self-signed TLS certificate for
// the QUIC server. The client uses InsecureSkipVerify since we rely on
// XChaCha20-Poly1305 at the RTP layer for actual security.
func ServerTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bletun"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, fmt.Errorf("key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"bletun"},
	}, nil
}

// ClientTLSConfig returns a TLS config for the QUIC client.
// InsecureSkipVerify is safe here because the Opus track already provides
// XChaCha20-Poly1305 authenticated encryption. QUIC TLS is just for protocol
// compliance — it is not the primary security layer.
func ClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"bletun"},
	}
}
