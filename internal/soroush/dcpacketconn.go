// Package soroush — DCPacketConn bridges a WebRTC DataChannel to net.PacketConn.
//
// Architecture:
//
//	QUIC (quic-go) ↔ DCPacketConn ↔ webrtc.DataChannel ↔ Soroush P2P
//
// A WebRTC DataChannel is already message-oriented under the hood (each dc.Send()
// delivers one atomic binary message). This makes the mapping trivial:
//
//	WriteTo(datagram) → dc.Send(datagram) → 1 DataChannel message
//	ReadFrom()        ← OnMessage()       ← 1 DataChannel message
//
// This is the Soroush equivalent of quicconn.OpusPacketConn for Bale.
package soroush

import (
	"net"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// dcAddr is a fake net.Addr for the point-to-point DataChannel link.
type dcAddr struct{ name string }

func (a dcAddr) Network() string { return "soroush-dc" }
func (a dcAddr) String() string  { return a.name }

var (
	localDCAddr  net.Addr = dcAddr{"soroush://local:0"}
	remoteDCAddr net.Addr = dcAddr{"soroush://remote:0"}
)

// DCPacketConn adapts a *webrtc.DataChannel to net.PacketConn for quic-go.
//
// Each dc.Send() maps to exactly one QUIC datagram (WriteTo).
// Each OnMessage callback delivers exactly one QUIC datagram (ReadFrom).
//
// The DataChannel MUST be open before wrapping — call this inside dc.OnOpen().
type DCPacketConn struct {
	dc     *webrtc.DataChannel
	recvCh chan []byte
	closed bool
	mu     sync.Mutex
	done   chan struct{}
}

// NewDCPacketConn wraps an open DataChannel as a net.PacketConn.
// It replaces any existing OnMessage/OnClose handlers on dc.
func NewDCPacketConn(dc *webrtc.DataChannel) *DCPacketConn {
	c := &DCPacketConn{
		dc:     dc,
		recvCh: make(chan []byte, 512), // 512-datagram buffer — QUIC bursts during handshake
		done:   make(chan struct{}),
	}

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			// Copy message bytes — pion reuses the underlying buffer
			pkt := make([]byte, len(msg.Data))
			copy(pkt, msg.Data)
			select {
			case c.recvCh <- pkt:
			default:
				// Drop if buffer is full — QUIC handles loss internally
			}
		}
	})

	dc.OnClose(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed {
			c.closed = true
			close(c.done)
		}
	})

	return c
}

// RemoteDCAddr returns the static fake remote address for quic.Dial().
func RemoteDCAddr() net.Addr { return remoteDCAddr }

// ReadFrom blocks until one QUIC datagram arrives from the DataChannel.
// Implements net.PacketConn.
func (c *DCPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-c.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt)
		return n, remoteDCAddr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo sends one QUIC datagram over the DataChannel.
// The addr parameter is ignored (point-to-point link).
// Implements net.PacketConn.
func (c *DCPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	// Copy before Send — pion may reference the slice asynchronously
	pkt := make([]byte, len(p))
	copy(pkt, p)
	if err := c.dc.Send(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying DataChannel and unblocks any ReadFrom.
// Implements net.PacketConn.
func (c *DCPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	return c.dc.Close()
}

// LocalAddr returns the fake local address.
func (c *DCPacketConn) LocalAddr() net.Addr { return localDCAddr }

// SetDeadline is a no-op — deadlines are managed by quic-go internally.
func (c *DCPacketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (c *DCPacketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (c *DCPacketConn) SetWriteDeadline(t time.Time) error { return nil }
