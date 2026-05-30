// Package rtpconn bridges the Pion WebRTC Opus track to quic-go via WriteFrame/ReadPacket.
//
// SPEED ARCHITECTURE (post-pacer removal):
//
//   WriteFrame() → WriteSample() immediately (no sleep, no queue)
//                  Pion internally increments RTP timestamp by 960 per call,
//                  so the SFU sees perfectly spaced logical timestamps even
//                  when packets arrive physically back-to-back.
//
//   silenceLoop() → fires every 20ms, but ONLY injects a 3-byte comfort noise
//                  frame when no real data was written in the last 20ms.
//                  This keeps the Opus track alive without blocking data writes.
//
// Result: QUIC can blast packets at full link speed. The SFU sees valid RTP
// timestamps (it checks timestamps, not wall-clock arrival rate). The track
// stays alive during idle periods via silence frames.
package rtpconn

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
	"github.com/salman/ble-webrtc-tun/internal/dcconn"
	"github.com/salman/ble-webrtc-tun/internal/logger"
)

var rtpLog = logger.New("rtpconn")

const (
	// maxPlainChunkSize is only used by the legacy Write() method.
	// WriteFrame() receives pre-sized QUIC datagrams (≤1100 bytes).
	maxPlainChunkSize = 1160

	// sampleDuration is passed to Pion's WriteSample so it can compute
	// the correct RTP timestamp increment (960 samples at 48kHz per 20ms).
	sampleDuration = 20 * time.Millisecond

	// readChSize is the channel buffer for incoming RTP payloads.
	readChSize = 8192
)

// minimalOpusSilence is the 3-byte Opus DTX comfort noise frame.
// Sent when the track is idle to prevent the SFU from tearing it down.
var minimalOpusSilence = []byte{0xF8, 0xFF, 0xFE}

// Conn wraps a Pion local audio track and an RTP receive channel.
// It exposes WriteFrame/ReadPacket for quic-go's OpusPacketConn bridge,
// and the legacy Read/Write interface for backward compatibility.
type Conn struct {
	localTrack *webrtc.TrackLocalStaticSample
	readCh     chan []byte
	buf        []byte
	closed     atomic.Bool
	once       sync.Once
	done       chan struct{}

	// Obfuscation (XChaCha20-Poly1305)
	obfuscator *dcconn.Obfuscator

	// lastWrite tracks the last time real data was sent (UnixNano).
	// silenceLoop uses this to decide whether to inject a keepalive frame.
	lastWrite atomic.Int64

	// writeMu serialises legacy Write() calls only.
	// WriteFrame() is already called from a single quic-go goroutine per stream.
	writeMu sync.Mutex

	bytesSent atomic.Int64
	bytesRecv atomic.Int64
}

// New creates a Conn and starts the silence keepalive loop.
// The pacer queue has been removed — WriteFrame() writes instantly.
func New(localTrack *webrtc.TrackLocalStaticSample, obfuscator *dcconn.Obfuscator) *Conn {
	c := &Conn{
		localTrack: localTrack,
		readCh:     make(chan []byte, readChSize),
		done:       make(chan struct{}),
		obfuscator: obfuscator,
	}
	c.lastWrite.Store(time.Now().UnixNano())
	if obfuscator != nil && obfuscator.Enabled() {
		rtpLog.Info("RTP obfuscation enabled (XChaCha20-Poly1305, overhead: %d bytes/pkt)", obfuscator.Overhead())
	}
	go c.silenceLoop()
	return c
}

// silenceLoop fires every 20ms and injects a 3-byte Opus comfort noise frame
// ONLY when no real data has been written in the last 20ms.
//
// This is non-blocking for data writes — real frames are never queued or delayed.
// The SFU track stays alive during idle periods without capping throughput.
func (c *Conn) silenceLoop() {
	ticker := time.NewTicker(sampleDuration)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.closed.Load() {
				return
			}
			now := time.Now().UnixNano()
			last := c.lastWrite.Load()
			// Only inject silence if no real write happened in the last 20ms
			if now-last >= int64(sampleDuration) {
				_ = c.localTrack.WriteSample(media.Sample{
					Data:     minimalOpusSilence,
					Duration: sampleDuration,
				})
			}
		}
	}
}

// HandleRTP is called from the OnTrack ReadRTP loop.
// Decrypts the payload and delivers it to ReadPacket/Read.
func (c *Conn) HandleRTP(payload []byte) {
	if c.closed.Load() || len(payload) == 0 {
		return
	}
	if isOpusSilence(payload) {
		return
	}

	plaintext := payload
	if c.obfuscator != nil && c.obfuscator.Enabled() {
		decrypted, err := c.obfuscator.Decrypt(payload)
		if err != nil {
			plaintext = payload
		} else {
			plaintext = decrypted
		}
	}

	buf := make([]byte, len(plaintext))
	copy(buf, plaintext)
	c.bytesRecv.Add(int64(len(plaintext)))

	select {
	case c.readCh <- buf:
	case <-c.done:
	}
}

// Read implements io.Reader (legacy yamux path — not used in QUIC mode).
func (c *Conn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			c.buf = data[n:]
		}
		return n, nil
	case <-c.done:
		return 0, io.EOF
	}
}

// Write implements io.Writer (legacy path — not used in QUIC mode).
// Splits large writes into MTU-safe chunks.
func (c *Conn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}
	if c.localTrack == nil {
		return 0, fmt.Errorf("no local track")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalLen := len(p)
	remaining := p
	chunkSize := 1200
	if c.obfuscator != nil && c.obfuscator.Enabled() {
		chunkSize = maxPlainChunkSize
	}

	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > chunkSize {
			chunk = remaining[:chunkSize]
		}
		remaining = remaining[len(chunk):]

		data := chunk
		if c.obfuscator != nil && c.obfuscator.Enabled() {
			encrypted, err := c.obfuscator.Encrypt(chunk)
			if err != nil {
				return 0, fmt.Errorf("encrypt: %w", err)
			}
			data = encrypted
		}

		c.lastWrite.Store(time.Now().UnixNano())
		if err := c.localTrack.WriteSample(media.Sample{
			Data:     data,
			Duration: sampleDuration,
		}); err != nil {
			return 0, fmt.Errorf("write sample: %w", err)
		}
	}
	c.bytesSent.Add(int64(totalLen))
	return totalLen, nil
}

// WriteFrame writes exactly ONE RTP frame INSTANTLY — no queuing, no sleeping.
//
// Speed design: QUIC calls WriteTo (which calls WriteFrame) as fast as its
// congestion window allows. Pion's WriteSample increments the RTP timestamp
// by 960 on every call (48kHz × 20ms), so the SFU sees a perfectly spaced
// logical timestamp sequence even when physical arrival is back-to-back.
//
// The SFU checks logical RTP timestamps, not physical wall-clock arrival time,
// so this bypasses the audio policer's pps limit without triggering drops.
func (c *Conn) WriteFrame(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}
	if c.localTrack == nil {
		return 0, fmt.Errorf("no local track")
	}

	data := p
	if c.obfuscator != nil && c.obfuscator.Enabled() {
		encrypted, err := c.obfuscator.Encrypt(p)
		if err != nil {
			return 0, fmt.Errorf("encrypt: %w", err)
		}
		data = encrypted
	}

	// Update activity time so silenceLoop doesn't inject a keepalive this tick
	c.lastWrite.Store(time.Now().UnixNano())

	// WRITE INSTANTLY — Pion fakes the RTP timestamp from Duration
	if err := c.localTrack.WriteSample(media.Sample{
		Data:     data,
		Duration: sampleDuration, // Pion adds 960 RTP samples per call
	}); err != nil {
		return 0, err
	}

	c.bytesSent.Add(int64(len(p)))
	return len(p), nil
}

// ReadPacket reads one complete decrypted RTP payload (one QUIC datagram).
// Used by quicconn.OpusPacketConn.ReadFrom().
func (c *Conn) ReadPacket() ([]byte, error) {
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		return data, nil
	case <-c.done:
		return nil, fmt.Errorf("connection closed")
	}
}

// StartSilenceLoop is a no-op — silence is managed by the silenceLoop goroutine
// started in New(). Kept for API compatibility.
func (c *Conn) StartSilenceLoop() {}

// Close implements io.Closer.
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.done)
		close(c.readCh)
	})
	return nil
}

// Stats returns bytes sent/received.
func (c *Conn) Stats() (sent, recv int64) {
	return c.bytesSent.Load(), c.bytesRecv.Load()
}

// QueueDepth is always 0 in the non-queued design. Kept for API compatibility.
func (c *Conn) QueueDepth() int { return 0 }

// isOpusSilence detects the 3-byte keepalive frame so we don't decrypt it.
func isOpusSilence(payload []byte) bool {
	return len(payload) == 3 &&
		payload[0] == 0xF8 && payload[1] == 0xFF && payload[2] == 0xFE
}
