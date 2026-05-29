package soroush

import (
	"io"
	"sync"

	"github.com/pion/webrtc/v4"
)

// DataChannelConn wraps a WebRTC DataChannel to implement io.ReadWriteCloser.
// This allows stream-oriented protocols (like yamux) to multiplex over the
// message-oriented DataChannel.
type DataChannelConn struct {
	dc     *webrtc.DataChannel
	readCh chan []byte // incoming messages buffered here
	buf    []byte     // partial read buffer
	closed bool
	mu     sync.Mutex
}

// NewDataChannelConn creates a new DataChannelConn adapter.
// It registers an OnMessage handler on the DataChannel to buffer incoming data.
// IMPORTANT: Call this BEFORE any other OnMessage handler is set on the dc.
func NewDataChannelConn(dc *webrtc.DataChannel) *DataChannelConn {
	conn := &DataChannelConn{
		dc:     dc,
		readCh: make(chan []byte, 256), // buffer up to 256 messages
	}

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		conn.mu.Lock()
		if conn.closed {
			conn.mu.Unlock()
			return
		}
		conn.mu.Unlock()

		// Non-blocking send to channel
		select {
		case conn.readCh <- msg.Data:
		default:
			// Drop if buffer is full (backpressure)
		}
	})

	dc.OnClose(func() {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		close(conn.readCh)
	})

	return conn
}

// Read implements io.Reader. Blocks until data is available.
func (c *DataChannelConn) Read(p []byte) (int, error) {
	// First, drain any leftover bytes from a previous partial read
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Wait for next message
	data, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, data)
	if n < len(data) {
		// Store leftover for next Read
		c.buf = data[n:]
	}
	return n, nil
}

// Write implements io.Writer. Sends data as a DataChannel message.
func (c *DataChannelConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

	if err := c.dc.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements io.Closer.
func (c *DataChannelConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.dc.Close()
}
