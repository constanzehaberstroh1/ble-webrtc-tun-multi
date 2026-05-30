package soroush

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

const (
	WsURI    = "wss://im-server.splus.ir/apiws"
	WsOrigin = "https://web.splus.ir"
	WsUA     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
)

// obfuscateTag selects the MTProto Intermediate framing protocol (0xee).
// 0xef = Abridged (does NOT work over WebSocket — wrong frame format)
// 0xee = Intermediate (correct for WebSocket tunneling)
var obfuscateTag = []byte{0xee, 0xee, 0xee, 0xee}

// forbidden start sequences that would be misinterpreted by Soroush's proxy
var forbidden = [][]byte{
	{0x50, 0x56, 0x72, 0x47},             // PVrG (client handshake replay)
	{0x47, 0x45, 0x54},                   // GET
	{0x50, 0x4f, 0x53, 0x54},             // POST
	{0xee, 0xee, 0xee, 0xee},             // Intermediate tag prefix (reserved)
	{0xef, 0xef, 0xef, 0xef},             // Abridged tag prefix (reserved)
}

// ObfuscatedTransport wraps a WebSocket connection with MTProto obfuscation.
type ObfuscatedTransport struct {
	ws      *websocket.Conn
	encrypt *AesCTRCipher
	decrypt *AesCTRCipher
	mu      sync.Mutex
}

func NewTransport() *ObfuscatedTransport {
	return &ObfuscatedTransport{}
}

// initHeader generates the 64-byte obfuscation header and initializes
// the AES-CTR encrypt/decrypt streams.
func (t *ObfuscatedTransport) initHeader() []byte {
	for {
		n := make([]byte, 64)
		rand.Read(n)

		// Reject any header whose first byte matches a known protocol identifier
		// or our own obfuscation tag (which lives at bytes 56-59, not 0-3).
		if n[0] == 0xEF || n[0] == 0xEE {
			continue
		}
		if n[4] == 0 && n[5] == 0 && n[6] == 0 && n[7] == 0 {
			continue
		}

		skip := false
		for _, f := range forbidden {
			match := true
			for j := 0; j < len(f); j++ {
				if n[j] != f[j] {
					match = false
					break
				}
			}
			if match {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// enc_key = n[8:40], enc_iv = n[40:56]
		encKey := make([]byte, 32)
		copy(encKey, n[8:40])
		encIV := make([]byte, 16)
		copy(encIV, n[40:56])

		// rev = n[8:56] reversed
		rev := make([]byte, 48)
		for i := 0; i < 48; i++ {
			rev[i] = n[8+47-i]
		}
		decKey := rev[0:32]
		decIV := rev[32:48]

		enc := NewAESCTR(encKey, encIV)
		dec := NewAESCTR(decKey, decIV)

		copy(n[56:60], obfuscateTag)

		encrypted := enc.Update(n)
		copy(n[56:64], encrypted[56:64])

		t.encrypt = NewAESCTR(encKey, encIV)
		t.encrypt.Update(make([]byte, 64)) // skip first 64 bytes
		t.decrypt = dec

		return n
	}
}

// Connect establishes a WebSocket connection to Soroush and performs the
// obfuscation handshake.
func (t *ObfuscatedTransport) Connect(ctx context.Context) error {
	log.Printf("[Transport] Connecting to Soroush WebSocket %s...", WsURI)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	opts := &websocket.DialOptions{
		// v1.mtproto signals the Soroush edge proxy to use WS-framed MTProto.
		// Without it the proxy may drop into raw TCP mode, corrupting framing.
		Subprotocols: []string{"binary", "v1.mtproto"},
		HTTPHeader: http.Header{
			"Origin":          {WsOrigin},
			"User-Agent":      {WsUA},
			"Accept-Language": {"fa-IR,fa;q=0.9,en;q=0.8"},
			"Cache-Control":   {"no-cache"},
			"Pragma":          {"no-cache"},
		},
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		// CRITICAL: disabling deflate prevents RSV1 being set on compressed frames.
		// When compression is active, Soroush's proxy sees RSV1=1 and treats it
		// as a raw TCP obfuscation byte, corrupting the entire stream.
		CompressionMode: websocket.CompressionDisabled,
	}

	ws, _, err := websocket.Dial(ctx, WsURI, opts)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	t.ws = ws

	// Set a large read limit for MTProto payloads
	t.ws.SetReadLimit(64 * 1024 * 1024)

	// Generate and send obfuscation header
	header := t.initHeader()

	err = t.ws.Write(ctx, websocket.MessageBinary, header)
	if err != nil {
		t.ws.Close(websocket.StatusNormalClosure, "")
		return fmt.Errorf("send obfuscation header: %w", err)
	}

	log.Println("[Transport] WebSocket connected and obfuscation initialized")
	return nil
}

// Disconnect closes the WebSocket connection.
func (t *ObfuscatedTransport) Disconnect() {
	if t.ws != nil {
		t.ws.Close(websocket.StatusNormalClosure, "goodbye")
		t.ws = nil
	}
}

// Send encrypts and sends a payload over the obfuscated WebSocket.
func (t *ObfuscatedTransport) Send(ctx context.Context, payload []byte) error {
	if len(payload)%4 != 0 {
		return fmt.Errorf("payload not multiple of 4: %d", len(payload))
	}

	n := len(payload) / 4
	var frame []byte
	if n < 0x7F {
		frame = make([]byte, 1+len(payload))
		frame[0] = byte(n)
		copy(frame[1:], payload)
	} else {
		frame = make([]byte, 4+len(payload))
		frame[0] = 0x7F
		frame[1] = byte(n & 0xFF)
		frame[2] = byte((n >> 8) & 0xFF)
		frame[3] = byte((n >> 16) & 0xFF)
		copy(frame[4:], payload)
	}

	encrypted := t.encrypt.Update(frame)

	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ws.Write(ctx, websocket.MessageBinary, encrypted)
}

// Recv reads and decrypts a payload from the obfuscated WebSocket.
func (t *ObfuscatedTransport) Recv(ctx context.Context) ([]byte, error) {
	_, raw, err := t.ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("websocket read: %w", err)
	}

	decrypted := t.decrypt.Update(raw)

	if len(decrypted) == 0 {
		return nil, fmt.Errorf("transport: received empty frame")
	}

	first := decrypted[0]
	var payload []byte
	if first == 0x7F {
		if len(decrypted) < 4 {
			return nil, fmt.Errorf("transport: long frame too short: %d", len(decrypted))
		}
		payload = decrypted[4:]
	} else {
		payload = decrypted[1:]
	}

	if len(payload) == 4 {
		code := int32(binary.LittleEndian.Uint32(payload))
		return nil, fmt.Errorf("transport error code: %d", code)
	}

	return payload, nil
}
