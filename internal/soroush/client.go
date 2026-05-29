package soroush

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/provider"
)

// SoroushClientAdapter wraps the Soroush MTProto session to satisfy provider.Client
type SoroushClientAdapter struct {
	authKey      []byte
	authKeyID    []byte
	serverSalt   []byte
	userID       int64
	accessHash   int64
	session      *MTProtoSession
	transport    *ObfuscatedTransport
	callCh       chan *provider.IncomingCall
	textCh       chan string
	ctx          context.Context
	cancel       context.CancelFunc
	pingStopCh   chan struct{}
	connected    bool
	mu           sync.Mutex

	activeCallsMu      sync.RWMutex
	activeCallAccesses map[int64]int64 // maps callID -> accessHash
}

func NewSoroushClientAdapter(authKey, authKeyID, serverSalt []byte, userID, accessHash int64) *SoroushClientAdapter {
	return &SoroushClientAdapter{
		authKey:            authKey,
		authKeyID:          authKeyID,
		serverSalt:         serverSalt,
		userID:             userID,
		accessHash:         accessHash,
		callCh:             make(chan *provider.IncomingCall, 32),
		textCh:             make(chan string, 128),
		pingStopCh:         make(chan struct{}),
		activeCallAccesses: make(map[int64]int64),
	}
}

// Connect implements provider.Client
func (c *SoroushClientAdapter) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())

	// Restore Soroush session
	session, transport := RestoreSession(c.authKey, c.authKeyID, c.serverSalt)
	c.session = session
	c.transport = transport

	// Set connection-specific timeout for transport connection
	connCtx, connCancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer connCancel()

	if err := c.transport.Connect(connCtx); err != nil {
		return fmt.Errorf("transport connect: %w", err)
	}

	// Warm up session to fetch the correct salt and verify connection
	warmCtx, warmCancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer warmCancel()
	if err := c.session.WarmUpSession(warmCtx); err != nil {
		c.transport.Disconnect()
		return fmt.Errorf("session warm up failed: %w", err)
	}

	c.connected = true

	// Send initial ping to keepalive
	pingBody := BuildPingDelayDisconnectRequest(time.Now().UnixNano(), 75)
	c.session.Send(c.ctx, pingBody, true)

	// Start reading loops
	go c.runMessageReader()

	return nil
}

// Close implements provider.Client
func (c *SoroushClientAdapter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	if c.cancel != nil {
		c.cancel()
	}

	close(c.pingStopCh)

	if c.transport != nil {
		c.transport.Disconnect()
	}

	c.connected = false
	return nil
}

// GetCallCh implements provider.Client
func (c *SoroushClientAdapter) GetCallCh() <-chan *provider.IncomingCall {
	return c.callCh
}

// AcceptCall implements provider.Client
func (c *SoroushClientAdapter) AcceptCall(callID int64, expectedVideo bool) error {
	c.activeCallsMu.RLock()
	accessHash, ok := c.activeCallAccesses[callID]
	c.activeCallsMu.RUnlock()

	if !ok {
		return fmt.Errorf("call %d access hash not found", callID)
	}

	gB := make([]byte, 256)
	_, _ = rand.Read(gB)

	acceptBody := BuildPhoneAcceptCall(callID, accessHash, gB)
	acceptCtx, acceptCancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer acceptCancel()

	_, err := c.session.Send(acceptCtx, acceptBody, true)
	if err != nil {
		return fmt.Errorf("accept call signaling failed: %w", err)
	}

	return nil
}

// ReceiveCall implements provider.Client
func (c *SoroushClientAdapter) ReceiveCall(callID int64) error {
	c.activeCallsMu.RLock()
	accessHash, ok := c.activeCallAccesses[callID]
	c.activeCallsMu.RUnlock()

	if !ok {
		return fmt.Errorf("call %d access hash not found", callID)
	}

	recvBody := BuildPhoneReceivedCall(callID, accessHash)
	recvCtx, recvCancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer recvCancel()

	_, err := c.session.Send(recvCtx, recvBody, true)
	if err != nil {
		return fmt.Errorf("receive call ack failed: %w", err)
	}

	return nil
}

// GetWssURL implements provider.Client (LiveKit specific, unused in Soroush)
func (c *SoroushClientAdapter) GetWssURL(callID int64) error {
	return nil
}

// WaitForAccept implements provider.Client
func (c *SoroushClientAdapter) WaitForAccept(timeout time.Duration) (*provider.CallAcceptResult, error) {
	// For Soroush, wait for confirmed (active call) or accepted updates on transport
	// However, TURN server addresses can be returned dynamically or from default list.
	// Since domestic Iranian TURN servers are constant and highly reliable, we can
	// return them directly to ensure instant connectivity!
	conns := make([]provider.ICEConnectionInfo, 0)
	for _, srv := range SoroushTURNServers {
		for _, url := range srv.URLs {
			conns = append(conns, provider.ICEConnectionInfo{
				URL:      url,
				Username: srv.Username,
				Password: srv.Credential,
				IsTurn:   strings.HasPrefix(url, "turn:"),
			})
		}
	}

	return &provider.CallAcceptResult{
		Connections: conns,
	}, nil
}

// DiscardCall implements provider.Client
func (c *SoroushClientAdapter) DiscardCall(callID int64) error {
	c.activeCallsMu.RLock()
	accessHash, ok := c.activeCallAccesses[callID]
	c.activeCallsMu.RUnlock()

	if !ok {
		return fmt.Errorf("call %d access hash not found", callID)
	}

	discardBody := BuildPhoneDiscardCall(callID, accessHash, 10)
	discardCtx, discardCancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer discardCancel()

	_, err := c.session.Send(discardCtx, discardBody, true)
	if err != nil {
		return fmt.Errorf("discard call failed: %w", err)
	}

	return nil
}

// InitiateCall implements provider.Client (client side outgoing calls)
func (c *SoroushClientAdapter) InitiateCall(ctx context.Context, targetUserID int64, targetAccessHash int64) (*provider.CallAcceptResult, error) {
	gAHash := make([]byte, 32)
	_, _ = rand.Read(gAHash)

	randomID := rand.Int31()

	callBody := BuildPhoneRequestCall(targetUserID, targetAccessHash, randomID, gAHash)
	callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
	defer callCancel()

	// Wait for call acceptance or confirmation
	callRecvCh := make(chan error, 1)
	var acceptedEvent *CallEvent

	go func() {
		for {
			select {
			case <-callCtx.Done():
				callRecvCh <- callCtx.Err()
				return
			default:
			}

			cid, reader, err := c.session.Recv(callCtx)
			if err != nil {
				callRecvCh <- err
				return
			}

			// Parse call updates
			innerCID := cid
			innerReader := reader
			if cid == IDMsgContainer {
				count, _ := reader.ReadInt32()
				for i := int32(0); i < count; i++ {
					reader.ReadInt64() // msg_id
					reader.ReadInt32() // seq_no
					bodyLen, _ := reader.ReadInt32()
					body, err := reader.ReadRaw(int(bodyLen))
					if err == nil {
						subReader := NewTLReader(body)
						subCID, _ := subReader.ReadUint32()
						if subCID == IDUpdatePhoneCall {
							innerCID = subCID
							innerReader = subReader
							break
						}
					}
				}
			}

			if innerCID == IDUpdatePhoneCall {
				event, err := ParseCallUpdate(innerReader)
				if err == nil && event != nil {
					if event.Type == "accepted" || event.Type == "confirmed" {
						acceptedEvent = event
						callRecvCh <- nil
						return
					}
				}
			}
		}
	}()

	// Send request call
	_, err := c.session.Send(callCtx, callBody, true)
	if err != nil {
		return nil, fmt.Errorf("send requestCall failed: %w", err)
	}

	err = <-callRecvCh
	if err != nil {
		return nil, fmt.Errorf("waiting for call acceptance failed: %w", err)
	}

	// Prepare results
	conns := make([]provider.ICEConnectionInfo, 0)
	if acceptedEvent != nil && len(acceptedEvent.Connections) > 0 {
		for _, conn := range acceptedEvent.Connections {
			turnURL := fmt.Sprintf("turn:%s:%d", conn.IP, conn.Port)
			if conn.Stun {
				turnURL = fmt.Sprintf("stun:%s:%d", conn.IP, conn.Port)
			}
			conns = append(conns, provider.ICEConnectionInfo{
				URL:      turnURL,
				Username: conn.Username,
				Password: conn.Password,
				IsTurn:   conn.Turn,
			})
		}
	}

	// Fallback to defaults if none returned
	if len(conns) == 0 {
		for _, srv := range SoroushTURNServers {
			for _, url := range srv.URLs {
				conns = append(conns, provider.ICEConnectionInfo{
					URL:      url,
					Username: srv.Username,
					Password: srv.Credential,
					IsTurn:   strings.HasPrefix(url, "turn:"),
				})
			}
		}
	}

	return &provider.CallAcceptResult{
		Connections: conns,
	}, nil
}

// SendTextMessage implements provider.Client
func (c *SoroushClientAdapter) SendTextMessage(targetUserID int64, text string) error {
	sendCtx, sendCancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer sendCancel()

	// access_hash = 0 is acceptable in MTProto direct message if dialog already exists
	return SendTextMessage(sendCtx, c.session, targetUserID, 0, text)
}

// GetTextMsgCh implements provider.Client
func (c *SoroushClientAdapter) GetTextMsgCh() <-chan string {
	return c.textCh
}

// StartPingLoop implements provider.Client
func (c *SoroushClientAdapter) StartPingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				if c.connected && c.session != nil {
					pingBody := BuildPingDelayDisconnectRequest(time.Now().UnixNano(), 75)
					c.session.Send(c.ctx, pingBody, true)
				}
				c.mu.Unlock()
			case <-c.pingStopCh:
				return
			}
		}
	}()
}

// CleanupMessages implements provider.Client
func (c *SoroushClientAdapter) CleanupMessages() {
	// Erase transient metadata or chat history in stealth cleanup phase
}

// DrainChannels implements provider.Client
func (c *SoroushClientAdapter) DrainChannels() {}

// DrainTextChannels implements provider.Client
func (c *SoroushClientAdapter) DrainTextChannels() {}

// Type implements provider.Client
func (c *SoroushClientAdapter) Type() provider.ProviderType {
	return provider.ProviderSoroush
}

// UserID implements provider.Client
func (c *SoroushClientAdapter) UserID() int64 {
	return c.userID
}

// runMessageReader reads Soroush updates in a continuous loop
func (c *SoroushClientAdapter) runMessageReader() {
	err := ListenForMessages(c.ctx, c.session, func(msg IncomingMessage) {
		// Handle internal call request notification
		if strings.HasPrefix(msg.Text, "CALL_REQUESTED:") {
			parts := strings.Split(msg.Text, ":")
			if len(parts) == 4 {
				callID, _ := strconv.ParseInt(parts[1], 10, 64)
				callerID, _ := strconv.ParseInt(parts[2], 10, 64)
				accessHash, _ := strconv.ParseInt(parts[3], 10, 64)

				c.activeCallsMu.Lock()
				c.activeCallAccesses[callID] = accessHash
				c.activeCallsMu.Unlock()

				select {
				case c.callCh <- &provider.IncomingCall{
					CallID:     callID,
					CallerID:   callerID,
					AccessHash: accessHash,
				}:
				default:
					log.Printf("[SoroushClient] Call queue full, discarded call %d", callID)
				}
			}
			return
		}

		// Text messaging forwarder
		select {
		case c.textCh <- msg.Text:
		default:
		}
	})

	if err != nil && c.ctx.Err() == nil {
		log.Printf("[SoroushClient] Reader exited with error: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SoroushClientFactory implements provider.ClientFactory.
// ──────────────────────────────────────────────────────────────────────────────

type SoroushClientFactory struct{}

func init() {
	provider.Register(&SoroushClientFactory{})
}

// NewClient implements provider.ClientFactory
func (f *SoroushClientFactory) NewClient(accountData map[string]interface{}) (provider.Client, error) {
	authKey, _ := accountData["auth_key"].([]byte)
	authKeyID, _ := accountData["auth_key_id"].([]byte)
	serverSalt, _ := accountData["server_salt"].([]byte)

	var userID int64
	if uid, ok := accountData["external_id"].(int64); ok {
		userID = uid
	} else if uid, ok := accountData["external_id"].(float64); ok {
		userID = int64(uid)
	}

	var accessHash int64
	if ah, ok := accountData["access_hash"].(int64); ok {
		accessHash = ah
	} else if ah, ok := accountData["access_hash"].(float64); ok {
		accessHash = int64(ah)
	}

	if len(authKey) == 0 {
		return nil, errors.New("missing auth_key for Soroush client initialization")
	}

	return NewSoroushClientAdapter(authKey, authKeyID, serverSalt, userID, accessHash), nil
}

// NewAuthClient implements provider.ClientFactory
func (f *SoroushClientFactory) NewAuthClient() provider.AuthClient {
	return NewSoroushAuthAdapter()
}

// Type implements provider.ClientFactory
func (f *SoroushClientFactory) Type() provider.ProviderType {
	return provider.ProviderSoroush
}

var (
	_ provider.ClientFactory = (*SoroushClientFactory)(nil)
	_ provider.Client        = (*SoroushClientAdapter)(nil)
)
