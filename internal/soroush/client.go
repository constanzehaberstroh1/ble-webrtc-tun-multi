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
	authKey            []byte
	authKeyID          []byte
	serverSalt         []byte
	userID             int64
	accessHash         int64
	session            *MTProtoSession
	transport          *ObfuscatedTransport
	callCh             chan *provider.IncomingCall
	textCh             chan string
	ctx                context.Context
	cancel             context.CancelFunc
	pingStopCh         chan struct{}
	connected          bool
	mu                 sync.Mutex
	lastIncomingCallID int64

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
	c.mu.Lock()
	callID := c.lastIncomingCallID
	c.mu.Unlock()

	if callID == 0 {
		return c.defaultCallAcceptResult(), nil
	}

	eventCh := make(chan *CallEvent, 10)
	RegisterCallEventListener(callID, eventCh)
	defer UnregisterCallEventListener(callID)

	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case ev := <-eventCh:
		if ev.Type == "discarded" {
			return nil, errors.New("call discarded/ended by remote")
		}
		if ev.Type == "confirmed" {
			conns := make([]provider.ICEConnectionInfo, 0)
			if len(ev.Connections) > 0 {
				for _, conn := range ev.Connections {
					turnURL := fmt.Sprintf("turn:%s:%d", conn.IP, conn.Port)
					if conn.Stun {
						turnURL = fmt.Sprintf("stun:%s:%d", conn.IP, conn.Port)
					}
					if conn.Turn && !strings.Contains(turnURL, "?transport=tcp") {
						turnURL += "?transport=tcp"
					}
					conns = append(conns, provider.ICEConnectionInfo{
						URL:      turnURL,
						Username: conn.Username,
						Password: conn.Password,
						IsTurn:   conn.Turn,
					})
				}
			}
			if len(conns) > 0 {
				return &provider.CallAcceptResult{Connections: conns}, nil
			}
		}
	case <-time.After(timeout):
		// Fallback on timeout
	}

	return c.defaultCallAcceptResult(), nil
}

func (c *SoroushClientAdapter) defaultCallAcceptResult() *provider.CallAcceptResult {
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
	}
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

	gA := make([]byte, 256)
	_, _ = rand.Read(gA)

	randomID := rand.Int31()

	eventCh := make(chan *CallEvent, 10)
	RegisterCallEventListener(0, eventCh)
	defer UnregisterCallEventListener(0)

	callBody := BuildPhoneRequestCall(targetUserID, targetAccessHash, randomID, gAHash)
	_, err := c.session.Send(ctx, callBody, true)
	if err != nil {
		return nil, fmt.Errorf("send requestCall failed: %w", err)
	}

	var callID int64
	var callAccessHash int64
	var acceptedEvent *CallEvent

	// Step 1: Wait for call to be created (waiting state)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ev := <-eventCh:
		if ev.Type == "discarded" {
			return nil, errors.New("call discarded/rejected immediately")
		}
		callID = ev.CallID
		callAccessHash = ev.AccessHash
	case <-time.After(15 * time.Second):
		return nil, errors.New("timeout waiting for call to initiate")
	}

	// Register specific listener for this call ID
	RegisterCallEventListener(callID, eventCh)
	defer UnregisterCallEventListener(callID)
	// Unregister from wildcard so we don't leak/duplicate
	UnregisterCallEventListener(0)

	// Step 2: Wait for callee to accept the call
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ev := <-eventCh:
		if ev.Type == "discarded" {
			return nil, errors.New("call rejected/discarded by callee")
		}
		if ev.Type == "accepted" {
			acceptedEvent = ev
		} else {
			return nil, fmt.Errorf("unexpected call event type: %s", ev.Type)
		}
	case <-time.After(30 * time.Second):
		return nil, errors.New("timeout waiting for callee to accept call")
	}

	// Send confirmCall
	confirmBody := BuildPhoneConfirmCall(callID, callAccessHash, gA, 0)
	_, err = c.session.Send(ctx, confirmBody, true)
	if err != nil {
		return nil, fmt.Errorf("send confirmCall failed: %w", err)
	}

	// Step 3: Wait for call to transition to active (confirmed)
	var activeEvent *CallEvent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ev := <-eventCh:
		if ev.Type == "discarded" {
			return nil, errors.New("call discarded during confirmation")
		}
		if ev.Type == "confirmed" {
			activeEvent = ev
		} else {
			return nil, fmt.Errorf("unexpected call event during confirmation: %s", ev.Type)
		}
	case <-time.After(15 * time.Second):
		return nil, errors.New("timeout waiting for call confirmation")
	}

	// Prepare results (connections)
	conns := make([]provider.ICEConnectionInfo, 0)
	// We check connections from activeEvent first, fallback to acceptedEvent
	sourceConnections := activeEvent.Connections
	if len(sourceConnections) == 0 && acceptedEvent != nil {
		sourceConnections = acceptedEvent.Connections
	}

	if len(sourceConnections) > 0 {
		for _, conn := range sourceConnections {
			turnURL := fmt.Sprintf("turn:%s:%d", conn.IP, conn.Port)
			if conn.Stun {
				turnURL = fmt.Sprintf("stun:%s:%d", conn.IP, conn.Port)
			}
			// Soroush WebRTC connection requires tcp transport option for TURN
			if conn.Turn && !strings.Contains(turnURL, "?transport=tcp") {
				turnURL += "?transport=tcp"
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

				c.mu.Lock()
				c.lastIncomingCallID = callID
				c.mu.Unlock()

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
