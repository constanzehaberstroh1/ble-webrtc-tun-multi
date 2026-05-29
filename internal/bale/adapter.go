package bale

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/provider"
)

// BaleClientAdapter wraps bale.Client to satisfy the provider.Client interface.
type BaleClientAdapter struct {
	client    *Client
	userIDVal int64
	callCh    chan *provider.IncomingCall
	closeChan chan struct{}
}

// NewBaleClientAdapter creates a new adapter for bale.Client.
func NewBaleClientAdapter(token string) *BaleClientAdapter {
	c := NewClient(token)
	uid := extractUserID(token)
	return &BaleClientAdapter{
		client:    c,
		userIDVal: uid,
		callCh:    make(chan *provider.IncomingCall, 32),
		closeChan: make(chan struct{}),
	}
}

// Connect implements provider.Client
func (a *BaleClientAdapter) Connect() error {
	if err := a.client.Connect(); err != nil {
		return err
	}
	// Start forwarding incoming calls to provider channel format
	go a.forwardCalls()
	return nil
}

// Close implements provider.Client
func (a *BaleClientAdapter) Close() error {
	a.client.Close()
	select {
	case <-a.closeChan:
	default:
		close(a.closeChan)
	}
	return nil
}

// GetCallCh implements provider.Client
func (a *BaleClientAdapter) GetCallCh() <-chan *provider.IncomingCall {
	return a.callCh
}

// AcceptCall implements provider.Client
func (a *BaleClientAdapter) AcceptCall(callID int64, expectedVideo bool) error {
	return a.client.AcceptCall(callID, expectedVideo)
}

// ReceiveCall implements provider.Client
func (a *BaleClientAdapter) ReceiveCall(callID int64) error {
	return a.client.ReceiveCall(callID)
}

// GetWssURL implements provider.Client
func (a *BaleClientAdapter) GetWssURL(callID int64) error {
	return a.client.GetWssURL(callID)
}

// WaitForAccept implements provider.Client
func (a *BaleClientAdapter) WaitForAccept(timeout time.Duration) (*provider.CallAcceptResult, error) {
	res, err := a.client.WaitForAccept(timeout)
	if err != nil {
		return nil, err
	}
	return &provider.CallAcceptResult{
		RoomID:       res.RoomID,
		WssURL:       res.WssURL,
		LivekitToken: res.LivekitToken,
	}, nil
}

// DiscardCall implements provider.Client
func (a *BaleClientAdapter) DiscardCall(callID int64) error {
	return a.client.DiscardCall(callID)
}

// InitiateCall implements provider.Client
func (a *BaleClientAdapter) InitiateCall(ctx context.Context, targetUserID int64, targetAccessHash int64) (*provider.CallAcceptResult, error) {
	if err := a.client.StartCall(targetUserID, true); err != nil {
		return nil, err
	}
	res, err := a.client.WaitForAccept(60 * time.Second)
	if err != nil {
		return nil, err
	}
	return &provider.CallAcceptResult{
		RoomID:       res.RoomID,
		WssURL:       res.WssURL,
		LivekitToken: res.LivekitToken,
	}, nil
}

// SendTextMessage implements provider.Client
func (a *BaleClientAdapter) SendTextMessage(targetUserID int64, text string) error {
	return a.client.SendTextMessage(targetUserID, text)
}

// GetTextMsgCh implements provider.Client
func (a *BaleClientAdapter) GetTextMsgCh() <-chan string {
	return a.client.TextMsgCh
}

// StartPingLoop implements provider.Client
func (a *BaleClientAdapter) StartPingLoop() {
	a.client.StartPingLoop()
}

// CleanupMessages implements provider.Client
func (a *BaleClientAdapter) CleanupMessages() {
	a.client.CleanupMessages()
}

// DrainChannels implements provider.Client
func (a *BaleClientAdapter) DrainChannels() {
	a.client.DrainChannels()
}

// DrainTextChannels implements provider.Client
func (a *BaleClientAdapter) DrainTextChannels() {
	a.client.DrainTextChannels()
}

// Type implements provider.Client
func (a *BaleClientAdapter) Type() provider.ProviderType {
	return provider.ProviderBale
}

// UserID implements provider.Client
func (a *BaleClientAdapter) UserID() int64 {
	return a.userIDVal
}

func (a *BaleClientAdapter) forwardCalls() {
	baleCh := a.client.GetCallCh()
	for {
		select {
		case <-a.closeChan:
			return
		case call, ok := <-baleCh:
			if !ok {
				return
			}
			a.callCh <- &provider.IncomingCall{
				CallID:   call.CallID,
				CallerID: call.CallerID,
			}
		}
	}
}

// Helper to extract user_id from Bale JWT token.
func extractUserID(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0
	}
	var claims struct {
		Payload struct {
			UserID int64 `json:"user_id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return 0
	}
	return claims.Payload.UserID
}

// BaleAuthAdapter wraps bale.AuthClient to satisfy the provider.AuthClient interface.
type BaleAuthAdapter struct {
	authClient *AuthClient
}

// NewBaleAuthAdapter creates a new adapter for Bale's AuthClient.
func NewBaleAuthAdapter() *BaleAuthAdapter {
	return &BaleAuthAdapter{
		authClient: NewAuthClient(),
	}
}

// StartPhoneAuth implements provider.AuthClient
func (a *BaleAuthAdapter) StartPhoneAuth(phone int64) (string, error) {
	return a.authClient.StartPhoneAuth(phone)
}

// ValidateCode implements provider.AuthClient
func (a *BaleAuthAdapter) ValidateCode(txHash string, code string) (*provider.AuthResult, error) {
	res, err := a.authClient.ValidateCode(txHash, code)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("nil auth result received")
	}
	return &provider.AuthResult{
		Token:       res.Token,
		UserID:      res.UserID,
		AccessHash:  res.AccessHash,
		DisplayName: res.DisplayName,
		Phone:       res.Phone,
	}, nil
}

// Type implements provider.AuthClient
func (a *BaleAuthAdapter) Type() provider.ProviderType {
	return provider.ProviderBale
}
