package provider

import (
	"context"
	"time"
)

// ProviderType identifies the messaging platform
type ProviderType string

const (
	ProviderBale    ProviderType = "bale"
	ProviderSoroush ProviderType = "soroush"
)

// AuthResult contains the output of a successful authentication
type AuthResult struct {
	UserID      int64
	AccessHash  int64  // Soroush-specific, 0 for Bale
	DisplayName string
	Phone       string
	Token       string // Bale JWT token
	AuthKey     []byte // Soroush auth key (256 bytes)
	AuthKeyID   []byte // Soroush auth key ID (8 bytes)
	ServerSalt  []byte // Soroush server salt (8 bytes)
}

// IncomingCall represents an incoming voice/video call from the provider
type IncomingCall struct {
	CallID     int64
	CallerID   int64
	AccessHash int64
}

// CallAcceptResult contains LiveKit/WebRTC connection info after accepting a call
type CallAcceptResult struct {
	RoomID       string              // LiveKit room (Bale) or empty (Soroush)
	WssURL       string              // LiveKit WSS URL (Bale)
	LivekitToken string              // LiveKit JWT (Bale)
	Connections  []ICEConnectionInfo // TURN/STUN from call signaling (Soroush)
}

// ICEConnectionInfo holds TURN/STUN server info from call signaling
type ICEConnectionInfo struct {
	URL      string
	Username string
	Password string
	IsTurn   bool
}

// Client is the main provider interface for messenger operations
type Client interface {
	// Connect establishes the WebSocket/transport connection
	Connect() error
	Close() error

	// Call signaling (server side — waiting for incoming calls)
	GetCallCh() <-chan *IncomingCall
	AcceptCall(callID int64, expectedVideo bool) error
	ReceiveCall(callID int64) error
	GetWssURL(callID int64) error
	WaitForAccept(timeout time.Duration) (*CallAcceptResult, error)
	DiscardCall(callID int64) error

	// Call initiation (client side — making outgoing calls)
	InitiateCall(ctx context.Context, targetUserID int64, targetAccessHash int64) (*CallAcceptResult, error)

	// Text messaging (for SDP exchange markers: BLETUN:*, BLECMD:*)
	SendTextMessage(targetUserID int64, text string) error
	GetTextMsgCh() <-chan string

	// Keepalive
	StartPingLoop()

	// Cleanup — erase all traces from chat
	CleanupMessages()
	DrainChannels()
	DrainTextChannels()

	// Provider info
	Type() ProviderType
	UserID() int64
}

// AuthClient handles phone-number-based OTP authentication
type AuthClient interface {
	// StartPhoneAuth sends OTP to the phone number. Returns transaction hash.
	StartPhoneAuth(phone int64) (string, error)

	// ValidateCode verifies the OTP and returns auth credentials
	ValidateCode(txHash string, code string) (*AuthResult, error)

	// Type returns the provider type
	Type() ProviderType
}

// ClientFactory creates provider clients from stored credentials
type ClientFactory interface {
	// NewClient creates a client from stored account data
	NewClient(accountData map[string]interface{}) (Client, error)

	// NewAuthClient creates an auth client for new account registration
	NewAuthClient() AuthClient

	// Type returns the provider type
	Type() ProviderType
}
