// Package db provides embedded SQLite storage via GORM for the BLE WebRTC Tunnel.
// Uses a CGO-free SQLite driver (glebarez/sqlite) to keep single-binary deployment.
package db

import (
	"time"

	"gorm.io/gorm"
)

// Account represents a Bale or Soroush token/account and its current routing state.
// Each account is either a CLIENT (initiates calls) or SERVER (accepts calls).
type Account struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProviderType string         `gorm:"type:text;not null;default:'bale';index:idx_provider_ext,unique" json:"provider_type"` // bale, soroush
	ExternalID   int64          `gorm:"not null;default:0;index:idx_provider_ext,unique" json:"external_id"`
	BaleUserID   int64          `gorm:"index" json:"bale_user_id"` // Deprecated in favor of ExternalID
	AccessHash   int64          `json:"access_hash"`
	Token        string         `gorm:"default:''" json:"-"` // never expose token in JSON (only for Bale)
	TokenHash    string         `gorm:"index" json:"-"`      // SHA256 prefix for display
	AuthKey      []byte         `gorm:"type:blob" json:"-"`  // Soroush auth_key
	AuthKeyID    []byte         `gorm:"type:blob" json:"-"`  // Soroush auth_key_id
	ServerSalt   []byte         `gorm:"type:blob" json:"-"`  // Soroush server_salt
	Role         string         `gorm:"type:text;not null;index" json:"role"` // CLIENT or SERVER
	Status       string         `gorm:"type:text;default:'IDLE';index" json:"status"` // IDLE, RESERVED, IN_CALL, OFFLINE, ERROR
	DisplayName  string         `json:"display_name"`
	Phone        string         `json:"phone"`
	Enabled      bool           `gorm:"default:true" json:"enabled"`
	LastSeen     *time.Time     `json:"last_seen"`
	LastError    string         `json:"last_error,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// Pairing links one client account to one server account for call routing.
// Each server account can only be paired by one client (owner).
// The OwnerID identifies which client machine owns this pairing.
type Pairing struct {
	ID              uint      `gorm:"primarykey" json:"id"`
	ClientAccountID uint      `gorm:"uniqueIndex:idx_pairing;not null" json:"client_account_id"`
	ServerAccountID uint      `gorm:"uniqueIndex:idx_pairing;not null" json:"server_account_id"`
	OwnerID         string    `gorm:"type:text;index;default:''" json:"owner_id"` // client machine identifier
	Active          bool      `gorm:"default:true;index" json:"active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Associations (loaded with Preload)
	ClientAccount *Account `gorm:"foreignKey:ClientAccountID" json:"client_account,omitempty"`
	ServerAccount *Account `gorm:"foreignKey:ServerAccountID" json:"server_account,omitempty"`
}

// ConnectionLog tracks historical and active WebRTC sessions for the dashboard.
type ConnectionLog struct {
	ID            uint       `gorm:"primarykey" json:"id"`
	ClientAcctID  uint       `gorm:"index" json:"client_account_id"`
	ServerAcctID  uint       `gorm:"index" json:"server_account_id"`
	PairingID     uint       `gorm:"index" json:"pairing_id"`
	CallID        int64      `json:"call_id"`
	RoomID        string     `json:"room_id"`
	StartTime     time.Time  `json:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	BytesSent     int64      `json:"bytes_sent"`
	BytesReceived int64      `json:"bytes_received"`
	Termination   string     `gorm:"type:text" json:"termination"` // USER_DISCONNECT, NETWORK_DROP, TIMEOUT, ERROR
	ErrorDetail   string     `json:"error_detail,omitempty"`

	// Associations
	ClientAccount *Account `gorm:"foreignKey:ClientAcctID" json:"client_account,omitempty"`
	ServerAccount *Account `gorm:"foreignKey:ServerAcctID" json:"server_account,omitempty"`
}

// Event is an append-only log entry for event-sourced synchronization
// between client and server databases.
type Event struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	Type      string    `gorm:"type:text;not null;index" json:"type"`
	Payload   string    `gorm:"type:text" json:"payload"` // JSON-encoded event data
	Source    string    `gorm:"type:text" json:"source"`  // "client" or "server"
	Timestamp time.Time `gorm:"autoCreateTime;index" json:"timestamp"`
}

// Setting stores global configuration key-value pairs.
type Setting struct {
	Key       string    `gorm:"primarykey" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AdminUser stores admin panel credentials in the database.
type AdminUser struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ---- Constants ----

// Account roles
const (
	RoleClient = "CLIENT"
	RoleServer = "SERVER"
)

// Account statuses
const (
	StatusIdle     = "IDLE"
	StatusReserved = "RESERVED"
	StatusInCall   = "IN_CALL"
	StatusOffline  = "OFFLINE"
	StatusError    = "ERROR"
)

// Event types
const (
	EventAccountAdded    = "ACCOUNT_ADDED"
	EventAccountRemoved  = "ACCOUNT_REMOVED"
	EventAccountUpdated  = "ACCOUNT_UPDATED"
	EventStatusChanged   = "STATUS_CHANGED"
	EventPairingCreated  = "PAIRING_CREATED"
	EventPairingRemoved  = "PAIRING_REMOVED"
	EventCallStarted     = "CALL_STARTED"
	EventCallEnded       = "CALL_ENDED"
	EventTokenRevoked    = "TOKEN_REVOKED"
	EventHealthCheckFail = "HEALTH_CHECK_FAIL"
	EventSettingChanged  = "SETTING_CHANGED"
)
