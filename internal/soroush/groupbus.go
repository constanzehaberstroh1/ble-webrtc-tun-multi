package soroush

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Group Bus Protocol — Pub/Sub command types for the "My lovely family" group
// ──────────────────────────────────────────────────────────────────────────────

// Group command types
const (
	CmdHeartbeat  = "HEARTBEAT"
	CmdDiscover   = "DISCOVER"
	CmdOffer      = "OFFER"
	CmdCalling    = "CALLING"
	CmdConnected  = "CONNECTED"
	CmdDisconnect = "DISCONNECT"
)

// GroupCommand represents a structured command sent through the group chat
type GroupCommand struct {
	Version    int    `json:"v"`              // Protocol version (always 1)
	Cmd        string `json:"cmd"`            // Command type
	CID        string `json:"cid,omitempty"`  // Client ID (sender or target)
	SID        string `json:"sid,omitempty"`  // Server ID (sender or target)
	UID        int64  `json:"uid,omitempty"`  // Soroush User ID (for call target)
	AccessHash int64  `json:"ah,omitempty"`   // Access hash (for call target)
	Load       int    `json:"load,omitempty"` // Current load (for HEARTBEAT)
	Timestamp  int64  `json:"ts,omitempty"`   // Unix timestamp in milliseconds
	Latency    int64  `json:"lat,omitempty"`  // Latency in ms (for CONNECTED)
}

// ──────────────────────────────────────────────────────────────────────────────
// Command constructors — convenience builders
// ──────────────────────────────────────────────────────────────────────────────

// NewHeartbeat creates a server heartbeat command
func NewHeartbeat(serverID string, uid int64, accessHash int64, load int) *GroupCommand {
	return &GroupCommand{
		Version:    1,
		Cmd:        CmdHeartbeat,
		SID:        serverID,
		UID:        uid,
		AccessHash: accessHash,
		Load:       load,
		Timestamp:  time.Now().UnixMilli(),
	}
}

// NewDiscover creates a client discover command
func NewDiscover(clientID string) *GroupCommand {
	return &GroupCommand{
		Version:   1,
		Cmd:       CmdDiscover,
		CID:       clientID,
		Timestamp: time.Now().UnixMilli(),
	}
}

// NewOffer creates a server offer command in response to a discover
func NewOffer(clientID, serverID string, workerUID int64, workerAccessHash int64) *GroupCommand {
	return &GroupCommand{
		Version:    1,
		Cmd:        CmdOffer,
		CID:        clientID,
		SID:        serverID,
		UID:        workerUID,
		AccessHash: workerAccessHash,
		Timestamp:  time.Now().UnixMilli(),
	}
}

// NewCalling creates a client calling command to lock a server
func NewCalling(clientID, serverID string) *GroupCommand {
	return &GroupCommand{
		Version:   1,
		Cmd:       CmdCalling,
		CID:       clientID,
		SID:       serverID,
		Timestamp: time.Now().UnixMilli(),
	}
}

// NewConnected creates a client connected command
func NewConnected(clientID, serverID string, latencyMs int64) *GroupCommand {
	return &GroupCommand{
		Version:   1,
		Cmd:       CmdConnected,
		CID:       clientID,
		SID:       serverID,
		Latency:   latencyMs,
		Timestamp: time.Now().UnixMilli(),
	}
}

// NewDisconnect creates a disconnect command
func NewDisconnect(id string) *GroupCommand {
	return &GroupCommand{
		Version:   1,
		Cmd:       CmdDisconnect,
		SID:       id,
		Timestamp: time.Now().UnixMilli(),
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Encoding / Decoding — uses stealth obfuscation
// ──────────────────────────────────────────────────────────────────────────────

// EncodeGroupCommand serializes a command and wraps it in stealth encoding
func EncodeGroupCommand(cmd *GroupCommand, psk []byte) (string, error) {
	jsonBytes, err := json.Marshal(cmd)
	if err != nil {
		return "", fmt.Errorf("marshal command: %w", err)
	}
	return EncodePayload(jsonBytes, psk)
}

// DecodeGroupCommand extracts and parses a command from a stealth-encoded message
func DecodeGroupCommand(message string, psk []byte) (*GroupCommand, error) {
	if !IsStealthMessage(message) {
		return nil, fmt.Errorf("not a stealth message")
	}

	jsonBytes, err := DecodePayload(message, psk)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var cmd GroupCommand
	if err := json.Unmarshal(jsonBytes, &cmd); err != nil {
		return nil, fmt.Errorf("unmarshal command: %w", err)
	}

	if cmd.Version == 0 || cmd.Cmd == "" {
		return nil, fmt.Errorf("invalid command: missing version or cmd")
	}

	return &cmd, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Group Bus Send Helper — encode + send to group in one call
// ──────────────────────────────────────────────────────────────────────────────

// SendGroupCommand encodes and sends a command to the group chat.
// accessHash should be non-zero for channels/supergroups.
func SendGroupCommand(ctx context.Context, session *MTProtoSession, chatID int64, cmd *GroupCommand, psk []byte, accessHash ...int64) error {
	encoded, err := EncodeGroupCommand(cmd, psk)
	if err != nil {
		return fmt.Errorf("encode group command: %w", err)
	}

	ah := int64(0)
	if len(accessHash) > 0 {
		ah = accessHash[0]
	}

	if err := SendChannelMessage(ctx, session, chatID, ah, encoded); err != nil {
		return fmt.Errorf("send group command: %w", err)
	}

	log.Printf("[GroupBus] Sent %s to group %d", cmd.Cmd, chatID)
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Server Info — in-memory representation of available servers
// ──────────────────────────────────────────────────────────────────────────────

// ServerInfo represents a discovered server from heartbeat messages
type ServerInfo struct {
	SID        string
	UID        int64
	AccessHash int64
	Load       int
	LastSeen   time.Time
}

// IsAlive returns true if the server was seen within the given timeout
func (s *ServerInfo) IsAlive(timeout time.Duration) bool {
	return time.Since(s.LastSeen) < timeout
}
