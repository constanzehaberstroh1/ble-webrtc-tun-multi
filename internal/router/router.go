// Package router provides the connection routing and state machine for the
// BLE WebRTC Tunnel. It replaces the in-memory activeCallIDs map and
// expectedCallerID filtering with a database-driven, atomic state machine
// that prevents duplicate call collisions and enforces strict pairing.
//
// State machine per server account:
//
//	IDLE ──→ RESERVED ──→ IN_CALL ──→ IDLE
//	  │         │                        ↑
//	  │         └──── (timeout 30s) ─────┘
//	  ↓
//	OFFLINE ──→ IDLE (when reconnected)
package router

import (
	"context"
	"fmt"
	"github.com/salman/ble-webrtc-tun/internal/logger"
	"sync"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/db"
)

var routerLog = logger.New("router")

// Session represents an active or pending tunnel session.
type Session struct {
	ID              uint          // ConnectionLog ID
	PairingID       uint          // Which pairing this session belongs to
	ClientAccountID uint          // Client Bale account
	ServerAccountID uint          // Server Bale account
	CallID          int64         // Bale call ID
	RoomID          string        // LiveKit room ID
	StartTime       time.Time     // When the session began
	cancelFn        context.CancelFunc
}

// Router manages the state machine and call routing decisions.
type Router struct {
	database *db.Database
	mu       sync.RWMutex

	// Active sessions keyed by server account ID
	sessions map[uint]*Session

	// Reservation timeouts — cancel if call isn't established within deadline
	reservationTimers map[uint]*time.Timer
}

// NewRouter creates a new connection router.
func NewRouter(database *db.Database) *Router {
	r := &Router{
		database:          database,
		sessions:          make(map[uint]*Session),
		reservationTimers: make(map[uint]*time.Timer),
	}

	// Reset stale RESERVED/IN_CALL statuses from a previous crash
	if err := database.ResetAllStatuses(); err != nil {
		routerLog.Warn("Warning: failed to reset statuses: %v", err)
	}

	routerLog.Info("✅ Initialized")
	return r
}

// Reserve atomically reserves the next available server account
// and returns the full pairing info. The caller has 30 seconds to
// promote the reservation to IN_CALL via ConfirmCall(), otherwise
// the reservation auto-expires.
//
// This is the client-side entry point: "I want to connect."
func (r *Router) Reserve() (*db.Pairing, error) {
	// Atomically find and reserve an IDLE server account
	acct, err := r.database.ReserveIdleServerAccount()
	if err != nil {
		return nil, fmt.Errorf("no available server accounts: %w", err)
	}

	// Get the pairing for this server account
	pairing, err := r.database.GetPairingByServerAccount(acct.ID)
	if err != nil {
		// No pairing — release the reservation
		r.database.SetAccountStatus(acct.ID, db.StatusIdle)
		return nil, fmt.Errorf("no pairing for server account %d: %w", acct.ID, err)
	}

	// Start reservation timeout
	r.mu.Lock()
	r.reservationTimers[acct.ID] = time.AfterFunc(30*time.Second, func() {
		r.expireReservation(acct.ID)
	})
	r.mu.Unlock()

	routerLog.Info("Reserved server account %d (BaleID=%d) via pairing %d",
		acct.ID, acct.BaleUserID, pairing.ID)

	// Emit event
	r.database.AppendEvent(db.EventStatusChanged, r.database.Role(), db.AccountEventPayload{
		AccountID:  acct.ID,
		BaleUserID: acct.BaleUserID,
		Status:     db.StatusReserved,
		Reason:     "client_reservation",
	})

	return pairing, nil
}

// ReserveSpecific reserves a specific server account by ID.
// Used when you want a particular pairing rather than round-robin.
func (r *Router) ReserveSpecific(serverAccountID uint) (*db.Pairing, error) {
	// Atomically try to reserve this specific account
	result := r.database.DB.Model(&db.Account{}).
		Where("id = ? AND status = ? AND enabled = ?", serverAccountID, db.StatusIdle, true).
		Update("status", db.StatusReserved)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("server account %d is not available (not IDLE or disabled)", serverAccountID)
	}

	pairing, err := r.database.GetPairingByServerAccount(serverAccountID)
	if err != nil {
		r.database.SetAccountStatus(serverAccountID, db.StatusIdle)
		return nil, fmt.Errorf("no pairing for server account %d: %w", serverAccountID, err)
	}

	// Start reservation timeout
	r.mu.Lock()
	r.reservationTimers[serverAccountID] = time.AfterFunc(30*time.Second, func() {
		r.expireReservation(serverAccountID)
	})
	r.mu.Unlock()

	routerLog.Info("Reserved specific server account %d via pairing %d",
		serverAccountID, pairing.ID)

	return pairing, nil
}

// ConfirmCall promotes a RESERVED account to IN_CALL and starts
// tracking the session. Call this after the WebRTC call is established.
func (r *Router) ConfirmCall(serverAccountID uint, callID int64, roomID string) (*Session, error) {
	// Verify the account is in RESERVED state
	acct, err := r.database.GetAccount(serverAccountID)
	if err != nil {
		return nil, fmt.Errorf("account %d not found: %w", serverAccountID, err)
	}
	if acct.Status != db.StatusReserved {
		return nil, fmt.Errorf("account %d is in %s state, expected RESERVED", serverAccountID, acct.Status)
	}

	// Cancel reservation timer
	r.cancelReservationTimer(serverAccountID)

	// Transition: RESERVED → IN_CALL
	if err := r.database.SetAccountStatus(serverAccountID, db.StatusInCall); err != nil {
		return nil, fmt.Errorf("setting IN_CALL status: %w", err)
	}

	// Find the pairing
	pairing, err := r.database.GetPairingByServerAccount(serverAccountID)
	if err != nil {
		return nil, fmt.Errorf("pairing not found: %w", err)
	}

	// Also set client account to IN_CALL
	r.database.SetAccountStatus(pairing.ClientAccountID, db.StatusInCall)

	// Create connection log entry
	connLog, err := r.database.CreateConnectionLog(
		pairing.ClientAccountID,
		serverAccountID,
		pairing.ID,
		callID,
		roomID,
	)
	if err != nil {
		routerLog.Warn("Warning: failed to create connection log: %v", err)
	}

	connLogID := uint(0)
	if connLog != nil {
		connLogID = connLog.ID
	}

	session := &Session{
		ID:              connLogID,
		PairingID:       pairing.ID,
		ClientAccountID: pairing.ClientAccountID,
		ServerAccountID: serverAccountID,
		CallID:          callID,
		RoomID:          roomID,
		StartTime:       time.Now(),
	}

	r.mu.Lock()
	r.sessions[serverAccountID] = session
	r.mu.Unlock()

	routerLog.Info("✅ Call confirmed: server=%d callID=%d room=%s (log=%d)",
		serverAccountID, callID, roomID, connLogID)

	// Emit event
	r.database.AppendEvent(db.EventCallStarted, r.database.Role(), db.CallEventPayload{
		ConnectionLogID: connLogID,
		ClientAcctID:    pairing.ClientAccountID,
		ServerAcctID:    serverAccountID,
		CallID:          callID,
		RoomID:          roomID,
	})

	return session, nil
}

// EndCall terminates a session and transitions accounts back to IDLE.
// Call this when the WebRTC connection drops or the user disconnects.
func (r *Router) EndCall(serverAccountID uint, bytesSent, bytesRecv int64, termination string) {
	r.mu.Lock()
	session, exists := r.sessions[serverAccountID]
	if exists {
		delete(r.sessions, serverAccountID)
	}
	r.mu.Unlock()

	if !exists {
		// No active session — just reset the status
		r.database.SetAccountStatus(serverAccountID, db.StatusIdle)
		return
	}

	// Transition: IN_CALL → IDLE
	r.database.SetAccountStatus(serverAccountID, db.StatusIdle)
	r.database.SetAccountStatus(session.ClientAccountID, db.StatusIdle)

	// End the connection log
	if session.ID > 0 {
		r.database.EndConnectionLog(session.ID, bytesSent, bytesRecv, termination, "")
	}

	routerLog.Info("Call ended: server=%d callID=%d termination=%s (sent=%d recv=%d)",
		serverAccountID, session.CallID, termination, bytesSent, bytesRecv)

	// Emit event
	r.database.AppendEvent(db.EventCallEnded, r.database.Role(), db.CallEventPayload{
		ConnectionLogID: session.ID,
		ClientAcctID:    session.ClientAccountID,
		ServerAcctID:    serverAccountID,
		CallID:          session.CallID,
	})
}

// EndCallWithError terminates a session with an error description.
func (r *Router) EndCallWithError(serverAccountID uint, bytesSent, bytesRecv int64, errMsg string) {
	r.mu.Lock()
	session, exists := r.sessions[serverAccountID]
	if exists {
		delete(r.sessions, serverAccountID)
	}
	r.mu.Unlock()

	r.database.SetAccountStatus(serverAccountID, db.StatusIdle)
	if exists {
		r.database.SetAccountStatus(session.ClientAccountID, db.StatusIdle)
		if session.ID > 0 {
			r.database.EndConnectionLog(session.ID, bytesSent, bytesRecv, "ERROR", errMsg)
		}
	}

	routerLog.Error("Call ended with error: server=%d error=%s", serverAccountID, errMsg)
}

// ShouldAcceptCall decides whether an incoming call should be accepted.
// It checks:
//  1. The server account is in IDLE or RESERVED state
//  2. The caller matches the paired client account (if expectedCallerID is set)
//  3. The call isn't already being handled by another account
//
// Returns the server account ID for status tracking, or an error explaining
// why the call should be rejected.
func (r *Router) ShouldAcceptCall(serverAccountID uint, callerID int64, callID int64) error {
	acct, err := r.database.GetAccount(serverAccountID)
	if err != nil {
		return fmt.Errorf("account %d not found", serverAccountID)
	}

	// Check state — only accept if IDLE or RESERVED
	if acct.Status != db.StatusIdle && acct.Status != db.StatusReserved {
		return fmt.Errorf("account %d is %s, cannot accept calls", serverAccountID, acct.Status)
	}

	// Check if the account is enabled
	if !acct.Enabled {
		return fmt.Errorf("account %d is disabled", serverAccountID)
	}

	// Caller validation: check if the caller matches the paired client
	if callerID != 0 {
		pairing, err := r.database.GetPairingByServerAccount(serverAccountID)
		if err != nil {
			return fmt.Errorf("no pairing for server account %d", serverAccountID)
		}
		if pairing.ClientAccount != nil {
			clientExtID := pairing.ClientAccount.ExternalID
			if clientExtID == 0 {
				clientExtID = pairing.ClientAccount.BaleUserID
			}
			if clientExtID != callerID {
				return fmt.Errorf("caller %d doesn't match paired client %d",
					callerID, clientExtID)
			}
		}
	}

	// Check for duplicate call across all accounts
	r.mu.RLock()
	for _, session := range r.sessions {
		if session.CallID == callID {
			r.mu.RUnlock()
			return fmt.Errorf("call %d is already being handled by server account %d",
				callID, session.ServerAccountID)
		}
	}
	r.mu.RUnlock()

	return nil
}

// ForceEndCall forcibly terminates a session (used from admin panel).
func (r *Router) ForceEndCall(serverAccountID uint) {
	r.EndCall(serverAccountID, 0, 0, "ADMIN_FORCE_KILL")
}

// ---- Query methods ----

// GetSession returns the active session for a server account, if any.
func (r *Router) GetSession(serverAccountID uint) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[serverAccountID]
}

// GetAllSessions returns a snapshot of all active sessions.
func (r *Router) GetAllSessions() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// ActiveSessionCount returns the number of active tunnel sessions.
func (r *Router) ActiveSessionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// IsCallActive checks if a specific call ID is being handled.
func (r *Router) IsCallActive(callID int64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, session := range r.sessions {
		if session.CallID == callID {
			return true
		}
	}
	return false
}

// ---- Internal helpers ----

// expireReservation is called when a reservation times out.
func (r *Router) expireReservation(serverAccountID uint) {
	acct, err := r.database.GetAccount(serverAccountID)
	if err != nil {
		return
	}

	// Only expire if still in RESERVED state (might have been confirmed already)
	if acct.Status != db.StatusReserved {
		return
	}

	r.database.SetAccountStatus(serverAccountID, db.StatusIdle)
	routerLog.Warn("⏰ Reservation expired for server account %d — back to IDLE", serverAccountID)

	r.database.AppendEvent(db.EventStatusChanged, r.database.Role(), db.AccountEventPayload{
		AccountID:  serverAccountID,
		BaleUserID: acct.BaleUserID,
		Status:     db.StatusIdle,
		Reason:     "reservation_timeout",
	})
}

// cancelReservationTimer stops and removes a reservation timer.
func (r *Router) cancelReservationTimer(serverAccountID uint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if timer, ok := r.reservationTimers[serverAccountID]; ok {
		timer.Stop()
		delete(r.reservationTimers, serverAccountID)
	}
}

// Close cleans up the router, ending all sessions.
func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Cancel all reservation timers
	for id, timer := range r.reservationTimers {
		timer.Stop()
		delete(r.reservationTimers, id)
	}

	// End all sessions
	for serverAcctID := range r.sessions {
		r.database.SetAccountStatus(serverAcctID, db.StatusIdle)
	}
	r.sessions = make(map[uint]*Session)

	routerLog.Info("Closed — all sessions ended")
}
