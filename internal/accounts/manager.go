// Package accounts provides the account management service for the BLE WebRTC Tunnel.
// It handles adding, removing, validating, and fetching info for Bale accounts,
// coordinating between the database layer and the Bale WebSocket API.
package accounts

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/bale"
	"github.com/salman/ble-webrtc-tun/internal/db"
	"github.com/salman/ble-webrtc-tun/internal/provider"
)

// accountsLog is declared in health.go

// Manager handles the lifecycle of accounts: add, remove, validate,
// fetch info, and periodic health checks.
type Manager struct {
	database *db.Database
	mu       sync.RWMutex

	// Active clients keyed by account ID — used for server-side
	// accounts that need persistent WS connections to receive calls.
	activeClients map[uint]provider.Client
	clientMu      sync.RWMutex

	syncStopCh chan struct{}
}

// NewManager creates a new account manager.
func NewManager(database *db.Database) *Manager {
	m := &Manager{
		database:      database,
		activeClients: make(map[uint]provider.Client),
		syncStopCh:    make(chan struct{}),
	}
	go m.StartPeriodicSync()
	return m
}

// SyncAllAccounts triggers a background sync for all enabled accounts.
func (m *Manager) SyncAllAccounts() {
	accounts, _ := m.database.ListAccounts("")
	for _, acct := range accounts {
		if acct.Enabled {
			// Non-blocking sync
			go m.fetchAndUpdateInfo(acct.ID, acct.Token, acct.BaleUserID)
			time.Sleep(1 * time.Second) // Stagger the requests to avoid rate limits
		}
	}
}

// StartPeriodicSync periodically syncs all enabled accounts.
func (m *Manager) StartPeriodicSync() {
	// Then periodically refresh every 24 hours
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.SyncAllAccounts()
		case <-m.syncStopCh:
			return
		}
	}
}

// AddAccount adds a new Bale account by token. It:
// 1. Parses the JWT to extract the Bale user ID
// 2. Connects to Bale WS temporarily
// 3. Calls GetFullUser RPC to fetch display name, phone, access hash
// 4. Saves everything to the database
// 5. Emits an ACCOUNT_ADDED event
func (m *Manager) AddAccount(token, role string) (*db.Account, error) {
	if role != db.RoleClient && role != db.RoleServer {
		return nil, fmt.Errorf("invalid role: %s (must be CLIENT or SERVER)", role)
	}

	// 1. Extract user ID from JWT
	userID := extractUserIDFromJWT(token)
	if userID == 0 {
		return nil, fmt.Errorf("could not extract user_id from token JWT")
	}

	// Check for duplicates
	existing, _ := m.database.GetAccountByBaleUserID(userID)
	if existing != nil {
		return nil, fmt.Errorf("account with Bale user ID %d already exists (ID=%d)", userID, existing.ID)
	}

	// 2. Create the account in DB first (with minimal info)
	acct, err := m.database.CreateAccount(token, role, userID)
	if err != nil {
		return nil, fmt.Errorf("creating account: %w", err)
	}
	accountsLog.Info("Created account ID=%d BaleID=%d Role=%s", acct.ID, userID, role)

	// 3. Try to fetch full user info from Bale (non-blocking — account is usable without it)
	go m.fetchAndUpdateInfo(acct.ID, token, userID)

	// 4. Emit event
	m.database.AppendEvent(db.EventAccountAdded, m.database.Role(), db.AccountEventPayload{
		AccountID:  acct.ID,
		BaleUserID: userID,
		Role:       role,
	})

	return acct, nil
}

// RemoveAccount removes an account and its associated pairings.
func (m *Manager) RemoveAccount(id uint) error {
	acct, err := m.database.GetAccount(id)
	if err != nil {
		return fmt.Errorf("account %d not found: %w", id, err)
	}

	// Close any active client
	m.StopClient(id)

	// Delete the account (soft delete)
	if err := m.database.DeleteAccount(id); err != nil {
		return fmt.Errorf("deleting account: %w", err)
	}

	accountsLog.Info("Removed account ID=%d BaleID=%d", id, acct.BaleUserID)

	// Emit event
	m.database.AppendEvent(db.EventAccountRemoved, m.database.Role(), db.AccountEventPayload{
		AccountID:  id,
		BaleUserID: acct.BaleUserID,
		Role:       acct.Role,
	})

	return nil
}

// EnableAccount enables or disables an account.
func (m *Manager) EnableAccount(id uint, enabled bool) error {
	if err := m.database.SetAccountEnabled(id, enabled); err != nil {
		return err
	}
	if !enabled {
		m.StopClient(id)
	}

	status := "enabled"
	if !enabled {
		status = "disabled"
	}
	accountsLog.Info("Account %d %s", id, status)

	m.database.AppendEvent(db.EventAccountUpdated, m.database.Role(), db.AccountEventPayload{
		AccountID: id,
		Status:    status,
	})

	return nil
}

// RefreshAccountInfo re-fetches account info from Bale API.
func (m *Manager) RefreshAccountInfo(id uint) (*db.Account, error) {
	acct, err := m.database.GetAccount(id)
	if err != nil {
		return nil, fmt.Errorf("account %d not found: %w", id, err)
	}

	if err := m.fetchAndUpdateInfo(acct.ID, acct.Token, acct.BaleUserID); err != nil {
		return nil, fmt.Errorf("fetching info: %w", err)
	}

	// Re-read from DB to get updated fields
	return m.database.GetAccount(id)
}

// ListAccounts returns all accounts, optionally filtered by role.
func (m *Manager) ListAccounts(role string) ([]db.Account, error) {
	return m.database.ListAccounts(role)
}

// GetAccount retrieves a single account.
func (m *Manager) GetAccount(id uint) (*db.Account, error) {
	return m.database.GetAccount(id)
}

// ---- Client Management ----

// StartClient creates and connects a provider client for a server account.
// The client stays connected to receive incoming calls.
func (m *Manager) StartClient(accountID uint) (provider.Client, error) {
	acct, err := m.database.GetAccount(accountID)
	if err != nil {
		return nil, fmt.Errorf("account %d not found: %w", accountID, err)
	}

	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	// Close existing client if any
	if existing, ok := m.activeClients[accountID]; ok {
		existing.Close()
		delete(m.activeClients, accountID)
	}

	// Dynamic instantiation via factory registry!
	factory, ok := provider.GetFactory(provider.ProviderType(acct.ProviderType))
	if !ok {
		return nil, fmt.Errorf("no registered factory for provider %q", acct.ProviderType)
	}

	// Prepare accountData
	acctData := map[string]interface{}{
		"token":         acct.Token,
		"external_id":   acct.ExternalID,
		"access_hash":   acct.AccessHash,
		"auth_key":      acct.AuthKey,
		"auth_key_id":   acct.AuthKeyID,
		"server_salt":   acct.ServerSalt,
	}

	client, err := factory.NewClient(acctData)
	if err != nil {
		m.database.SetAccountError(accountID, "init: "+err.Error())
		return nil, fmt.Errorf("initializing client: %w", err)
	}

	if err := client.Connect(); err != nil {
		m.database.SetAccountError(accountID, "connect: "+err.Error())
		return nil, fmt.Errorf("connecting to %s: %w", acct.ProviderType, err)
	}
	client.StartPingLoop()

	m.activeClients[accountID] = client
	m.database.SetAccountStatus(accountID, db.StatusIdle)
	m.database.TouchAccount(accountID)

	accountsLog.Info("Started %s client for account %d (ExtID=%d)", acct.ProviderType, accountID, acct.ExternalID)
	return client, nil
}

// GetClient returns the active client for an account, or nil.
func (m *Manager) GetClient(accountID uint) provider.Client {
	m.clientMu.RLock()
	defer m.clientMu.RUnlock()
	return m.activeClients[accountID]
}

// StopClient disconnects and removes the client for an account.
func (m *Manager) StopClient(accountID uint) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	if client, ok := m.activeClients[accountID]; ok {
		client.Close()
		delete(m.activeClients, accountID)
		m.database.SetAccountStatus(accountID, db.StatusOffline)
		accountsLog.Info("Stopped client for account %d", accountID)
	}
}

// StopAllClients disconnects all active clients.
func (m *Manager) StopAllClients() {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	for id, client := range m.activeClients {
		client.Close()
		m.database.SetAccountStatus(id, db.StatusOffline)
	}
	m.activeClients = make(map[uint]provider.Client)
	accountsLog.Info("Stopped all active clients")
}

// ActiveClientCount returns the number of connected clients.
func (m *Manager) ActiveClientCount() int {
	m.clientMu.RLock()
	defer m.clientMu.RUnlock()
	return len(m.activeClients)
}

// ---- Internal helpers ----

// fetchAndUpdateInfo temporarily connects to Bale to fetch account details.
func (m *Manager) fetchAndUpdateInfo(accountID uint, token string, userID int64) error {
	acct, err := m.database.GetAccount(accountID)
	if err != nil {
		return err
	}
	if acct.ProviderType != "bale" {
		// Soroush info is fetched during registration/OTP flow, nothing to do
		return nil
	}

	client := bale.NewClient(token)
	if err := client.Connect(); err != nil {
		m.database.SetAccountError(accountID, "info fetch connect: "+err.Error())
		return fmt.Errorf("connecting: %w", err)
	}
	defer client.Close()
	client.StartPingLoop()

	// Wait briefly for the connection to stabilize
	time.Sleep(1 * time.Second)

	info, err := client.GetFullUserInfo(userID)
	if err != nil {
		accountsLog.Warn("GetFullUserInfo failed for %d: %v", userID, err)
		// Not fatal — account is still usable, just without display info
		return err
	}

	// Update database with fetched info
	if err := m.database.UpdateAccountInfo(accountID, info.DisplayName, info.Phone, info.AccessHash); err != nil {
		return fmt.Errorf("updating account info: %w", err)
	}

	accountsLog.Info("✅ Updated info for account %d: name=%q phone=%q hash=%d",
		accountID, info.DisplayName, info.Phone, info.AccessHash)
	return nil
}

// extractUserIDFromJWT parses a Bale JWT token and extracts the user_id.
func extractUserIDFromJWT(token string) int64 {
	parts := splitString(token, '.')
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

// splitString splits a string by a separator byte without importing strings.
func splitString(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
