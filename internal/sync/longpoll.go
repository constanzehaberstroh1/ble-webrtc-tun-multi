// Package sync provides the long-polling sync worker that runs on the client side.
// It polls the server admin panel for changes to accounts and pairings,
// and applies those changes to the local client database.
package sync

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/db"
	"github.com/salman/ble-webrtc-tun/internal/logger"
)

var lpLog = logger.New("longpoll")

// LongPollWorker maintains a long-polling connection to the server admin
// and syncs accounts and pairings to the local database.
type LongPollWorker struct {
	database      *db.Database
	serverURL     string
	authHeader    string
	lastVersion   int64
	stopCh        chan struct{}
	running       bool
}

// NewLongPollWorker creates a new long-poll sync worker.
func NewLongPollWorker(database *db.Database, serverURL, username, password string) *LongPollWorker {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return &LongPollWorker{
		database:   database,
		serverURL:  strings.TrimSuffix(serverURL, "/"),
		authHeader: "Basic " + auth,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the long-polling loop in a goroutine.
func (w *LongPollWorker) Start() {
	if w.running {
		return
	}
	w.running = true

	// Initial full sync
	go func() {
		w.initialSync()
		w.pollLoop()
	}()

	lpLog.Info("Long-poll sync worker started (server=%s)", w.serverURL)
}

// Stop stops the long-polling loop.
func (w *LongPollWorker) Stop() {
	if !w.running {
		return
	}
	w.running = false
	close(w.stopCh)
	lpLog.Info("Long-poll sync worker stopped")
}

// initialSync fetches the full snapshot from the server and applies it.
func (w *LongPollWorker) initialSync() {
	lpLog.Info("Performing initial sync from server...")

	resp, err := w.doRequest("GET", "/api/sync/snapshot", nil)
	if err != nil {
		lpLog.Warn("Initial sync failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		lpLog.Warn("Initial sync: server returned %d", resp.StatusCode)
		return
	}

	var snapshot struct {
		Version  int64        `json:"version"`
		Accounts []accountData `json:"accounts"`
		Pairings []pairingData `json:"pairings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		lpLog.Warn("Initial sync: decode error: %v", err)
		return
	}

	w.lastVersion = snapshot.Version
	w.applySnapshot(snapshot.Accounts, snapshot.Pairings)
	lpLog.Info("Initial sync complete (version=%d, accounts=%d, pairings=%d)",
		snapshot.Version, len(snapshot.Accounts), len(snapshot.Pairings))
}

// pollLoop continuously long-polls the server for changes.
func (w *LongPollWorker) pollLoop() {
	for {
		select {
		case <-w.stopCh:
			return
		default:
		}

		url := fmt.Sprintf("/api/sync/long-poll?since_version=%d", w.lastVersion)
		resp, err := w.doRequest("GET", url, nil)
		if err != nil {
			lpLog.Warn("Long-poll request failed: %v — retrying in 5s", err)
			w.sleepOrStop(5 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lpLog.Warn("Long-poll: server returned %d: %s — retrying in 5s",
				resp.StatusCode, string(body))
			w.sleepOrStop(5 * time.Second)
			continue
		}

		var result struct {
			Changed  bool          `json:"changed"`
			Version  int64         `json:"version"`
			Accounts []accountData `json:"accounts"`
			Pairings []pairingData `json:"pairings"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			lpLog.Warn("Long-poll: decode error: %v — retrying in 5s", err)
			w.sleepOrStop(5 * time.Second)
			continue
		}
		resp.Body.Close()

		if result.Changed {
			w.lastVersion = result.Version
			w.applySnapshot(result.Accounts, result.Pairings)
			lpLog.Info("Sync update applied (version=%d, accounts=%d, pairings=%d)",
				result.Version, len(result.Accounts), len(result.Pairings))
		}

		// Small pause between polls to prevent tight loop
		w.sleepOrStop(500 * time.Millisecond)
	}
}

// accountData is the wire format for accounts in sync snapshots.
type accountData struct {
	ID           uint   `json:"id"`
	ProviderType string `json:"provider_type"`
	ExternalID   int64  `json:"external_id"`
	BaleUserID   int64  `json:"bale_user_id"`
	Token        string `json:"token,omitempty"` // May be empty (hidden in JSON)
	Role         string `json:"role"`
	Status       string `json:"status"`
	DisplayName  string `json:"display_name"`
	Phone        string `json:"phone"`
	Enabled      bool   `json:"enabled"`
}

// pairingData is the wire format for pairings in sync snapshots.
type pairingData struct {
	ID              uint         `json:"id"`
	ClientAccountID uint         `json:"client_account_id"`
	ServerAccountID uint         `json:"server_account_id"`
	Active          bool         `json:"active"`
	ClientAccount   *accountData `json:"client_account,omitempty"`
	ServerAccount   *accountData `json:"server_account,omitempty"`
}

// applySnapshot applies the server's snapshot to the local database.
// It syncs SERVER accounts from the server and CLIENT+SERVER pairings.
func (w *LongPollWorker) applySnapshot(remoteAccounts []accountData, remotePairings []pairingData) {
	// Only sync SERVER accounts from the remote server
	// (CLIENT accounts are managed locally by the client admin)
	localAccounts, _ := w.database.ListAccounts("")
	
	type accountKey struct {
		providerType string
		externalID   int64
	}
	
	localAccountMap := make(map[accountKey]*db.Account)
	for i := range localAccounts {
		prov := localAccounts[i].ProviderType
		if prov == "" {
			prov = "bale"
		}
		extID := localAccounts[i].ExternalID
		if extID == 0 {
			extID = localAccounts[i].BaleUserID
		}
		localAccountMap[accountKey{prov, extID}] = &localAccounts[i]
	}

	// Track remote SERVER accounts
	remoteServerKeys := make(map[accountKey]bool)

	for _, ra := range remoteAccounts {
		if ra.Role != db.RoleServer {
			continue // Only sync SERVER accounts from the remote
		}
		
		prov := ra.ProviderType
		if prov == "" {
			prov = "bale"
		}
		extID := ra.ExternalID
		if extID == 0 {
			extID = ra.BaleUserID
		}
		if extID == 0 {
			continue
		}
		
		key := accountKey{prov, extID}
		remoteServerKeys[key] = true

		local, exists := localAccountMap[key]
		if !exists {
			// Create SERVER account locally
			lpLog.Info("Creating server account locally: %s %d (%s)", prov, extID, ra.DisplayName)
			acct, err := w.database.CreateAccountWithProvider("", ra.Role, extID, prov)
			if err != nil {
				lpLog.Warn("Failed to create server account %s %d: %v", prov, extID, err)
				continue
			}
			if ra.DisplayName != "" || ra.Phone != "" {
				w.database.UpdateAccountInfo(acct.ID, ra.DisplayName, ra.Phone, 0)
			}
		} else if local.Role != db.RoleServer {
			// Conflict: this account exists locally with a different role
			lpLog.Warn("Role conflict for %s %d: local=%s remote=%s — skipping",
				prov, extID, local.Role, ra.Role)
		} else {
			// Update display info if changed
			if (ra.DisplayName != "" && ra.DisplayName != local.DisplayName) ||
				(ra.Phone != "" && ra.Phone != local.Phone) {
				w.database.UpdateAccountInfo(local.ID, ra.DisplayName, ra.Phone, 0)
			}
		}
	}

	// Remove SERVER accounts locally that no longer exist on the server
	// GUARD: If the server returned 0 SERVER accounts, it likely just restarted
	// with an empty DB — do NOT delete local accounts in that case.
	if len(remoteServerKeys) > 0 {
		for _, localAcct := range localAccounts {
			prov := localAcct.ProviderType
			if prov == "" {
				prov = "bale"
			}
			extID := localAcct.ExternalID
			if extID == 0 {
				extID = localAcct.BaleUserID
			}
			key := accountKey{prov, extID}

			if localAcct.Role == db.RoleServer && !remoteServerKeys[key] {
				lpLog.Info("Removing deleted server account: %s %d", prov, extID)
				// Delete associated pairings first
				pairings, _ := w.database.ListPairings()
				for _, p := range pairings {
					if p.ServerAccountID == localAcct.ID {
						w.database.DeletePairing(p.ID)
					}
				}
				w.database.DeleteAccount(localAcct.ID)
			}
		}
	} else {
		// Server has 0 SERVER accounts — likely just restarted.
		// Skip deletion to preserve local data.
		lpLog.Info("Server returned 0 SERVER accounts — skipping local deletion (possible server restart)")
	}

	// Sync pairings
	w.syncPairings(remotePairings)
}

// syncPairings syncs pairings from the remote server to the local database.
func (w *LongPollWorker) syncPairings(remotePairings []pairingData) {
	localPairings, _ := w.database.ListPairings()

	type accountKey struct {
		providerType string
		externalID   int64
	}
	type pairingKey struct {
		client accountKey
		server accountKey
	}

	getAccountKey := func(acct *db.Account) accountKey {
		if acct == nil {
			return accountKey{}
		}
		prov := acct.ProviderType
		if prov == "" {
			prov = "bale"
		}
		extID := acct.ExternalID
		if extID == 0 {
			extID = acct.BaleUserID
		}
		return accountKey{prov, extID}
	}

	getRemoteAccountKey := func(acct *accountData) accountKey {
		if acct == nil {
			return accountKey{}
		}
		prov := acct.ProviderType
		if prov == "" {
			prov = "bale"
		}
		extID := acct.ExternalID
		if extID == 0 {
			extID = acct.BaleUserID
		}
		return accountKey{prov, extID}
	}

	// Build a map of existing local pairings
	localPairingMap := make(map[pairingKey]uint)
	for _, p := range localPairings {
		if p.ClientAccount != nil && p.ServerAccount != nil {
			key := pairingKey{
				client: getAccountKey(p.ClientAccount),
				server: getAccountKey(p.ServerAccount),
			}
			localPairingMap[key] = p.ID
		}
	}

	// Track remote pairings
	remotePairingKeys := make(map[pairingKey]bool)

	for _, rp := range remotePairings {
		if rp.ClientAccount == nil || rp.ServerAccount == nil {
			continue
		}

		key := pairingKey{
			client: getRemoteAccountKey(rp.ClientAccount),
			server: getRemoteAccountKey(rp.ServerAccount),
		}
		remotePairingKeys[key] = true

		if _, exists := localPairingMap[key]; !exists {
			// Create this pairing locally
			clientAcct, _ := w.database.GetAccountByExternalID(key.client.providerType, key.client.externalID)
			serverAcct, _ := w.database.GetAccountByExternalID(key.server.providerType, key.server.externalID)
			if clientAcct != nil && serverAcct != nil {
				_, err := w.database.CreatePairing(clientAcct.ID, serverAcct.ID, "")
				if err != nil {
					lpLog.Warn("Failed to create pairing (client=%s:%d server=%s:%d): %v",
						key.client.providerType, key.client.externalID,
						key.server.providerType, key.server.externalID, err)
				} else {
					lpLog.Info("Created pairing: client=%s:%d server=%s:%d",
						key.client.providerType, key.client.externalID,
						key.server.providerType, key.server.externalID)
				}
			}
		}
	}

	// Remove pairings that no longer exist on the server
	// GUARD: Don't delete local pairings if server returned 0 pairings (possible restart)
	if len(remotePairingKeys) > 0 {
		for key, pairingID := range localPairingMap {
			if !remotePairingKeys[key] {
				lpLog.Info("Removing deleted pairing: client=%s:%d server=%s:%d",
					key.client.providerType, key.client.externalID,
					key.server.providerType, key.server.externalID)
				w.database.DeletePairing(pairingID)
			}
		}
	}
}

// doRequest makes an authenticated HTTP request to the server.
func (w *LongPollWorker) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	url := w.serverURL + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", w.authHeader)
	req.Header.Set("Content-Type", "application/json")

	// Use a longer timeout for long-poll requests
	timeout := 10 * time.Second
	if strings.Contains(path, "long-poll") {
		timeout = 35 * time.Second // 30s server timeout + 5s buffer
	}

	client := &http.Client{Timeout: timeout}
	return client.Do(req)
}

// sleepOrStop sleeps for the given duration or returns early if stopped.
func (w *LongPollWorker) sleepOrStop(d time.Duration) {
	select {
	case <-w.stopCh:
	case <-time.After(d):
	}
}

// helper to avoid importing strconv just for this
var _ = strconv.Itoa // keep import valid
