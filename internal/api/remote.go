package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// handleRemoteServerURL returns the auto-detected remote server URL.
func (s *Server) handleRemoteServerURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":       s.RemoteServerURL,
		"connected": s.RemoteServerURL != "",
	})
}

// handleRemoteSyncAll proxies a sync-all request to the remote server.
func (s *Server) handleRemoteSyncAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("POST", "/api/accounts/sync-all", nil)
	if err != nil {
		apiLog.Error("Remote sync-all failed: %v", err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteAccounts proxies GET /api/accounts to the remote server.
func (s *Server) handleRemoteAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("GET", "/api/accounts", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteCreateAccount proxies a POST /api/accounts to the remote server.
func (s *Server) handleRemoteCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("POST", "/api/accounts", r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteSyncPull proxies a GET /api/sync/pull to the remote server.
func (s *Server) handleRemoteSyncPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	query := r.URL.Query().Encode()
	resp, err := s.proxyToRemote("GET", "/api/sync/pull?"+query, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteSyncPush proxies a POST /api/sync/push to the remote server.
func (s *Server) handleRemoteSyncPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("POST", "/api/sync/push", r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteSyncPushAccounts pushes all local accounts (with their real tokens) to the remote server.
func (s *Server) handleRemoteSyncPushAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	localAccounts, err := s.database.ListAccounts("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read local accounts")
		return
	}

	pushed := 0
	failed := 0

	for _, acct := range localAccounts {
		payload := map[string]string{
			"token": acct.Token,
			"role":  acct.Role,
		}
		body, _ := json.Marshal(payload)
		
		resp, err := s.proxyToRemote("POST", "/api/accounts", bytes.NewReader(body))
		if err != nil {
			failed++
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			pushed++
		} else {
			// Might be 400 if already exists, count as ignored/failed
			failed++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pushed": pushed,
		"failed": failed,
		"total":  len(localAccounts),
	})
}

// handleRemotePushSingleAccount pushes a single account (by ID) to the remote server.
// POST /api/remote/accounts/{id}/push
func (s *Server) handleRemotePushSingleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	idStr := extractID(r.URL.Path, "/api/remote/accounts/")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acct, err := s.database.GetAccount(uint(id))
	if err != nil || acct == nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	s.pushAccountToRemote(acct)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "account pushed to remote server",
		"account_id": acct.ID,
	})
}

// handleRemotePushSinglePairing pushes a single pairing (by ID) to the remote server.
// POST /api/remote/pairings/{id}/push
func (s *Server) handleRemotePushSinglePairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	idStr := extractID(r.URL.Path, "/api/remote/pairings/")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pairing ID")
		return
	}

	// Find the pairing
	pairings, err := s.database.ListPairings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list pairings")
		return
	}

	var found bool
	for _, p := range pairings {
		if p.ID == uint(id) {
			found = true
			s.pushPairingToRemote(p.ClientAccountID, p.ServerAccountID)
			break
		}
	}

	if !found {
		writeError(w, http.StatusNotFound, "pairing not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "pairing pushed to remote server",
		"pairing_id": uint(id),
	})
}

// handleRemotePushAllPairings pushes all local pairings to the remote server.
// POST /api/remote/sync/push-pairings
func (s *Server) handleRemotePushAllPairings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	s.pushAllPairingsToRemote()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "all pairings pushed to remote server",
	})
}

// handleRemoteDBBackup proxies GET /api/db/backup to the remote server.
// Returns the full database state including tokens for local backup storage.
func (s *Server) handleRemoteDBBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("GET", "/api/db/backup", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemoteDBRestore pushes a backup to the remote server to restore its DB.
func (s *Server) handleRemoteDBRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	resp, err := s.proxyToRemote("POST", "/api/db/restore", r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleRemotePullAccounts pulls SERVER accounts from the remote server
// and inserts them locally if they don't already exist.
// POST /api/remote/pull-accounts
func (s *Server) handleRemotePullAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	// Fetch accounts from remote server
	resp, err := s.proxyToRemote("GET", "/api/accounts", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeError(w, resp.StatusCode, string(body))
		return
	}

	var remoteAccounts []struct {
		ProviderType string `json:"provider_type"`
		ExternalID   int64  `json:"external_id"`
		BaleUserID   int64  `json:"bale_user_id"` // fallback for legacy servers
		Role         string `json:"role"`
		DisplayName  string `json:"display_name"`
		Phone        string `json:"phone"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&remoteAccounts); err != nil {
		writeError(w, http.StatusBadGateway, "failed to decode remote accounts")
		return
	}

	inserted := 0
	skipped := 0

	for _, ra := range remoteAccounts {
		// Only pull SERVER accounts (client manages its own CLIENT accounts)
		if ra.Role != "SERVER" {
			continue
		}

		// Resolve provider + external ID (support both new and legacy fields)
		provType := ra.ProviderType
		if provType == "" {
			provType = "bale"
		}
		extID := ra.ExternalID
		if extID == 0 {
			extID = ra.BaleUserID
		}
		if extID == 0 {
			skipped++
			continue
		}

		// Check if already exists locally
		existing, _ := s.database.GetAccountByExternalID(provType, extID)
		if existing != nil {
			// Update display info if needed
			if (ra.DisplayName != "" && ra.DisplayName != existing.DisplayName) ||
				(ra.Phone != "" && ra.Phone != existing.Phone) {
				s.database.UpdateAccountInfo(existing.ID, ra.DisplayName, ra.Phone, 0)
			}
			skipped++
			continue
		}

		// Create locally (no token needed — just a reference for pairing)
		acct, err := s.database.CreateAccountWithProvider("", ra.Role, extID, provType)
		if err != nil {
			apiLog.Warn("Pull: failed to create %s account %d: %v", provType, extID, err)
			skipped++
			continue
		}
		if ra.DisplayName != "" || ra.Phone != "" {
			s.database.UpdateAccountInfo(acct.ID, ra.DisplayName, ra.Phone, 0)
		}
		inserted++
		apiLog.Info("Pulled SERVER account from remote: %s/%d (%s)", provType, extID, ra.DisplayName)
	}

	if inserted > 0 {
		bumpDataVersion()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inserted": inserted,
		"skipped":  skipped,
		"total":    len(remoteAccounts),
	})
}

// handleRemoteSyncFromServer pulls ALL data (accounts + pairings) from the remote
// server and inserts anything that doesn't exist locally. No duplicates.
// POST /api/remote/sync-from-server
func (s *Server) handleRemoteSyncFromServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RemoteServerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remote server URL not configured")
		return
	}

	// 1. Fetch snapshot from remote server
	resp, err := s.proxyToRemote("GET", "/api/sync/snapshot", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("remote server error: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeError(w, resp.StatusCode, string(body))
		return
	}

	// Use db.Account directly since the snapshot returns the full Account struct
	var snapshot struct {
		Version  int64       `json:"version"`
		Accounts []struct {
			ProviderType string `json:"provider_type"`
			ExternalID   int64  `json:"external_id"`
			BaleUserID   int64  `json:"bale_user_id"` // fallback
			Role         string `json:"role"`
			DisplayName  string `json:"display_name"`
			Phone        string `json:"phone"`
			Enabled      bool   `json:"enabled"`
		} `json:"accounts"`
		Pairings []struct {
			ClientAccountID uint `json:"client_account_id"`
			ServerAccountID uint `json:"server_account_id"`
			Active          bool `json:"active"`
			ClientAccount   *struct {
				ProviderType string `json:"provider_type"`
				ExternalID   int64  `json:"external_id"`
				BaleUserID   int64  `json:"bale_user_id"`
				Role         string `json:"role"`
				DisplayName  string `json:"display_name"`
			} `json:"client_account"`
			ServerAccount *struct {
				ProviderType string `json:"provider_type"`
				ExternalID   int64  `json:"external_id"`
				BaleUserID   int64  `json:"bale_user_id"`
				Role         string `json:"role"`
				DisplayName  string `json:"display_name"`
			} `json:"server_account"`
		} `json:"pairings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		writeError(w, http.StatusBadGateway, "failed to decode server snapshot")
		return
	}

	accountsInserted := 0
	accountsUpdated := 0
	pairingsInserted := 0

	// helper: resolve provider+ID from either new or legacy fields
	resolveAccount := func(provType string, extID, baleID int64) (string, int64) {
		if provType == "" {
			provType = "bale"
		}
		if extID == 0 {
			extID = baleID
		}
		return provType, extID
	}

	// 2. Sync SERVER accounts from remote (client manages its own CLIENT accounts)
	for _, ra := range snapshot.Accounts {
		if ra.Role != "SERVER" {
			continue
		}
		provType, extID := resolveAccount(ra.ProviderType, ra.ExternalID, ra.BaleUserID)
		if extID == 0 {
			continue
		}

		existing, _ := s.database.GetAccountByExternalID(provType, extID)
		if existing != nil {
			// Update display info if changed
			changed := false
			if ra.DisplayName != "" && ra.DisplayName != existing.DisplayName {
				changed = true
			}
			if ra.Phone != "" && ra.Phone != existing.Phone {
				changed = true
			}
			if changed {
				s.database.UpdateAccountInfo(existing.ID, ra.DisplayName, ra.Phone, 0)
				accountsUpdated++
			}
			continue
		}

		// Create new SERVER account locally with correct provider type
		acct, err := s.database.CreateAccountWithProvider("", ra.Role, extID, provType)
		if err != nil {
			apiLog.Warn("Sync: failed to create %s account %d: %v", provType, extID, err)
			continue
		}
		if ra.DisplayName != "" || ra.Phone != "" {
			s.database.UpdateAccountInfo(acct.ID, ra.DisplayName, ra.Phone, 0)
		}
		accountsInserted++
		apiLog.Info("Sync: imported SERVER account %s/%d (%s)", provType, extID, ra.DisplayName)
	}

	// 3. Sync pairings from remote
	for _, rp := range snapshot.Pairings {
		if rp.ClientAccount == nil || rp.ServerAccount == nil {
			continue
		}

		clientProv, clientExtID := resolveAccount(rp.ClientAccount.ProviderType, rp.ClientAccount.ExternalID, rp.ClientAccount.BaleUserID)
		serverProv, serverExtID := resolveAccount(rp.ServerAccount.ProviderType, rp.ServerAccount.ExternalID, rp.ServerAccount.BaleUserID)

		clientAcct, _ := s.database.GetAccountByExternalID(clientProv, clientExtID)
		serverAcct, _ := s.database.GetAccountByExternalID(serverProv, serverExtID)
		if clientAcct == nil || serverAcct == nil {
			apiLog.Warn("Sync: skipping pairing — client=%s/%d found=%v, server=%s/%d found=%v",
				clientProv, clientExtID, clientAcct != nil,
				serverProv, serverExtID, serverAcct != nil)
			continue
		}

		// Check if pairing already exists
		existingPairings, _ := s.database.ListPairings()
		alreadyExists := false
		for _, p := range existingPairings {
			if p.ClientAccountID == clientAcct.ID && p.ServerAccountID == serverAcct.ID {
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}

		_, err := s.database.CreatePairing(clientAcct.ID, serverAcct.ID, "")
		if err == nil {
			pairingsInserted++
		}
	}

	if accountsInserted > 0 || pairingsInserted > 0 {
		bumpDataVersion()
	}

	apiLog.Info("Sync from server: %d accounts inserted, %d updated, %d pairings inserted",
		accountsInserted, accountsUpdated, pairingsInserted)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accounts_inserted": accountsInserted,
		"accounts_updated":  accountsUpdated,
		"pairings_inserted": pairingsInserted,
		"server_accounts":   len(snapshot.Accounts),
		"server_pairings":   len(snapshot.Pairings),
	})
}

// proxyToRemote makes an authenticated HTTP request to the remote server.
func (s *Server) proxyToRemote(method, path string, body io.Reader) (*http.Response, error) {
	url := s.RemoteServerURL + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Use the same hardcoded admin credentials for the remote server
	auth := base64.StdEncoding.EncodeToString([]byte("salman:Salman136517"))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}
