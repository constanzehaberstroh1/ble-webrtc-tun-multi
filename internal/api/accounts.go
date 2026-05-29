package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/salman/ble-webrtc-tun/internal/db"
)

// handleAccounts handles GET /api/accounts and POST /api/accounts.
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAccounts(w, r)
	case http.MethodPost:
		s.createAccount(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSyncAllAccounts triggers a background sync of all accounts.
func (s *Server) handleSyncAllAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	go s.manager.SyncAllAccounts()
	writeJSON(w, http.StatusOK, map[string]string{"message": "Background sync started"})
}

// handleAccountByID handles operations on /api/accounts/{id}[/action].
func (s *Server) handleAccountByID(w http.ResponseWriter, r *http.Request) {
	idStr := extractID(r.URL.Path, "/api/accounts/")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing account ID")
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	subPath := extractSubPath(r.URL.Path, "/api/accounts/")

	switch {
	case subPath == "info" && r.Method == http.MethodPost:
		s.refreshAccountInfo(w, r, uint(id))
	case subPath == "" && r.Method == http.MethodGet:
		s.getAccount(w, r, uint(id))
	case subPath == "" && r.Method == http.MethodPatch:
		s.updateAccount(w, r, uint(id))
	case subPath == "" && r.Method == http.MethodDelete:
		s.deleteAccount(w, r, uint(id))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// GET /api/accounts?role=CLIENT|SERVER
func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	accts, err := s.manager.ListAccounts(role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, accts)
}

// autoDetectRole returns the appropriate role for this admin panel.
// Client panel → CLIENT, Server panel → SERVER.
func (s *Server) autoDetectRole() string {
	dbRole := s.database.Role()
	if strings.EqualFold(dbRole, "client") {
		return db.RoleClient
	}
	return db.RoleServer
}

// POST /api/accounts { "token": "...", "role": "CLIENT|SERVER" }
// Role is auto-determined from the panel's database role if not provided.
// Cross-role validation: prevents adding an account that already exists
// with the opposite role on either this side or the remote side.
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	// Auto-determine role from panel's DB role if not explicitly specified
	if req.Role == "" {
		req.Role = s.autoDetectRole()
	}

	if req.Role != db.RoleClient && req.Role != db.RoleServer {
		writeError(w, http.StatusBadRequest, "role must be CLIENT or SERVER")
		return
	}

	// Extract bale_user_id from token to check cross-role uniqueness
	userID := extractUserIDFromToken(req.Token)
	if userID != 0 {
		// Check locally: same bale_user_id must not exist with opposite role
		existing, _ := s.database.GetAccountByBaleUserID(userID)
		if existing != nil && existing.Role != req.Role {
			writeError(w, http.StatusConflict,
				fmt.Sprintf("account (Bale ID %d) already exists as %s — cannot add as %s", userID, existing.Role, req.Role))
			return
		}

		// Check remote server for cross-role conflict
		if s.RemoteServerURL != "" {
			if err := s.checkRemoteRoleConflict("bale", userID, req.Role); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
		}
	}

	acct, err := s.manager.AddAccount(req.Token, req.Role)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// Bump data version to notify long-poll clients
	bumpDataVersion()

	// Push to remote server
	if s.RemoteServerURL != "" && acct != nil {
		go s.pushAccountToRemote(acct)
	}

	writeJSON(w, http.StatusCreated, acct)
}

// checkRemoteRoleConflict checks if an account with the given external ID/bale_user_id
// already exists on the remote server with the opposite role.
func (s *Server) checkRemoteRoleConflict(providerType string, externalID int64, wantRole string) error {
	path := fmt.Sprintf("/api/sync/check-role?provider_type=%s&external_id=%d", providerType, externalID)
	resp, err := s.proxyToRemote("GET", path, nil)
	if err != nil {
		return nil // Don't block on remote errors
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var result struct {
		Exists bool   `json:"exists"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	if result.Exists && result.Role != wantRole {
		return fmt.Errorf("account (%s ID %d) already exists on remote as %s — cannot add as %s",
			providerType, externalID, result.Role, wantRole)
	}
	return nil
}

// pushAccountToRemote pushes a newly created account to the remote server via sync API.
func (s *Server) pushAccountToRemote(acct *db.Account) {
	payload := map[string]interface{}{
		"token":         acct.Token,
		"role":          acct.Role,
		"provider_type": acct.ProviderType,
		"external_id":   acct.ExternalID,
		"bale_user_id":  acct.ExternalID, // for backward compatibility
		"display_name":  acct.DisplayName,
		"phone":         acct.Phone,
		"auth_key":      acct.AuthKey,
		"auth_key_id":   acct.AuthKeyID,
		"server_salt":   acct.ServerSalt,
	}
	body, _ := json.Marshal(payload)

	resp, err := s.proxyToRemote("POST", "/api/sync/account-created", bytes.NewReader(body))
	if err != nil {
		apiLog.Warn("Failed to push account to remote: %v", err)
		return
	}
	resp.Body.Close()
	apiLog.Info("Pushed account %d to remote server (status=%d)", acct.ID, resp.StatusCode)
}

// pushAccountDeleteToRemote notifies the remote server about a deleted account.
func (s *Server) pushAccountDeleteToRemote(providerType string, externalID int64) {
	payload := map[string]interface{}{
		"provider_type": providerType,
		"external_id":   externalID,
		"bale_user_id":  externalID, // for backward compatibility
	}
	body, _ := json.Marshal(payload)

	resp, err := s.proxyToRemote("POST", "/api/sync/account-deleted", bytes.NewReader(body))
	if err != nil {
		apiLog.Warn("Failed to push account delete to remote: %v", err)
		return
	}
	resp.Body.Close()
	apiLog.Info("Pushed account delete (%s %d) to remote server", providerType, externalID)
}

// GET /api/accounts/{id}
func (s *Server) getAccount(w http.ResponseWriter, _ *http.Request, id uint) {
	acct, err := s.manager.GetAccount(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// PATCH /api/accounts/{id} { "enabled": true|false, "token": "..." }
// Role changes are no longer allowed — role is auto-determined.
func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request, id uint) {
	var req struct {
		Enabled *bool   `json:"enabled"`
		Token   *string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Enabled != nil {
		if err := s.manager.EnableAccount(id, *req.Enabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Token != nil {
		if *req.Token == "" {
			writeError(w, http.StatusBadRequest, "token cannot be empty")
			return
		}
		updates := map[string]interface{}{
			"token":      *req.Token,
			"token_hash": db.HashToken(*req.Token),
		}
		if err := s.database.UpdateAccount(id, updates); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	bumpDataVersion()

	acct, err := s.manager.GetAccount(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// DELETE /api/accounts/{id}
func (s *Server) deleteAccount(w http.ResponseWriter, _ *http.Request, id uint) {
	// Get account info before deleting for remote sync
	acct, _ := s.manager.GetAccount(id)

	if err := s.manager.RemoveAccount(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	bumpDataVersion()

	// Push delete to remote server
	if s.RemoteServerURL != "" && acct != nil {
		go s.pushAccountDeleteToRemote(acct.ProviderType, acct.ExternalID)
	}

	writeOK(w, "account deleted")
}

// POST /api/accounts/{id}/info — refresh account info from Bale
func (s *Server) refreshAccountInfo(w http.ResponseWriter, _ *http.Request, id uint) {
	acct, err := s.manager.RefreshAccountInfo(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// extractUserIDFromToken extracts user_id from a Bale JWT token.
func extractUserIDFromToken(token string) int64 {
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

// handleAvailableServers returns server accounts that are available for pairing
// by the given owner. Excludes server accounts already paired by OTHER owners.
// GET /api/accounts/available-servers?owner_id=xxx
func (s *Server) handleAvailableServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ownerID := r.URL.Query().Get("owner_id")
	accounts, err := s.manager.GetAvailableServerAccounts(ownerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}
