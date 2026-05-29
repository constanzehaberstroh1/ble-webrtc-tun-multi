package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/salman/ble-webrtc-tun/internal/bale"
)

// pendingLogin tracks an in-progress OTP login session.
type pendingLogin struct {
	Phone           string
	TransactionHash string
	AuthClient      *bale.AuthClient
}

var (
	pendingLogins   = make(map[string]*pendingLogin) // keyed by phone number
	pendingLoginsMu sync.Mutex
)

// handleBaleLoginStart initiates the OTP flow by sending SMS to the phone number.
// POST /api/bale/login/start — body: { "phone": "09151016774" }
func (s *Server) handleBaleLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	phone := normalizePhone(req.Phone)
	if phone == 0 {
		writeError(w, http.StatusBadRequest, "invalid phone number")
		return
	}

	// Try to find an existing access_token from any account in the DB
	// The Bale Envoy proxy requires a valid access_token cookie even for StartPhoneAuth
	existingToken := ""
	if accounts, err := s.database.ListAccounts(""); err == nil {
		for _, acct := range accounts {
			if acct.Token != "" {
				existingToken = acct.Token
				break
			}
		}
	}

	var authClient *bale.AuthClient
	if existingToken != "" {
		apiLog.Info("Using existing token for Bale auth cookie")
		authClient = bale.NewAuthClientWithToken(existingToken)
	} else {
		apiLog.Warn("No existing token found — StartPhoneAuth may fail without cookie")
		authClient = bale.NewAuthClient()
	}
	txHash, err := authClient.StartPhoneAuth(phone)
	if err != nil {
		apiLog.Warn("Bale login start failed for %s: %v", req.Phone, err)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to send OTP: %v", err))
		return
	}

	// Store the pending login
	pendingLoginsMu.Lock()
	pendingLogins[req.Phone] = &pendingLogin{
		Phone:           req.Phone,
		TransactionHash: txHash,
		AuthClient:      authClient,
	}
	pendingLoginsMu.Unlock()

	apiLog.Info("Bale OTP sent to %s (txHash=%s)", req.Phone, txHash[:8]+"...")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "OTP sent successfully",
		"phone":            req.Phone,
		"transaction_hash": txHash,
	})
}

// handleBaleLoginVerify validates the OTP code and creates the account.
// POST /api/bale/login/verify — body: { "phone": "09151016774", "code": "123456" }
func (s *Server) handleBaleLoginVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
		Role  string `json:"role"` // auto-determined if empty
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" || len(req.Code) < 4 {
		writeError(w, http.StatusBadRequest, "invalid OTP code")
		return
	}

	// Auto-determine role from the panel's database role
	if req.Role == "" {
		req.Role = s.autoDetectRole()
	}

	// Look up pending login
	pendingLoginsMu.Lock()
	pending, ok := pendingLogins[req.Phone]
	pendingLoginsMu.Unlock()

	if !ok {
		writeError(w, http.StatusBadRequest, "no pending OTP for this phone number — start login first")
		return
	}

	// Validate the code
	result, err := pending.AuthClient.ValidateCode(pending.TransactionHash, req.Code)
	if err != nil {
		apiLog.Warn("Bale OTP verification failed for %s: %v", req.Phone, err)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("OTP verification failed: %v", err))
		return
	}

	// Clean up pending login
	pendingLoginsMu.Lock()
	delete(pendingLogins, req.Phone)
	pendingLoginsMu.Unlock()

	// Check if account already exists (including soft-deleted)
	existingAcct, _ := s.database.GetAccountByBaleUserID(result.UserID)
	if existingAcct == nil {
		// Also check for soft-deleted accounts
		existingAcct, _ = s.database.GetAccountByBaleUserIDUnscoped(result.UserID)
	}

	// Enforce cross-role uniqueness: same account cannot be both CLIENT and SERVER
	if existingAcct != nil && existingAcct.Role != req.Role {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("account (Bale ID %d) already exists as %s — cannot add as %s",
				result.UserID, existingAcct.Role, req.Role))
		return
	}

	// Check remote server for cross-role conflict
	if s.RemoteServerURL != "" {
		if err := s.checkRemoteRoleConflict("bale", result.UserID, req.Role); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}

	if existingAcct != nil {
		// Update the token and restore if soft-deleted
		updates := map[string]interface{}{
			"token":        result.Token,
			"display_name": result.DisplayName,
			"phone":        result.Phone,
			"deleted_at":   nil, // Restore if soft-deleted
			"enabled":      true,
			"status":       "IDLE",
		}
		s.database.DB.Unscoped().Model(existingAcct).Updates(updates)
		existingAcct.Token = result.Token
		existingAcct.DisplayName = result.DisplayName
		existingAcct.Phone = result.Phone
		apiLog.Info("Updated existing account %d (user %d) with new token", existingAcct.ID, result.UserID)
		bumpDataVersion()

		// Push updated account to remote server
		if s.RemoteServerURL != "" {
			go s.pushAccountToRemote(existingAcct)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":    "account updated with new token",
			"account_id": existingAcct.ID,
			"user_id":    result.UserID,
			"name":       result.DisplayName,
			"phone":      result.Phone,
			"updated":    true,
		})
		return
	}

	// Create new account
	acct, err := s.database.CreateAccount(result.Token, req.Role, result.UserID)
	if err != nil {
		apiLog.Warn("Failed to create account for user %d: %v", result.UserID, err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create account: %v", err))
		return
	}

	// Update display info
	if result.DisplayName != "" || result.Phone != "" {
		s.database.UpdateAccountInfo(acct.ID, result.DisplayName, result.Phone, result.AccessHash)
	}

	bumpDataVersion()

	// Push to remote server
	if s.RemoteServerURL != "" {
		go s.pushAccountToRemote(acct)
	}

	apiLog.Info("Created new %s account %d (user %d, %s)", req.Role, acct.ID, result.UserID, result.Phone)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "account created successfully",
		"account_id": acct.ID,
		"user_id":    result.UserID,
		"name":       result.DisplayName,
		"phone":      result.Phone,
		"role":       req.Role,
	})
}

// normalizePhone converts a local phone number to international format.
// e.g., "09151016774" → 989151016774, "+989151016774" → 989151016774
func normalizePhone(phone string) int64 {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	if strings.HasPrefix(phone, "+98") {
		phone = "98" + phone[3:]
	} else if strings.HasPrefix(phone, "0") {
		phone = "98" + phone[1:]
	} else if !strings.HasPrefix(phone, "98") {
		phone = "98" + phone
	}

	n, err := strconv.ParseInt(phone, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
