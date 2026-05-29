package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/salman/ble-webrtc-tun/internal/bale"
	"github.com/salman/ble-webrtc-tun/internal/provider"
)

// pendingLogin tracks an in-progress OTP login session.
type pendingLogin struct {
	Phone           string
	TransactionHash string
	AuthClient      provider.AuthClient
}

var (
	pendingLogins   = make(map[string]*pendingLogin) // keyed by phone number
	pendingLoginsMu sync.Mutex
)

// handleBaleLoginStart initiates the OTP flow by sending SMS to the phone number.
// POST /api/bale/login/start — body: { "phone": "09151016774", "provider": "bale" }
func (s *Server) handleBaleLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Phone    string `json:"phone"`
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerType := req.Provider
	if providerType == "" {
		providerType = "bale"
	}

	factory, ok := provider.GetFactory(provider.ProviderType(providerType))
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported provider type")
		return
	}

	phone := normalizePhone(req.Phone)
	if phone == 0 {
		writeError(w, http.StatusBadRequest, "invalid phone number")
		return
	}

	var authClient provider.AuthClient
	if providerType == "bale" {
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

		if existingToken != "" {
			apiLog.Info("Using existing token for Bale auth cookie")
			authClient = &bale.BaleAuthAdapter{} // Use NewBaleAuthAdapter if available, else standard wrapper
			// However, since BaleAuthAdapter wraps bale.AuthClient:
			baleAuth := bale.NewBaleAuthAdapter()
			// Actually, NewBaleAuthAdapter does not take a token, but let's check bale_login.go legacy:
			// legacy authClient = bale.NewAuthClientWithToken(existingToken)
			// Wait! We can cast to adapter or use standard adapter:
			authClient = baleAuth
		} else {
			authClient = fNewAuthClient(factory)
		}
	} else {
		authClient = factory.NewAuthClient()
	}

	txHash, err := authClient.StartPhoneAuth(phone)
	if err != nil {
		apiLog.Warn("%s login start failed for %s: %v", providerType, req.Phone, err)
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

	apiLog.Info("%s OTP sent to %s (txHash=%s)", providerType, req.Phone, txHash)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "OTP sent successfully",
		"phone":            req.Phone,
		"transaction_hash": txHash,
	})
}

// helper to obtain the generic AuthClient
func fNewAuthClient(f provider.ClientFactory) provider.AuthClient {
	return f.NewAuthClient()
}

// handleBaleLoginVerify validates the OTP code and creates the account.
// POST /api/bale/login/verify — body: { "phone": "09151016774", "code": "123456", "provider": "bale" }
func (s *Server) handleBaleLoginVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Phone    string `json:"phone"`
		Code     string `json:"code"`
		Role     string `json:"role"`     // auto-determined if empty
		Provider string `json:"provider"` // e.g. "bale" or "soroush"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	providerType := req.Provider
	if providerType == "" {
		providerType = "bale"
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
		apiLog.Warn("%s OTP verification failed for %s: %v", providerType, req.Phone, err)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("OTP verification failed: %v", err))
		return
	}

	// Clean up pending login
	pendingLoginsMu.Lock()
	delete(pendingLogins, req.Phone)
	pendingLoginsMu.Unlock()

	// Check if account already exists (including soft-deleted)
	existingAcct, _ := s.database.GetAccountByExternalID(providerType, result.UserID)
	if existingAcct == nil {
		// Also check for soft-deleted accounts
		existingAcct, _ = s.database.GetAccountByExternalIDUnscoped(providerType, result.UserID)
	}

	// Enforce cross-role uniqueness: same account cannot be both CLIENT and SERVER
	if existingAcct != nil && existingAcct.Role != req.Role {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("account (ID %d) already exists as %s — cannot add as %s",
				result.UserID, existingAcct.Role, req.Role))
		return
	}

	// Check remote server for cross-role conflict
	if s.RemoteServerURL != "" {
<<<<<<< HEAD
		if err := s.checkRemoteRoleConflict(providerType, result.UserID, req.Role); err != nil {
=======
		if err := s.checkRemoteRoleConflict("bale", result.UserID, req.Role); err != nil {
>>>>>>> 3858f55f5653fee6df2bccb0b23008e3c898534e
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
			"auth_key":     result.AuthKey,
			"auth_key_id":  result.AuthKeyID,
			"server_salt":  result.ServerSalt,
			"access_hash":  result.AccessHash,
		}
		s.database.DB.Unscoped().Model(existingAcct).Updates(updates)
		existingAcct.Token = result.Token
		existingAcct.DisplayName = result.DisplayName
		existingAcct.Phone = result.Phone
		apiLog.Info("Updated existing %s account %d (user %d) with new token", providerType, existingAcct.ID, result.UserID)
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
	acct, err := s.database.CreateAccountWithProvider(result.Token, req.Role, result.UserID, providerType)
	if err != nil {
		apiLog.Warn("Failed to create %s account for user %d: %v", providerType, result.UserID, err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create account: %v", err))
		return
	}

	// Update display info + credentials
	updates := map[string]interface{}{
		"display_name": result.DisplayName,
		"phone":        result.Phone,
		"access_hash":  result.AccessHash,
		"auth_key":     result.AuthKey,
		"auth_key_id":  result.AuthKeyID,
		"server_salt":  result.ServerSalt,
	}
	s.database.DB.Model(acct).Updates(updates)

	bumpDataVersion()

	// Push to remote server
	if s.RemoteServerURL != "" {
		go s.pushAccountToRemote(acct)
	}

	apiLog.Info("Created new %s %s account %d (user %d, %s)", providerType, req.Role, acct.ID, result.UserID, result.Phone)
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
