package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/salman/ble-webrtc-tun/internal/db"
)

// handlePairings handles GET /api/pairings and POST /api/pairings.
func (s *Server) handlePairings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listPairings(w, r)
	case http.MethodPost:
		s.createPairing(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handlePairingByID handles operations on /api/pairings/{id}.
func (s *Server) handlePairingByID(w http.ResponseWriter, r *http.Request) {
	idStr := extractID(r.URL.Path, "/api/pairings/")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing pairing ID")
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pairing ID")
		return
	}

	switch r.Method {
	case http.MethodDelete:
		s.deletePairing(w, r, uint(id))
	case http.MethodPatch:
		s.updatePairing(w, r, uint(id))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAutoPair handles POST /api/pairings/auto.
func (s *Server) handleAutoPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		OwnerID string `json:"owner_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	count, err := s.manager.AutoPairUnmatched(req.OwnerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if count > 0 {
		bumpDataVersion()
		// Push new pairings to remote
		if s.RemoteServerURL != "" {
			go s.pushAllPairingsToRemote()
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"paired": count,
	})
}

// GET /api/pairings?owner_id=xxx
func (s *Server) listPairings(w http.ResponseWriter, r *http.Request) {
	ownerID := r.URL.Query().Get("owner_id")
	var pairings []db.Pairing
	var err error
	if ownerID != "" {
		pairings, err = s.manager.ListPairingsByOwner(ownerID)
	} else {
		pairings, err = s.manager.ListPairings()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pairings)
}

// POST /api/pairings { "client_account_id": 1, "server_account_id": 2, "owner_id": "xxx" }
func (s *Server) createPairing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientAccountID uint   `json:"client_account_id"`
		ServerAccountID uint   `json:"server_account_id"`
		OwnerID         string `json:"owner_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ClientAccountID == 0 || req.ServerAccountID == 0 {
		writeError(w, http.StatusBadRequest, "client_account_id and server_account_id are required")
		return
	}

	pairing, err := s.manager.CreatePairing(req.ClientAccountID, req.ServerAccountID, req.OwnerID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	bumpDataVersion()

	// Push pairing to remote server
	if s.RemoteServerURL != "" && pairing != nil {
		go s.pushPairingToRemote(pairing.ClientAccountID, pairing.ServerAccountID)
	}

	writeJSON(w, http.StatusCreated, pairing)
}

// DELETE /api/pairings/{id}
func (s *Server) deletePairing(w http.ResponseWriter, _ *http.Request, id uint) {
	// Get pairing info before deletion for remote sync
	pairingList, _ := s.manager.ListPairings()
	var clientProvType, serverProvType string
	var clientExtID, serverExtID int64
	for _, p := range pairingList {
		if p.ID == id {
			if p.ClientAccount != nil {
				clientProvType = p.ClientAccount.ProviderType
				if clientProvType == "" {
					clientProvType = "bale"
				}
				clientExtID = p.ClientAccount.ExternalID
				if clientExtID == 0 {
					clientExtID = p.ClientAccount.BaleUserID
				}
			}
			if p.ServerAccount != nil {
				serverProvType = p.ServerAccount.ProviderType
				if serverProvType == "" {
					serverProvType = "bale"
				}
				serverExtID = p.ServerAccount.ExternalID
				if serverExtID == 0 {
					serverExtID = p.ServerAccount.BaleUserID
				}
			}
			break
		}
	}

	if err := s.manager.RemovePairing(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	bumpDataVersion()

	// Push pairing delete to remote
	if s.RemoteServerURL != "" && clientExtID != 0 && serverExtID != 0 {
		go s.pushPairingDeleteToRemote(clientProvType, clientExtID, serverProvType, serverExtID)
	}

	writeOK(w, "pairing deleted")
}

// PATCH /api/pairings/{id} { "active": true|false }
func (s *Server) updatePairing(w http.ResponseWriter, r *http.Request, id uint) {
	var req struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Active != nil {
		if err := s.manager.SetPairingActive(id, *req.Active); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		bumpDataVersion()
	}

	writeOK(w, "pairing updated")
}

// pushPairingToRemote pushes a created pairing to the remote server.
func (s *Server) pushPairingToRemote(clientAccountID, serverAccountID uint) {
	clientAcct, _ := s.database.GetAccount(clientAccountID)
	serverAcct, _ := s.database.GetAccount(serverAccountID)
	if clientAcct == nil || serverAcct == nil {
		return
	}

	clientProv := clientAcct.ProviderType
	if clientProv == "" {
		clientProv = "bale"
	}
	clientExtID := clientAcct.ExternalID
	if clientExtID == 0 {
		clientExtID = clientAcct.BaleUserID
	}

	serverProv := serverAcct.ProviderType
	if serverProv == "" {
		serverProv = "bale"
	}
	serverExtID := serverAcct.ExternalID
	if serverExtID == 0 {
		serverExtID = serverAcct.BaleUserID
	}

	payload := map[string]interface{}{
		"client_provider_type": clientProv,
		"client_external_id":   clientExtID,
		"client_bale_user_id":  clientExtID, // backward compat
		"server_provider_type": serverProv,
		"server_external_id":   serverExtID,
		"server_bale_user_id":  serverExtID, // backward compat
	}
	body, _ := json.Marshal(payload)

	resp, err := s.proxyToRemote("POST", "/api/sync/pairing-created", bytes.NewReader(body))
	if err != nil {
		apiLog.Warn("Failed to push pairing to remote: %v", err)
		return
	}
	resp.Body.Close()
	apiLog.Info("Pushed pairing to remote (%s/%d ↔ %s/%d)", clientProv, clientExtID, serverProv, serverExtID)
}

// pushPairingDeleteToRemote notifies the remote server about a deleted pairing.
func (s *Server) pushPairingDeleteToRemote(clientProvType string, clientExtID int64, serverProvType string, serverExtID int64) {
	payload := map[string]interface{}{
		"client_provider_type": clientProvType,
		"client_external_id":   clientExtID,
		"client_bale_user_id":  clientExtID, // backward compat
		"server_provider_type": serverProvType,
		"server_external_id":   serverExtID,
		"server_bale_user_id":  serverExtID, // backward compat
	}
	body, _ := json.Marshal(payload)

	resp, err := s.proxyToRemote("POST", "/api/sync/pairing-deleted", bytes.NewReader(body))
	if err != nil {
		apiLog.Warn("Failed to push pairing delete to remote: %v", err)
		return
	}
	resp.Body.Close()
	apiLog.Info("Pushed pairing delete to remote (%s/%d ↔ %s/%d)", clientProvType, clientExtID, serverProvType, serverExtID)
}

// pushAllPairingsToRemote pushes all current pairings to the remote server.
func (s *Server) pushAllPairingsToRemote() {
	pairings, _ := s.database.ListPairings()
	for _, p := range pairings {
		if p.ClientAccount != nil && p.ServerAccount != nil {
			s.pushPairingToRemote(p.ClientAccountID, p.ServerAccountID)
		}
	}
}
