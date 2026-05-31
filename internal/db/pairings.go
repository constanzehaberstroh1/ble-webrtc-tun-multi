package db

import (
	"fmt"

	"gorm.io/gorm"
)

// CreatePairing links a client account to a server account.
// Enforces: each client account pairs with at most one server account,
// and each server account pairs with at most one client account.
// OwnerID tracks which client machine owns this pairing.
func (d *Database) CreatePairing(clientAccountID, serverAccountID uint, ownerID string) (*Pairing, error) {
	// Validate accounts exist and have correct roles
	var client, server Account
	if err := d.DB.First(&client, clientAccountID).Error; err != nil {
		return nil, fmt.Errorf("client account %d not found: %w", clientAccountID, err)
	}
	if client.Role != RoleClient {
		return nil, fmt.Errorf("account %d is not a CLIENT account", clientAccountID)
	}
	if err := d.DB.First(&server, serverAccountID).Error; err != nil {
		return nil, fmt.Errorf("server account %d not found: %w", serverAccountID, err)
	}
	if server.Role != RoleServer {
		return nil, fmt.Errorf("account %d is not a SERVER account", serverAccountID)
	}

	clientProv := client.ProviderType
	if clientProv == "" {
		clientProv = "bale"
	}
	serverProv := server.ProviderType
	if serverProv == "" {
		serverProv = "bale"
	}
	if clientProv != serverProv {
		return nil, fmt.Errorf("provider mismatch: cannot pair %s client with %s server", clientProv, serverProv)
	}

	// Enforce exclusivity: server account must not be actively paired by another owner
	var existingPairing Pairing
	err := d.DB.Where("server_account_id = ? AND active = ? AND owner_id != ?", serverAccountID, true, ownerID).
		First(&existingPairing).Error
	if err == nil {
		return nil, fmt.Errorf("server account %d is already paired by another client (owner: %s)", serverAccountID, existingPairing.OwnerID)
	}

	pairing := &Pairing{
		ClientAccountID: clientAccountID,
		ServerAccountID: serverAccountID,
		OwnerID:         ownerID,
		Active:          true,
	}

	if err := d.DB.Create(pairing).Error; err != nil {
		return nil, fmt.Errorf("creating pairing: %w", err)
	}
	return pairing, nil
}

// GetPairing retrieves a pairing by ID with associated accounts.
func (d *Database) GetPairing(id uint) (*Pairing, error) {
	var pairing Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		First(&pairing, id).Error; err != nil {
		return nil, err
	}
	return &pairing, nil
}

// ListPairings returns all pairings with their associated accounts.
func (d *Database) ListPairings() ([]Pairing, error) {
	var pairings []Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Order("created_at ASC").
		Find(&pairings).Error; err != nil {
		return nil, err
	}
	return pairings, nil
}

// ListPairingsByOwner returns pairings belonging to a specific owner.
func (d *Database) ListPairingsByOwner(ownerID string) ([]Pairing, error) {
	var pairings []Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Where("owner_id = ?", ownerID).
		Order("created_at ASC").
		Find(&pairings).Error; err != nil {
		return nil, err
	}
	return pairings, nil
}

// ListActivePairings returns only active pairings with accounts.
func (d *Database) ListActivePairings() ([]Pairing, error) {
	var pairings []Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Where("active = ?", true).
		Order("created_at ASC").
		Find(&pairings).Error; err != nil {
		return nil, err
	}
	return pairings, nil
}

// ListActivePairingsByOwner returns active pairings for a specific owner.
func (d *Database) ListActivePairingsByOwner(ownerID string) ([]Pairing, error) {
	var pairings []Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Where("active = ? AND owner_id = ?", true, ownerID).
		Order("created_at ASC").
		Find(&pairings).Error; err != nil {
		return nil, err
	}
	return pairings, nil
}

// GetPairingByServerAccount finds the pairing for a given server account.
func (d *Database) GetPairingByServerAccount(serverAccountID uint) (*Pairing, error) {
	var pairing Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Where("server_account_id = ? AND active = ?", serverAccountID, true).
		First(&pairing).Error; err != nil {
		return nil, err
	}
	return &pairing, nil
}

// GetPairingByClientAccount finds the pairing for a given client account.
func (d *Database) GetPairingByClientAccount(clientAccountID uint) (*Pairing, error) {
	var pairing Pairing
	if err := d.DB.Preload("ClientAccount").Preload("ServerAccount").
		Where("client_account_id = ? AND active = ?", clientAccountID, true).
		First(&pairing).Error; err != nil {
		return nil, err
	}
	return &pairing, nil
}

// DeletePairing removes a pairing.
func (d *Database) DeletePairing(id uint) error {
	return d.DB.Delete(&Pairing{}, id).Error
}

// SetPairingActive activates or deactivates a pairing.
func (d *Database) SetPairingActive(id uint, active bool) error {
	return d.DB.Model(&Pairing{}).Where("id = ?", id).Update("active", active).Error
}

// AutoPairUnmatched automatically pairs unmatched client and server accounts
// that belong to a specific owner.
// Pairs them in order of creation (oldest first).
// Returns the number of new pairings created.
func (d *Database) AutoPairUnmatched(ownerID string) (int, error) {
	var count int

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// Find unpaired client accounts belonging to this owner
		var unpairedClients []Account
		if err := tx.Where("role = ? AND enabled = ? AND id NOT IN (?)",
			RoleClient, true,
			tx.Model(&Pairing{}).Where("active = ? AND owner_id = ?", true, ownerID).Select("client_account_id"),
		).Order("created_at ASC").Find(&unpairedClients).Error; err != nil {
			return err
		}

		// Find server accounts NOT actively paired by ANY owner
		var availableServers []Account
		if err := tx.Where("role = ? AND enabled = ? AND id NOT IN (?)",
			RoleServer, true,
			tx.Model(&Pairing{}).Where("active = ?", true).Select("server_account_id"),
		).Order("created_at ASC").Find(&availableServers).Error; err != nil {
			return err
		}

		// Pair them 1:1 matching provider type
		for _, clientAcct := range unpairedClients {
			clientProv := clientAcct.ProviderType
			if clientProv == "" {
				clientProv = "bale"
			}

			// Find first available server with same provider type
			serverIdx := -1
			for idx, serverAcct := range availableServers {
				serverProv := serverAcct.ProviderType
				if serverProv == "" {
					serverProv = "bale"
				}
				if clientProv == serverProv {
					serverIdx = idx
					break
				}
			}

			// If matched, pair them
			if serverIdx != -1 {
				matchedServer := availableServers[serverIdx]
				
				// Remove matched server from available list
				availableServers = append(availableServers[:serverIdx], availableServers[serverIdx+1:]...)

				pairing := &Pairing{
					ClientAccountID: clientAcct.ID,
					ServerAccountID: matchedServer.ID,
					OwnerID:         ownerID,
					Active:          true,
				}
				if err := tx.Create(pairing).Error; err != nil {
					return err
				}
				count++
			}
		}

		return nil
	})

	return count, err
}

// GetAvailableServerAccounts returns server accounts that are NOT actively paired
// by any owner OTHER than the specified one. This means:
// - Unpaired server accounts are included
// - Server accounts already paired by the requesting owner are included
// - Server accounts paired by a DIFFERENT owner are excluded
func (d *Database) GetAvailableServerAccounts(ownerID string) ([]Account, error) {
	var accounts []Account



	if err := d.DB.Where("role = ? AND enabled = ?",
		RoleServer, true,
	).Order("created_at ASC").Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// GetUnpairedAccounts returns accounts that don't have an active pairing.
func (d *Database) GetUnpairedAccounts(role string) ([]Account, error) {
	var accounts []Account
	var subQuery *gorm.DB

	if role == RoleClient {
		subQuery = d.DB.Model(&Pairing{}).Where("active = ?", true).Select("client_account_id")
	} else {
		subQuery = d.DB.Model(&Pairing{}).Where("active = ?", true).Select("server_account_id")
	}

	if err := d.DB.Where("role = ? AND enabled = ? AND id NOT IN (?)", role, true, subQuery).
		Order("created_at ASC").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}
