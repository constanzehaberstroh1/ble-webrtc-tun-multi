package db

import (
	"crypto/sha256"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// HashToken generates a short SHA256 hash prefix for display (first 8 hex chars).
func HashToken(token string) string {
	if token == "" || token == "backup-placeholder" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash[:4])
}

// CreateAccount adds a new Bale account to the database.
// If a soft-deleted account with the same BaleUserID exists, it is restored and updated.
// Returns the created/restored account with its ID populated.
func (d *Database) CreateAccount(token string, role string, baleUserID int64) (*Account, error) {
	return d.CreateAccountWithProvider(token, role, baleUserID, "bale")
}

// CreateAccountWithProvider adds a new account for a specific provider.
func (d *Database) CreateAccountWithProvider(token string, role string, externalID int64, providerType string) (*Account, error) {
	tokenHash := HashToken(token)

	var acct Account
	err := d.DB.Unscoped().Where("provider_type = ? AND external_id = ?", providerType, externalID).First(&acct).Error
	if err == nil {
		// Found existing record. If it's not soft-deleted, it's a conflict.
		if !acct.DeletedAt.Valid {
			return nil, fmt.Errorf("account already exists")
		}
		
		// It is soft-deleted. Restore and update it.
		updates := map[string]interface{}{
			"deleted_at": nil, // Restore
			"token":      token,
			"token_hash": tokenHash,
			"role":       role,
			"status":     StatusIdle,
			"enabled":    true,
		}
		if providerType == "bale" {
			updates["bale_user_id"] = externalID
		}
		if err := d.DB.Unscoped().Model(&acct).UpdateColumns(updates).Error; err != nil {
			return nil, fmt.Errorf("restoring soft-deleted account: %w", err)
		}
		
		// Fetch the restored account to ensure all fields (like created_at) are fresh
		d.DB.First(&acct, acct.ID)
		return &acct, nil
	} else if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("checking existing account: %w", err)
	}

	acct = Account{
		ProviderType: providerType,
		ExternalID:   externalID,
		Token:        token,
		TokenHash:    tokenHash,
		Role:         role,
		Status:       StatusIdle,
		Enabled:      true,
	}
	if providerType == "bale" {
		acct.BaleUserID = externalID
	}

	if err := d.DB.Create(&acct).Error; err != nil {
		return nil, fmt.Errorf("creating account: %w", err)
	}
	return &acct, nil
}

// GetAccount retrieves an account by ID.
func (d *Database) GetAccount(id uint) (*Account, error) {
	var acct Account
	if err := d.DB.First(&acct, id).Error; err != nil {
		return nil, err
	}
	return &acct, nil
}

// GetAccountByExternalID retrieves an account by its provider type and external ID.
func (d *Database) GetAccountByExternalID(providerType string, externalID int64) (*Account, error) {
	var acct Account
	if err := d.DB.Where("provider_type = ? AND external_id = ?", providerType, externalID).First(&acct).Error; err != nil {
		return nil, err
	}
	return &acct, nil
}

// GetAccountByExternalIDUnscoped retrieves an account by its provider type and external ID,
// including soft-deleted records.
func (d *Database) GetAccountByExternalIDUnscoped(providerType string, externalID int64) (*Account, error) {
	var acct Account
	if err := d.DB.Unscoped().Where("provider_type = ? AND external_id = ?", providerType, externalID).First(&acct).Error; err != nil {
		return nil, err
	}
	return &acct, nil
}

// GetAccountByBaleUserID retrieves an account by its Bale user ID.
func (d *Database) GetAccountByBaleUserID(baleUserID int64) (*Account, error) {
	return d.GetAccountByExternalID("bale", baleUserID)
}

// GetAccountByBaleUserIDUnscoped retrieves an account by its Bale user ID,
// including soft-deleted records.
func (d *Database) GetAccountByBaleUserIDUnscoped(baleUserID int64) (*Account, error) {
	return d.GetAccountByExternalIDUnscoped("bale", baleUserID)
}

// ListAccounts returns all accounts, optionally filtered by role.
func (d *Database) ListAccounts(role string) ([]Account, error) {
	var accounts []Account
	query := d.DB.Order("created_at ASC")
	if role != "" {
		query = query.Where("role = ?", role)
	}
	if err := query.Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// ListEnabledAccounts returns all enabled accounts for a given role.
func (d *Database) ListEnabledAccounts(role string) ([]Account, error) {
	var accounts []Account
	if err := d.DB.Where("role = ? AND enabled = ?", role, true).
		Order("created_at ASC").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// ListEnabledAccountsByProvider returns all enabled accounts for a given role and provider type.
func (d *Database) ListEnabledAccountsByProvider(role string, providerType string) ([]Account, error) {
	var accounts []Account
	if err := d.DB.Where("role = ? AND provider_type = ? AND enabled = ?", role, providerType, true).
		Order("created_at ASC").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// UpdateAccount updates specific fields on an account.
func (d *Database) UpdateAccount(id uint, updates map[string]interface{}) error {
	return d.DB.Model(&Account{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateAccountInfo updates the display name, phone, and access hash.
func (d *Database) UpdateAccountInfo(id uint, displayName, phone string, accessHash int64) error {
	updates := map[string]interface{}{
		"access_hash": accessHash,
		"last_seen":   time.Now(),
	}
	if displayName != "" {
		updates["display_name"] = displayName
	}
	if phone != "" {
		updates["phone"] = phone
	}
	return d.DB.Model(&Account{}).Where("id = ?", id).Updates(updates).Error
}

// SetAccountStatus atomically updates the status of an account.
func (d *Database) SetAccountStatus(id uint, status string) error {
	return d.DB.Model(&Account{}).Where("id = ?", id).Update("status", status).Error
}

// SetAccountEnabled enables or disables an account.
func (d *Database) SetAccountEnabled(id uint, enabled bool) error {
	return d.DB.Model(&Account{}).Where("id = ?", id).Update("enabled", enabled).Error
}

// SetAccountError marks an account with an error status and message.
func (d *Database) SetAccountError(id uint, errMsg string) error {
	return d.DB.Model(&Account{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":     StatusError,
		"last_error": errMsg,
	}).Error
}

// DeleteAccount soft-deletes an account.
func (d *Database) DeleteAccount(id uint) error {
	return d.DB.Delete(&Account{}, id).Error
}

// CountAccounts returns the number of accounts by role and status.
func (d *Database) CountAccounts(role, status string) (int64, error) {
	var count int64
	query := d.DB.Model(&Account{})
	if role != "" {
		query = query.Where("role = ?", role)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// ReserveIdleServerAccount atomically finds an IDLE server account and sets it to RESERVED.
// Returns the reserved account, or nil if none available.
// Uses a database-level atomic update to prevent race conditions.
func (d *Database) ReserveIdleServerAccount() (*Account, error) {
	var acct Account

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// Find first IDLE + enabled server account
		if err := tx.Where("role = ? AND status = ? AND enabled = ?", RoleServer, StatusIdle, true).
			Order("updated_at ASC"). // prefer least recently used
			First(&acct).Error; err != nil {
			return err // includes gorm.ErrRecordNotFound
		}

		// Atomically reserve it (double-check status in WHERE to prevent TOCTOU)
		result := tx.Model(&Account{}).
			Where("id = ? AND status = ?", acct.ID, StatusIdle).
			Update("status", StatusReserved)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("account %d was reserved by another goroutine", acct.ID)
		}

		acct.Status = StatusReserved
		return nil
	})

	if err != nil {
		return nil, err
	}
	return &acct, nil
}

// ResetAllStatuses sets all accounts to IDLE on startup (clean state).
func (d *Database) ResetAllStatuses() error {
	return d.DB.Model(&Account{}).
		Where("status IN ?", []string{StatusReserved, StatusInCall}).
		Update("status", StatusIdle).Error
}

// TouchAccount updates the last_seen timestamp.
func (d *Database) TouchAccount(id uint) error {
	now := time.Now()
	return d.DB.Model(&Account{}).Where("id = ?", id).Update("last_seen", &now).Error
}
