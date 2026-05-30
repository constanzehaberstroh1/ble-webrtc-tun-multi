package db

import (
	"fmt"
	gormlog "log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/salman/ble-webrtc-tun/internal/logger"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	instance *Database
	once     sync.Once
	dbLog    = logger.New("db")
)

// Database wraps the GORM DB connection with helper methods.
type Database struct {
	DB   *gorm.DB
	role string // "client" or "server"
	path string
}

// Init initializes the database singleton for the given role.
// The DB file is created at data/{role}.db relative to the working directory.
func Init(role string) (*Database, error) {
	var initErr error
	once.Do(func() {
		db, err := open(role)
		if err != nil {
			initErr = err
			return
		}
		instance = db
	})
	if initErr != nil {
		return nil, initErr
	}
	return instance, nil
}

// Get returns the database singleton. Panics if Init() hasn't been called.
func Get() *Database {
	if instance == nil {
		dbLog.Fatal("Database not initialized — call db.Init() first")
	}
	return instance
}

// open creates the SQLite database file and runs auto-migrations.
func open(role string) (*Database, error) {
	// Ensure data directory exists
	dataDir := "data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, role+".db")
	dbLog.Info("Opening database at %s", dbPath)

	// SQLite pragmas for performance + safety
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.New(
			gormlog.New(dbLog.ErrorWriter(), "", 0),
			gormlogger.Config{
				SlowThreshold:             200 * time.Millisecond,
				LogLevel:                  gormlogger.Warn,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		),
		// Disable default transaction wrapping for single queries (performance)
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Proactively handle SQLite ALTER TABLE NOT NULL / UNIQUE constraint issues for old databases
	if db.Migrator().HasTable(&Account{}) {
		if !db.Migrator().HasColumn(&Account{}, "external_id") {
			dbLog.Info("Performing custom pre-migration: adding column external_id...")
			if err := db.Exec(`ALTER TABLE accounts ADD COLUMN external_id INTEGER DEFAULT 0`).Error; err != nil {
				dbLog.Error("Failed pre-migration ADD COLUMN: %v", err)
			}
		}

		// Now the column definitely exists. Backfill it BEFORE AutoMigrate to ensure unique values!
		dbLog.Info("Performing pre-migration backfill for multi-provider external_id...")
		db.Exec(`UPDATE accounts SET provider_type = 'bale' WHERE provider_type = '' OR provider_type IS NULL`)
		db.Exec(`UPDATE accounts SET external_id = bale_user_id WHERE (external_id = 0 OR external_id IS NULL) AND bale_user_id != 0`)
	}

	// Auto-migrate all models
	if err := db.AutoMigrate(
		&Account{},
		&Pairing{},
		&ConnectionLog{},
		&Event{},
		&Setting{},
		&AdminUser{},
	); err != nil {
		return nil, fmt.Errorf("auto-migrate: %w", err)
	}

	// Backfill existing accounts to support multi-provider transition
	db.Exec(`UPDATE accounts SET provider_type = 'bale' WHERE provider_type = '' OR provider_type IS NULL`)
	db.Exec(`UPDATE accounts SET external_id = bale_user_id WHERE (external_id = 0 OR external_id IS NULL) AND bale_user_id != 0`)

	dbLog.Info("✅ Database ready (role=%s)", role)

	return &Database{
		DB:   db,
		role: role,
		path: dbPath,
	}, nil
}

// Role returns the database role (client or server).
func (d *Database) Role() string {
	return d.role
}

// Path returns the absolute path to the database file.
func (d *Database) Path() string {
	return d.path
}

// Close closes the underlying database connection.
func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
