package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// DBSoroushAccountSQLite matches client SQLite schema
type DBSoroushAccountSQLite struct {
	ID            string `gorm:"primaryKey;size:191"`
	PhoneNumber   string `gorm:"uniqueIndex;size:191;not null"`
	Name          string `gorm:"not null"`
	SoroushUserID int64
	AccessHash    int64
	DisplayName   string
	AuthKey       []byte `gorm:"type:blob"`
	AuthKeyID     []byte `gorm:"type:blob"`
	ServerSalt    []byte `gorm:"type:blob"`
	SessionData   string `gorm:"type:text"`
	DcID          int
	Status        string `gorm:"default:'idle'"`
	LastActive    string
}

func (DBSoroushAccountSQLite) TableName() string {
	return "db_soroush_accounts"
}

// DBSoroushAccountMySQL matches server MySQL schema
type DBSoroushAccountMySQL struct {
	ID            string `gorm:"primaryKey;size:191"`
	PhoneNumber   string `gorm:"uniqueIndex;size:191;not null"`
	Name          string `gorm:"not null"`
	SoroushUserID int64
	AccessHash    int64
	DisplayName   string
	AuthKey       []byte `gorm:"type:blob"`
	AuthKeyID     []byte `gorm:"type:blob"`
	ServerSalt    []byte `gorm:"type:blob"`
	SessionData   string `gorm:"type:text"`
	DcID          int
	Role          string `gorm:"default:''"`
	Status        string `gorm:"default:'idle'"`
	LastActive    string
}

func (DBSoroushAccountMySQL) TableName() string {
	return "db_soroush_accounts"
}

func main() {
	// Active Soroush Hex AuthKey from Thorium LocalStorage dc2_auth_key
	activeKeyHex := "0f8d71b5141eec7e71051430184a149ccc33d68986a815bfa9e3df364fe478c481427b57c44855351aa99230f94c3737d429368503e1ac02dc9b758fd5cc68be86505e797a48533e80740487905d9f5708d571d7322c2eabc36b47c6298195ed195d9f1446f9c0053fb041f920fb9a5b81e075053e7549dde044a3783e9e26af94c620df7221d1f82c90c7f7900e6ad6af0c517b798a879250eb83d87afea10ee73ef93d84f7cc5f19bcfd712725b7f75898402dec9b5c309a8982166070e47c9f77b6ff72957f6eb119bc9179bb9bbe24884d59499ff6fce1482be506f39327cae23d6f8fc41bbb2d02ec04b8962694fbdd9e9b55abd82d1cb284b023db9a46"
	
	authKey, err := hex.DecodeString(activeKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode hex active key: %v", err)
	}

	// Calculate AuthKeyID: lower 8 bytes (little-endian) of SHA1(auth_key)
	// Equivalent to akHash[12:20]
	shaSum := sha1.Sum(authKey)
	authKeyID := shaSum[12:20]

	// Create 8 bytes of zero server salt (Go client will update it on retry)
	serverSalt := make([]byte, 8)

	fmt.Printf("Parsed Active AuthKey (len=%d)\n", len(authKey))
	fmt.Printf("Calculated AuthKeyID: %x\n", authKeyID)

	// 1. Update SQLite Database (Client Config)
	fmt.Println("\n[SQLite] Connecting to client_config.db ...")
	dbSqlite, err := gorm.Open(sqlite.Open("/home/salman/Projects/research/Sorush/soroush-relay/client_config.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to SQLite: %v", err)
	}

	var sqliteAccounts []DBSoroushAccountSQLite
	dbSqlite.Find(&sqliteAccounts)
	fmt.Printf("Found %d accounts in SQLite.\n", len(sqliteAccounts))

	for _, acc := range sqliteAccounts {
		fmt.Printf("Updating SQLite account: ID=%s, Phone=%s, Name=%s ...\n", acc.ID, acc.PhoneNumber, acc.Name)
		acc.AuthKey = authKey
		acc.AuthKeyID = authKeyID
		acc.ServerSalt = serverSalt
		acc.DcID = 2
		
		if err := dbSqlite.Save(&acc).Error; err != nil {
			log.Printf("Failed to update account in SQLite: %v\n", err)
		} else {
			fmt.Println("SQLite account updated successfully.")
		}
	}

	// 2. Update MySQL Database (Server Exit Node Config)
	fmt.Println("\n[MySQL] Connecting to Clever Cloud MySQL ...")
	dsn := "ubbjvpmkfqpwo1ku:gJ1RsKBEuzuh0rm5qIl6@tcp(bqgalqe1hnsoyltraetp-mysql.services.clever-cloud.com:3306)/bqgalqe1hnsoyltraetp?charset=utf8mb4&parseTime=True&loc=Local"
	dbMysql, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}

	var mysqlAccounts []DBSoroushAccountMySQL
	dbMysql.Find(&mysqlAccounts)
	fmt.Printf("Found %d accounts in MySQL.\n", len(mysqlAccounts))

	for _, acc := range mysqlAccounts {
		fmt.Printf("Updating MySQL account: ID=%s, Phone=%s, Name=%s ...\n", acc.ID, acc.PhoneNumber, acc.Name)
		acc.AuthKey = authKey
		acc.AuthKeyID = authKeyID
		acc.ServerSalt = serverSalt
		acc.DcID = 2

		if err := dbMysql.Save(&acc).Error; err != nil {
			log.Printf("Failed to update account in MySQL: %v\n", err)
		} else {
			fmt.Println("MySQL account updated successfully.")
		}
	}

	fmt.Println("\n[DONE] Both databases are now synchronized with the active session key!")
}
