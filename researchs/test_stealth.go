package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"soroush-relay/soroushlib"
)

type DBSoroushAccount struct {
	ID            string `gorm:"primaryKey;size:191"`
	PhoneNumber   string
	SoroushUserID int64
	AuthKey       []byte `gorm:"type:blob"`
	AuthKeyID     []byte `gorm:"type:blob"`
	ServerSalt    []byte `gorm:"type:blob"`
	Status        string
}

type DBTunnelConfig struct {
	ID              uint `gorm:"primaryKey"`
	GroupChatID     int64
	GroupAccessHash int64
	PSK             string
}

func main() {
	db, err := gorm.Open(sqlite.Open("client_config.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("DB: %v", err)
	}

	var account DBSoroushAccount
	if err := db.Where("status = ? AND length(auth_key) > 0", "connected").First(&account).Error; err != nil {
		log.Fatalf("No account: %v", err)
	}

	var cfg DBTunnelConfig
	db.First(&cfg)

	psk := soroushlib.DefaultPSK
	if cfg.PSK != "" {
		psk = []byte(cfg.PSK)
	}

	// Connect
	session, transport := soroushlib.RestoreSession(account.AuthKey, account.AuthKeyID, account.ServerSalt)
	ctx := context.Background()
	connCtx, connCancel := context.WithTimeout(ctx, 15*time.Second)
	if err := transport.Connect(connCtx); err != nil {
		connCancel()
		log.Fatalf("Connect: %v", err)
	}
	connCancel()
	defer transport.Disconnect()
	fmt.Println("✅ Connected")

	// Step 1: Send heartbeat wrapped in initConnection + SendAndWait
	fmt.Println("\n=== Sending heartbeat wrapped in initConnection ===")
	hb := soroushlib.NewHeartbeat(account.ID, account.SoroushUserID, 0, 0)
	encoded, err := soroushlib.EncodeGroupCommand(hb, psk)
	if err != nil {
		log.Fatalf("Encode: %v", err)
	}
	hbBody := soroushlib.BuildSendChannelMessage(cfg.GroupChatID, cfg.GroupAccessHash, encoded, time.Now().UnixNano())
	wrappedBody := soroushlib.WrapInitConnection(soroushlib.SoroushAppID, hbBody)

	sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)
	cid, _, err := session.SendAndWait(sendCtx, wrappedBody, true)
	sendCancel()
	if err != nil {
		fmt.Printf("❌ SendAndWait failed: %v\n", err)
	} else {
		fmt.Printf("✅ Heartbeat confirmed! Response CID=0x%08X\n", cid)
	}

	// Step 2: Send ping_delay_disconnect
	fmt.Println("\n=== Sending ping_delay_disconnect ===")
	pingBody := soroushlib.BuildPingDelayDisconnectRequest(time.Now().UnixNano(), 75)
	session.Send(ctx, pingBody, false)
	fmt.Println("✅ Ping sent")

	// Step 3: Test ListenForMessages (30s)
	fmt.Println("\n=== Testing ListenForMessages (30s) ===")
	listenCtx, listenCancel := context.WithTimeout(ctx, 30*time.Second)
	defer listenCancel()

	msgCount := 0
	err = soroushlib.ListenForMessages(listenCtx, session, func(msg soroushlib.IncomingMessage) {
		msgCount++
		if msg.IsGroup {
			fmt.Printf("  📩 Group msg from UID=%d in chat=%d: %s\n", msg.FromUserID, msg.ChatID, truncate(msg.Text, 60))
		} else {
			fmt.Printf("  📩 DM from UID=%d: %s\n", msg.FromUserID, truncate(msg.Text, 60))
		}
	})

	if err != nil {
		fmt.Printf("ListenForMessages ended: %v\n", err)
	} else {
		fmt.Println("ListenForMessages ended normally (context expired)")
	}
	fmt.Printf("Total messages received: %d\n", msgCount)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
