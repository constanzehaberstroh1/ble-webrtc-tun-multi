package main

import (
	"context"
	"encoding/binary"
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
	fmt.Printf("Account: %s (UID=%d)\n", account.PhoneNumber, account.SoroushUserID)

	var cfg DBTunnelConfig
	db.First(&cfg)
	fmt.Printf("Group: ChatID=%d AccessHash=%d\n", cfg.GroupChatID, cfg.GroupAccessHash)

	// Connect
	session, transport := soroushlib.RestoreSession(account.AuthKey, account.AuthKeyID, account.ServerSalt)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := transport.Connect(ctx); err != nil {
		cancel()
		log.Fatalf("Connect: %v", err)
	}
	cancel()
	defer transport.Disconnect()
	fmt.Println("✅ Connected to Soroush WebSocket")

	// Build a simple test message
	text := fmt.Sprintf("relay-test-%d", time.Now().Unix())
	fmt.Printf("Sending test message to group %d: %q\n", cfg.GroupChatID, text)

	body := soroushlib.BuildSendChannelMessage(cfg.GroupChatID, cfg.GroupAccessHash, text, time.Now().UnixNano())

	// Send and WAIT for response
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer sendCancel()

	// Start recv loop BEFORE sending
	type recvResult struct {
		cid    uint32
		reader *soroushlib.TLReader
		raw    []byte
		err    error
	}
	recvCh := make(chan recvResult, 5)
	go func() {
		for i := 0; i < 5; i++ { // read up to 5 responses
			cid, reader, err := session.Recv(sendCtx)
			if err != nil {
				recvCh <- recvResult{err: err}
				return
			}
			// Get raw bytes for analysis
			rem := reader.Remaining()
			raw, _ := reader.ReadRaw(rem)
			recvCh <- recvResult{cid: cid, reader: soroushlib.NewTLReader(raw), raw: raw}
		}
	}()

	msgID, err := session.Send(sendCtx, body, true)
	if err != nil {
		log.Fatalf("Send error: %v", err)
	}
	fmt.Printf("Sent! MsgID=%d, waiting for response...\n", msgID)

	// Read responses
	for i := 0; i < 5; i++ {
		select {
		case res := <-recvCh:
			if res.err != nil {
				fmt.Printf("  Recv error: %v\n", res.err)
				return
			}
			fmt.Printf("\n  Response #%d: CID=0x%08X (%d bytes)\n", i+1, res.cid, len(res.raw))

			// Decode known CIDs
			switch res.cid {
			case soroushlib.IDRPCResult:
				r := res.reader
				reqMsgID, _ := r.ReadInt64()
				innerCID, _ := r.ReadUint32()
				fmt.Printf("    rpc_result for msg=%d, inner CID=0x%08X\n", reqMsgID, innerCID)

				if innerCID == soroushlib.IDRPCError {
					errorCode, _ := r.ReadInt32()
					errorMsg, _ := r.ReadString()
					fmt.Printf("    ❌ RPC ERROR %d: %s\n", errorCode, errorMsg)
				} else if innerCID == soroushlib.IDUpdateShortSentMessage {
					fmt.Printf("    ✅ Message sent successfully! (updateShortSentMessage)\n")
				} else {
					fmt.Printf("    Inner response CID=0x%08X\n", innerCID)
					// Dump remaining bytes
					remBytes := r.Remaining()
					data, _ := r.ReadRaw(remBytes)
					if len(data) > 64 {
						data = data[:64]
					}
					fmt.Printf("    Raw: %x\n", data)
				}

			case soroushlib.IDBadServerSalt:
				r := res.reader
				r.ReadInt64() // bad_msg_id
				r.ReadInt32() // seq
				r.ReadInt32() // error_code
				newSalt, _ := r.ReadInt64()
				session.ServerSalt = newSalt
				fmt.Printf("    Bad server salt → updated to %d, re-sending...\n", newSalt)

				// Re-send with correct salt
				body = soroushlib.BuildSendChannelMessage(cfg.GroupChatID, cfg.GroupAccessHash, text, time.Now().UnixNano())
				msgID, _ = session.Send(sendCtx, body, true)
				fmt.Printf("    Re-sent with MsgID=%d\n", msgID)

			case soroushlib.IDNewSession:
				r := res.reader
				r.ReadInt64() // first_msg_id
				r.ReadInt64() // unique_id
				newSalt, _ := r.ReadInt64()
				session.ServerSalt = newSalt
				fmt.Printf("    New session created, salt=%d\n", newSalt)

			case soroushlib.IDMsgsAck:
				fmt.Printf("    msgs_ack (acknowledged)\n")

			case soroushlib.IDMsgContainer:
				r := res.reader
				count, _ := r.ReadInt32()
				fmt.Printf("    msg_container with %d messages:\n", count)
				for j := int32(0); j < count; j++ {
					subMsgID, _ := r.ReadInt64()
					seqNo, _ := r.ReadInt32()
					bodyLen, _ := r.ReadInt32()
					subBody, _ := r.ReadRaw(int(bodyLen))
					if len(subBody) >= 4 {
						subCID := binary.LittleEndian.Uint32(subBody[:4])
						fmt.Printf("      [%d] MsgID=%d seq=%d CID=0x%08X (%d bytes)\n", j, subMsgID, seqNo, subCID, bodyLen)

						if subCID == soroushlib.IDRPCResult && len(subBody) >= 16 {
							innerCID := binary.LittleEndian.Uint32(subBody[12:16])
							fmt.Printf("        rpc_result inner CID=0x%08X\n", innerCID)
							if innerCID == soroushlib.IDRPCError && len(subBody) >= 20 {
								errCode := int32(binary.LittleEndian.Uint32(subBody[16:20]))
								// Read error string
								sr := soroushlib.NewTLReader(subBody[20:])
								errMsg, _ := sr.ReadString()
								fmt.Printf("        ❌ RPC ERROR %d: %s\n", errCode, errMsg)
							} else if innerCID == soroushlib.IDUpdateShortSentMessage {
								fmt.Printf("        ✅ Message sent successfully!\n")
							}
						}
					}
				}

			default:
				fmt.Printf("    Unknown CID, hex dump: ")
				if len(res.raw) > 32 {
					fmt.Printf("%x...\n", res.raw[:32])
				} else {
					fmt.Printf("%x\n", res.raw)
				}
			}

		case <-time.After(10 * time.Second):
			fmt.Println("  Timeout waiting for more responses")
			return
		}
	}
}
