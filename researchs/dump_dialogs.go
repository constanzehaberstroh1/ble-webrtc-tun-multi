package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"soroush-relay/soroushlib"
)

type DBSoroushAccount struct {
	ID         string `gorm:"primaryKey"`
	AuthKey    []byte
	AuthKeyID  []byte
	ServerSalt []byte
}

func (DBSoroushAccount) TableName() string { return "db_soroush_accounts" }

func main() {
	// Load account from client DB
	db, err := gorm.Open(sqlite.Open("/home/salman/Projects/research/Sorush/soroush-relay/client_config.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	var acc DBSoroushAccount
	db.First(&acc)
	fmt.Printf("Account: %s, AuthKey len=%d\n", acc.ID, len(acc.AuthKey))

	session, transport := soroushlib.RestoreSession(acc.AuthKey, acc.AuthKeyID, acc.ServerSalt)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer transport.Disconnect()

	body := soroushlib.BuildGetDialogsRequest()
	wrappedBody := soroushlib.WrapInitConnection(soroushlib.SoroushAppID, body)

	// Start receiver
	type recvResult struct {
		cid    uint32
		reader *soroushlib.TLReader
		err    error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		cid, reader, err := session.Recv(ctx)
		recvCh <- recvResult{cid, reader, err}
	}()

	msgID, err := session.Send(ctx, wrappedBody, true)
	if err != nil {
		log.Fatalf("Send failed: %v", err)
	}
	fmt.Printf("Sent getDialogs, msgID=%d\n", msgID)

	for attempt := 0; attempt < 30; attempt++ {
		result := <-recvCh
		if result.err != nil {
			log.Fatalf("Recv failed: %v", result.err)
		}

		cid := result.cid
		r := result.reader

		fmt.Printf("\n=== Packet %d: CID=0x%08X ===\n", attempt, cid)

		// Handle rpc_result unwrapping
		if cid == soroushlib.IDRPCResult {
			r.ReadInt64() // msg_id
			innerCID, _ := r.ReadUint32()
			rem := r.Remaining()
			data, _ := r.ReadRaw(rem)
			fmt.Printf("  rpc_result -> innerCID=0x%08X, body=%d bytes\n", innerCID, len(data))

			// Dump full inner body
			fullData := make([]byte, 4+len(data))
			binary.LittleEndian.PutUint32(fullData, innerCID)
			copy(fullData[4:], data)

			dumpFile := "/home/salman/Projects/research/Sorush/soroush-relay/researchs/dialogs_dump.bin"
			os.WriteFile(dumpFile, fullData, 0644)
			fmt.Printf("  Dumped %d bytes to %s\n", len(fullData), dumpFile)

			// Search for "My lovely family" in raw bytes
			searchStr := "My lovely family"
			idx := strings.Index(string(fullData), searchStr)
			if idx >= 0 {
				fmt.Printf("\n  *** FOUND '%s' at byte offset %d! ***\n", searchStr, idx)
				start := max(0, idx-32)
				end := min(len(fullData), idx+len(searchStr)+32)
				fmt.Printf("  Context hex: %s\n", hex.EncodeToString(fullData[start:end]))
				fmt.Printf("  Context str: %q\n", string(fullData[start:end]))
			} else {
				fmt.Printf("  '%s' NOT found in raw bytes\n", searchStr)
				// Try case-insensitive
				lowerData := strings.ToLower(string(fullData))
				idx = strings.Index(lowerData, strings.ToLower(searchStr))
				if idx >= 0 {
					fmt.Printf("  *** FOUND (case-insensitive) at offset %d! ***\n", idx)
				}
			}

			// Scan for all string-like content
			fmt.Println("\n  === Scanning for readable strings ===")
			scanStrings(fullData)

			// Scan for vector markers
			fmt.Println("\n  === Vector markers (0x1CB5C415) ===")
			vecCID := [4]byte{0x15, 0xC4, 0xB5, 0x1C}
			for i := 0; i+4 <= len(fullData); i += 4 {
				if fullData[i] == vecCID[0] && fullData[i+1] == vecCID[1] &&
					fullData[i+2] == vecCID[2] && fullData[i+3] == vecCID[3] {
					count := int32(0)
					if i+8 <= len(fullData) {
						count = int32(binary.LittleEndian.Uint32(fullData[i+4 : i+8]))
					}
					fmt.Printf("  Vector at offset %d, count=%d\n", i, count)
				}
			}

			// Scan for chat/channel constructors
			fmt.Println("\n  === Chat/Channel constructors ===")
			knownCIDs := map[uint32]string{
				soroushlib.IDChat:             "chat",
				soroushlib.IDChannel:          "channel",
				soroushlib.IDChatForbidden:    "chatForbidden",
				soroushlib.IDChannelForbidden: "channelForbidden",
				soroushlib.IDDialogs:          "messages.dialogs",
				soroushlib.IDDialogsSlice:     "messages.dialogsSlice",
				soroushlib.IDDialog:           "dialog",
				soroushlib.IDPeerUser:         "peerUser",
				soroushlib.IDPeerChat:         "peerChat",
				soroushlib.IDPeerChannel:      "peerChannel",
				soroushlib.IDMessage:          "message",
			}
			for i := 0; i+4 <= len(fullData); i += 4 {
				v := binary.LittleEndian.Uint32(fullData[i:])
				if name, ok := knownCIDs[v]; ok {
					fmt.Printf("  0x%08X (%s) at offset %d\n", v, name, i)
				}
			}

			// Now try parsing with our actual parser
			fmt.Println("\n  === Trying ParseDialogsForGroups ===")
			innerReader := soroushlib.NewTLReader(data)
			groups, parseErr := soroushlib.ParseDialogsForGroups(innerCID, innerReader)
			if parseErr != nil {
				fmt.Printf("  Parse error: %v\n", parseErr)
			} else {
				fmt.Printf("  Parsed %d groups:\n", len(groups))
				for _, g := range groups {
					fmt.Printf("    - ID=%d, Title=%q, Type=%s, Members=%d\n", g.ID, g.Title, g.Type, g.MembersCount)
				}
			}
			return

		} else if cid == soroushlib.IDBadServerSalt {
			r.ReadInt64()
			r.ReadInt32()
			r.ReadInt32()
			newSalt, _ := r.ReadInt64()
			session.ServerSalt = newSalt
			fmt.Printf("  Bad salt -> updated to %d, retrying...\n", newSalt)
			go func() {
				cid, reader, err := session.Recv(ctx)
				recvCh <- recvResult{cid, reader, err}
			}()
			msgID, _ = session.Send(ctx, wrappedBody, true)
			continue
		} else if cid == soroushlib.IDNewSession {
			r.ReadInt64()
			r.ReadInt64()
			newSalt, _ := r.ReadInt64()
			session.ServerSalt = newSalt
			fmt.Printf("  New session -> salt=%d\n", newSalt)
			go func() {
				cid, reader, err := session.Recv(ctx)
				recvCh <- recvResult{cid, reader, err}
			}()
			continue
		} else if cid == soroushlib.IDMsgContainer {
			// Handle msg_container
			count, _ := r.ReadInt32()
			fmt.Printf("  msg_container with %d messages\n", count)
			for i := int32(0); i < count; i++ {
				r.ReadInt64() // msg_id
				r.ReadInt32() // seq
				bodyLen, _ := r.ReadInt32()
				subBody, _ := r.ReadRaw(int(bodyLen))
				subReader := soroushlib.NewTLReader(subBody)
				subCID, _ := subReader.ReadUint32()
				fmt.Printf("    sub[%d]: CID=0x%08X, len=%d\n", i, subCID, bodyLen)

				if subCID == soroushlib.IDRPCResult {
					subReader.ReadInt64()
					innerCID, _ := subReader.ReadUint32()
					rem := subReader.Remaining()
					data, _ := subReader.ReadRaw(rem)
					fmt.Printf("      rpc_result -> innerCID=0x%08X, body=%d bytes\n", innerCID, len(data))

					fullData := make([]byte, 4+len(data))
					binary.LittleEndian.PutUint32(fullData, innerCID)
					copy(fullData[4:], data)

					dumpFile := "/home/salman/Projects/research/Sorush/soroush-relay/researchs/dialogs_dump.bin"
					os.WriteFile(dumpFile, fullData, 0644)
					fmt.Printf("      Dumped %d bytes to %s\n", len(fullData), dumpFile)

					searchStr := "My lovely family"
					if idx := strings.Index(string(fullData), searchStr); idx >= 0 {
						fmt.Printf("\n      *** FOUND '%s' at byte offset %d! ***\n", searchStr, idx)
					}

					scanStrings(fullData)

					// Parse
					innerReader := soroushlib.NewTLReader(data)
					groups, parseErr := soroushlib.ParseDialogsForGroups(innerCID, innerReader)
					if parseErr != nil {
						fmt.Printf("      Parse error: %v\n", parseErr)
					} else {
						fmt.Printf("      Parsed %d groups:\n", len(groups))
						for _, g := range groups {
							fmt.Printf("        - ID=%d, Title=%q, Type=%s\n", g.ID, g.Title, g.Type)
						}
					}
					return
				} else if subCID == soroushlib.IDBadServerSalt {
					subReader.ReadInt64()
					subReader.ReadInt32()
					subReader.ReadInt32()
					newSalt, _ := subReader.ReadInt64()
					session.ServerSalt = newSalt
					fmt.Printf("      Bad salt -> updated to %d\n", newSalt)
				}
			}
			// Retry if we handled salt update inside container
			go func() {
				cid, reader, err := session.Recv(ctx)
				recvCh <- recvResult{cid, reader, err}
			}()
			msgID, _ = session.Send(ctx, wrappedBody, true)
			continue
		} else {
			fmt.Printf("  Unsolicited CID=0x%08X, ignoring...\n", cid)
			go func() {
				cid, reader, err := session.Recv(ctx)
				recvCh <- recvResult{cid, reader, err}
			}()
			continue
		}
	}
	fmt.Println("Timeout: no dialogs response after 30 attempts")
}

func scanStrings(data []byte) {
	// Find readable ASCII/UTF-8 strings of length >= 3
	i := 0
	for i < len(data) {
		b := data[i]
		// TL string encoding: if b < 254, length = b, data follows, then padding
		if b > 0 && b < 254 && int(b) >= 3 && i+1+int(b) <= len(data) {
			strBytes := data[i+1 : i+1+int(b)]
			// Check if it looks like a readable string
			readable := true
			for _, c := range strBytes {
				if c < 0x20 && c != 0x0A && c != 0x0D {
					// Allow UTF-8 high bytes
					if c < 0x80 {
						readable = false
						break
					}
				}
			}
			if readable {
				s := string(strBytes)
				// Filter out obvious non-strings
				if len(s) >= 3 {
					fmt.Printf("    String at offset %d (len=%d): %q\n", i, b, s)
				}
			}
		}
		i++
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
