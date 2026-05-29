package soroush

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// MTProto constructor IDs for messaging (Soroush / Telegram-derived)
// ──────────────────────────────────────────────────────────────────────────────


const (
	// messages.sendMessage — 0x280D096F (TL schema)
	IDSendMessage uint32 = 0x280D096F

	// messages.getDialogs — 0xA0F4CB4F (Soroush layer 182)
	IDGetDialogs uint32 = 0xA0F4CB4F

	// InputPeerUser — 0xDDE8A54C (Soroush layer 182)
	IDInputPeerUser uint32 = 0xDDE8A54C

	// InputPeerChat — 0x35A95CB9 (for group chats)
	IDInputPeerChat uint32 = 0x35A95CB9

	// PeerUser — 0x59511722
	IDPeerUser uint32 = 0x59511722

	// PeerChat — 0x36C6019A (group chat peer identifier)
	IDPeerChat uint32 = 0x36C6019A

	// updateShortMessage — 0x313BC7F8
	IDUpdateShortMessage uint32 = 0x313BC7F8

	// updateShort — 0x78D4DEC1
	IDUpdateShort uint32 = 0x78D4DEC1

	// updates — 0x74AE4240
	IDUpdates uint32 = 0x74AE4240

	// updatesTooLong — 0xE317AF7E
	IDUpdatesTooLong uint32 = 0xE317AF7E

	// updateNewMessage — 0x1F2B0AFD
	IDUpdateNewMessage uint32 = 0x1F2B0AFD

	// message — 0x38116EE0
	IDMessage uint32 = 0x38116EE0

	// updateShortSentMessage — 0x9015E101
	IDUpdateShortSentMessage uint32 = 0x9015E101

	// InputPeerEmpty — 0x7F3B18EA
	IDInputPeerEmpty uint32 = 0x7F3B18EA

	// messages.dialogs — 0x15BA6C40
	IDDialogs uint32 = 0x15BA6C40

	// messages.dialogsSlice — 0x71E094F3
	IDDialogsSlice uint32 = 0x71E094F3

	// dialog — 0xD58A08C6
	IDDialog uint32 = 0xD58A08C6

	// PeerChannel — 0xA2A5371E
	IDPeerChannel uint32 = 0xA2A5371E

	// InputPeerChannel — 0x27BCBBFC (for sending to channels/supergroups)
	IDInputPeerChannel uint32 = 0x27BCBBFC

	// updateNewChannelMessage — 0x62BA04D9
	IDUpdateNewChannelMessage uint32 = 0x62BA04D9

	// chat — 0x41CBF256
	IDChat uint32 = 0x41CBF256

	// chatForbidden — 0x6592A1A7
	IDChatForbidden uint32 = 0x6592A1A7

	// channel — 0x8E87CCD8 (Soroush layer 182)
	IDChannel uint32 = 0x8E87CCD8

	// channelForbidden — 0x17D493D5
	IDChannelForbidden uint32 = 0x17D493D5
)

// ──────────────────────────────────────────────────────────────────────────────
// Build messages.getDialogs TL payload
// ──────────────────────────────────────────────────────────────────────────────

// DialogInfo represents a chat/group from the user's dialog list
type DialogInfo struct {
	ID           int64  `json:"id"`
	Title        string `json:"title"`
	Type         string `json:"type"` // "group", "channel", "supergroup"
	MembersCount int32  `json:"membersCount"`
	AccessHash   int64  `json:"accessHash"`
}

// BuildGetDialogsRequest builds a messages.getDialogs request
// This fetches the user's chat list (groups, channels, DMs)
func BuildGetDialogsRequest() []byte {
	w := NewTLWriter()
	w.WriteUint32(IDGetDialogs)

	// flags = 0 (no exclude_pinned, folder_id, etc.)
	w.WriteInt32(0)

	// offset_date = 0
	w.WriteInt32(0)

	// offset_id = 0
	w.WriteInt32(0)

	// offset_peer = InputPeerEmpty
	w.WriteUint32(IDInputPeerEmpty)

	// limit = 100
	w.WriteInt32(100)

	// hash = 0
	w.WriteInt64(0)

	return w.GetBytes()
}

// ParseDialogsForGroups extracts group chats from a messages.getDialogs response.
// The response contains multiple vectors (dialogs, messages, chats, users), but
// message objects can also contain nested vectors (entities, reactions, etc.).
// So we can't simply count vector markers — instead we find the vector whose
// first element is a chat/channel constructor.
func ParseDialogsForGroups(cid uint32, r *TLReader) ([]DialogInfo, error) {
	if cid == IDRPCError {
		return nil, ParseRPCError(r)
	}

	if cid != IDDialogs && cid != IDDialogsSlice {
		return nil, fmt.Errorf("unexpected response cid=0x%08X for getDialogs", cid)
	}

	// Get raw remaining bytes from the reader
	raw := r.data[r.pos:]
	log.Printf("[Dialogs] Response CID=0x%08X, remaining payload=%d bytes", cid, len(raw))

	// For dialogsSlice, skip the count field (4 bytes) first
	offset := 0
	if cid == IDDialogsSlice {
		if len(raw) < 4 {
			return nil, fmt.Errorf("dialogsSlice: too short for count field")
		}
		count := int32(binary.LittleEndian.Uint32(raw[0:4]))
		log.Printf("[Dialogs] dialogsSlice total count=%d", count)
		offset = 4
	}

	// Chat/channel constructor IDs that indicate a chats vector
	chatCIDs := map[uint32]bool{
		IDChat: true, IDChannel: true,
		IDChatForbidden: true, IDChannelForbidden: true,
		0x29562865: true, // chatEmpty
	}

	// Scan for vector constructor markers (0x1CB5C415) and find the one
	// whose first element is a chat/channel constructor
	vectorCID := [4]byte{0x15, 0xC4, 0xB5, 0x1C}
	chatsStart := -1
	chatsEnd := len(raw)
	nextVecAfterChats := -1

	var allVecPositions []int
	for i := offset; i+4 <= len(raw); i += 4 {
		if raw[i] == vectorCID[0] && raw[i+1] == vectorCID[1] &&
			raw[i+2] == vectorCID[2] && raw[i+3] == vectorCID[3] {
			allVecPositions = append(allVecPositions, i)

			// Check: vec_cid(4) + count(4) + first_element_cid(4) = need 12 bytes
			if i+12 <= len(raw) {
				elemCount := int32(binary.LittleEndian.Uint32(raw[i+4 : i+8]))
				if elemCount > 0 {
					firstElemCID := binary.LittleEndian.Uint32(raw[i+8 : i+12])
					if chatCIDs[firstElemCID] {
						chatsStart = i
						log.Printf("[Dialogs] Found chats vector at offset %d (count=%d, firstCID=0x%08X)", i, elemCount, firstElemCID)
					}
				}
			}

			// Track the vector right after the chats vector
			if chatsStart >= 0 && nextVecAfterChats < 0 && i > chatsStart {
				nextVecAfterChats = i
				chatsEnd = i
			}
		}
	}

	log.Printf("[Dialogs] Found %d vector markers at positions: %v", len(allVecPositions), allVecPositions)

	if chatsStart < 0 {
		// No vector starts with a chat constructor — fall back to scanning entire payload
		log.Printf("[Dialogs] WARNING: No chats vector found by constructor check, scanning entire payload")
		return scanForChatsInRaw(raw[offset:]), nil
	}

	chatsSlice := raw[chatsStart:chatsEnd]
	if len(chatsSlice) >= 8 {
		vecCount := int32(binary.LittleEndian.Uint32(chatsSlice[4:8]))
		log.Printf("[Dialogs] Chats vector declares %d entries, scanning %d bytes", vecCount, len(chatsSlice))
	}

	groups := scanForChatsInRaw(chatsSlice)
	log.Printf("[Dialogs] Found %d groups/channels from chats vector", len(groups))

	return groups, nil
}

// scanForChatsInRaw scans raw bytes for chat/channel constructors
// and parses id+title independently from each position found.
func scanForChatsInRaw(raw []byte) []DialogInfo {
	var groups []DialogInfo

	for i := 0; i+4 <= len(raw); i += 4 {
		cid := binary.LittleEndian.Uint32(raw[i:])

		switch cid {
		case IDChat:
			subReader := NewTLReader(raw[i+4:])
			info := parseChatObject(subReader, cid)
			if info != nil {
				groups = append(groups, *info)
				log.Printf("[Dialogs] Found chat: id=%d title=%q members=%d", info.ID, info.Title, info.MembersCount)
			}
		case IDChannel:
			subReader := NewTLReader(raw[i+4:])
			info := parseChannelObject(subReader, cid)
			if info != nil {
				groups = append(groups, *info)
				log.Printf("[Dialogs] Found channel: id=%d title=%q type=%s ah=%d", info.ID, info.Title, info.Type, info.AccessHash)
			}
		case IDChatForbidden:
			subReader := NewTLReader(raw[i+4:])
			id, _ := subReader.ReadInt64()
			title, _ := subReader.ReadString()
			if title != "" {
				groups = append(groups, DialogInfo{ID: id, Title: title + " (forbidden)", Type: "group"})
				log.Printf("[Dialogs] Found forbidden chat: id=%d title=%q", id, title)
			}
		case IDChannelForbidden:
			subReader := NewTLReader(raw[i+4:])
			subReader.ReadInt32() // flags
			id, _ := subReader.ReadInt64()
			subReader.ReadInt64() // access_hash
			title, _ := subReader.ReadString()
			if title != "" {
				groups = append(groups, DialogInfo{ID: id, Title: title + " (forbidden)", Type: "channel"})
				log.Printf("[Dialogs] Found forbidden channel: id=%d title=%q", id, title)
			}
		}
	}
	return groups
}

// parseChatVector parses the chats vector and extracts group/channel info
func parseChatVector(r *TLReader) []DialogInfo {
	var groups []DialogInfo

	r.ReadUint32() // vector constructor ID (0x1cb5c415)
	count, err := r.ReadInt32()
	if err != nil || count <= 0 {
		log.Printf("[Dialogs] Chats vector count=%d (err=%v)", count, err)
		return groups
	}

	log.Printf("[Dialogs] Chats vector contains %d entries", count)

	for i := int32(0); i < count; i++ {
		cid, err := r.ReadUint32()
		if err != nil {
			log.Printf("[Dialogs] Error reading chat[%d] constructor: %v", i, err)
			break
		}

		log.Printf("[Dialogs] Chat[%d] constructor=0x%08X, remaining=%d", i, cid, r.Remaining())

		switch cid {
		case IDChat, 0x29562865: // chat or chatEmpty variants
			info := parseChatObject(r, cid)
			if info != nil {
				log.Printf("[Dialogs] Found group: id=%d title=%q members=%d", info.ID, info.Title, info.MembersCount)
				groups = append(groups, *info)
			}
		case IDChannel: // channel (layer 182)
			info := parseChannelObject(r, cid)
			if info != nil {
				log.Printf("[Dialogs] Found channel: id=%d title=%q type=%s", info.ID, info.Title, info.Type)
				groups = append(groups, *info)
			}
		case IDChatForbidden:
			id, _ := r.ReadInt64()
			title, _ := r.ReadString()
			groups = append(groups, DialogInfo{
				ID:    id,
				Title: title + " (forbidden)",
				Type:  "group",
			})
		case IDChannelForbidden:
			flags, _ := r.ReadInt32()
			id, _ := r.ReadInt64()
			_ = flags
			r.ReadInt64() // access_hash
			title, _ := r.ReadString()
			groups = append(groups, DialogInfo{
				ID:    id,
				Title: title + " (forbidden)",
				Type:  "channel",
			})
		default:
			// Unknown chat constructor — log and stop sequential parsing
			log.Printf("[Dialogs] Unknown chat constructor: 0x%08X at chat[%d], stopping", cid, i)
			return groups
		}
	}

	return groups
}

// parseChatObject parses a chat (group) TL object
func parseChatObject(r *TLReader, cid uint32) *DialogInfo {
	flags, _ := r.ReadInt32()
	id, _ := r.ReadInt64()
	title, _ := r.ReadString()

	// photo — skip
	photoCID, _ := r.ReadUint32()
	if photoCID != 0x37C1011C { // chatPhotoEmpty
		// chatPhoto — skip fields
		r.ReadInt32()  // flags
		r.ReadInt64()  // photo_id
		if r.Remaining() > 8 {
			r.ReadBytes() // stripped_thumb (optional based on flags)
		}
		r.ReadInt32() // dc_id
	}

	participantsCount, _ := r.ReadInt32()
	r.ReadInt32() // date
	r.ReadInt32() // version

	_ = flags

	return &DialogInfo{
		ID:           id,
		Title:        title,
		Type:         "group",
		MembersCount: participantsCount,
	}
}

// parseChannelObject parses a channel/supergroup TL object
// Soroush layer 182 schema:
//   channel#8e87ccd8 flags:# ... flags2:# ... id:long
//     access_hash:flags.13?long title:string username:flags.6?string
//     photo:ChatPhoto date:int ...
func parseChannelObject(r *TLReader, cid uint32) *DialogInfo {
	flags, _ := r.ReadInt32()
	flags2, _ := r.ReadInt32() // flags2 field (layer 182)
	_ = flags2
	id, _ := r.ReadInt64()

	// access_hash (if flags bit 13)
	var accessHash int64
	if flags&(1<<13) != 0 {
		accessHash, _ = r.ReadInt64()
	}

	title, _ := r.ReadString()

	// username (if flags bit 6)
	if flags&(1<<6) != 0 {
		r.ReadString() // username
	}

	chatType := "channel"
	if flags&(1<<8) != 0 { // megagroup flag
		chatType = "supergroup"
	}

	return &DialogInfo{
		ID:         id,
		Title:      title,
		Type:       chatType,
		AccessHash: accessHash,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Build messages.sendMessage TL payload
// ──────────────────────────────────────────────────────────────────────────────

// BuildSendTextMessage builds a messages.sendMessage request to a user
// userID: the Soroush user ID of the recipient
// accessHash: the access_hash for the target user
// text: message body
func BuildSendTextMessage(userID int64, accessHash int64, text string, randomID int64) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDSendMessage)

	// flags = 0 (no optional fields like reply_to, entities, etc.)
	w.WriteInt32(0)

	// peer = InputPeerUser(user_id, access_hash)
	w.WriteUint32(IDInputPeerUser)
	w.WriteInt64(userID)
	w.WriteInt64(accessHash)

	// message text
	w.WriteString(text)

	// random_id
	w.WriteInt64(randomID)

	return w.GetBytes()
}

// BuildSendGroupMessage builds a messages.sendMessage request to a group/channel chat
// For channels/supergroups, we must use InputPeerChannel with access_hash.
// chatID: the Soroush group chat ID
// accessHash: the channel's access_hash (0 for regular chats)
// text: message body
func BuildSendGroupMessage(chatID int64, text string, randomID int64) []byte {
	return BuildSendChannelMessage(chatID, 0, text, randomID)
}

// BuildSendChannelMessage builds a messages.sendMessage to a channel/supergroup
func BuildSendChannelMessage(chatID int64, accessHash int64, text string, randomID int64) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDSendMessage)

	// flags = 0
	w.WriteInt32(0)

	if accessHash != 0 {
		// peer = InputPeerChannel(channel_id, access_hash)
		w.WriteUint32(IDInputPeerChannel)
		w.WriteInt64(chatID)
		w.WriteInt64(accessHash)
	} else {
		// peer = InputPeerChat(chat_id) — fallback for regular groups
		w.WriteUint32(IDInputPeerChat)
		w.WriteInt64(chatID)
	}

	// message text
	w.WriteString(text)

	// random_id
	w.WriteInt64(randomID)

	return w.GetBytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Message listener — runs receive loop and dispatches incoming text messages
// ──────────────────────────────────────────────────────────────────────────────

// IncomingMessage represents a received Soroush text message
type IncomingMessage struct {
	FromUserID int64
	Text       string
	Date       int32
	MessageID  int32
	ChatID     int64 // non-zero if this is a group message
	IsGroup    bool  // true if message came from a group chat
}

// ListenForMessages runs a blocking receive loop on the given session.
// It calls the handler function for each incoming text message.
// Returns when the context is cancelled.
func ListenForMessages(ctx context.Context, session *MTProtoSession, handler func(msg IncomingMessage)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Use the parent context directly — NOT a timeout sub-context.
		// coder/websocket permanently closes the TCP socket when a context expires,
		// so a 30s timeout would kill the connection on idle groups.
		cid, reader, err := session.Recv(ctx)

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			errStr := err.Error()
			// Permanent connection errors — exit immediately
			if strings.Contains(errStr, "closed network connection") ||
				strings.Contains(errStr, "broken pipe") ||
				strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "EOF") {
				log.Printf("[Messaging] Connection lost (permanent): %v", err)
				return fmt.Errorf("connection lost: %w", err)
			}

			// Transient error — log and exit (let caller reconnect)
			log.Printf("[Messaging] recv error: %v", err)
			return fmt.Errorf("recv error: %w", err)
		}

		// Handle different update wrapper types
		processUpdate(cid, reader, session, handler)
	}
}

// processUpdate handles MTProto update messages and extracts text messages
func processUpdate(cid uint32, r *TLReader, session *MTProtoSession, handler func(msg IncomingMessage)) {
	switch cid {
	case IDMsgsAck:
		// Acknowledgment — ignore
		return

	case IDPong:
		// Pong response — ignore
		return

	case IDBadServerSalt:
		// Update server salt
		r.ReadInt64() // bad_msg_id
		r.ReadInt32() // bad_msg_seqno
		r.ReadInt32() // error_code
		newSalt, _ := r.ReadInt64()
		session.ServerSalt = newSalt
		log.Printf("[Messaging] Updated server salt: %d", newSalt)
		return

	case IDNewSession:
		r.ReadInt64() // first_msg_id
		r.ReadInt64() // unique_id
		newSalt, _ := r.ReadInt64()
		session.ServerSalt = newSalt
		log.Printf("[Messaging] New session, updated salt: %d", newSalt)
		return

	case IDMsgContainer:
		// Parse container
		count, _ := r.ReadInt32()
		for i := int32(0); i < count; i++ {
			r.ReadInt64() // msg_id
			r.ReadInt32() // seq_no
			bodyLen, _ := r.ReadInt32()
			body, err := r.ReadRaw(int(bodyLen))
			if err != nil {
				continue
			}
			subReader := NewTLReader(body)
			subCID, _ := subReader.ReadUint32()
			processUpdate(subCID, subReader, session, handler)
		}
		return

	case IDRPCResult:
		// RPC result (from our sendMessage, etc.) — can contain updates
		r.ReadInt64() // req_msg_id
		innerCID, _ := r.ReadUint32()
		processUpdate(innerCID, r, session, handler)
		return

	case IDUpdateShortMessage:
		// Direct short message from a user
		parseUpdateShortMessage(r, handler)
		return

	case IDUpdates:
		// Full updates container
		parseUpdates(r, handler)
		return

	case IDUpdateShort:
		// Single update wrapper
		innerCID, _ := r.ReadUint32()
		if innerCID == IDUpdateNewMessage || innerCID == IDUpdateNewChannelMessage {
			parseUpdateNewMessage(r, handler)
		} else if innerCID == IDUpdatePhoneCall {
			callEvent, err := ParseCallUpdate(r)
			if err == nil && callEvent != nil && callEvent.Type == "requested" {
				handler(IncomingMessage{
					FromUserID: callEvent.AdminID,
					Text:       fmt.Sprintf("CALL_REQUESTED:%d:%d:%d", callEvent.CallID, callEvent.AdminID, callEvent.AccessHash),
				})
			}
		}
		return

	case IDUpdateShortSentMessage:
		// Our sent message was confirmed — ignore
		return
	}
}

// parseUpdateShortMessage extracts a short incoming message
func parseUpdateShortMessage(r *TLReader, handler func(msg IncomingMessage)) {
	flags, _ := r.ReadInt32()
	msgID, _ := r.ReadInt32()
	userID, _ := r.ReadInt64()
	text, _ := r.ReadString()
	_ = flags // flags contain out/mentioned/media_unread etc.

	handler(IncomingMessage{
		FromUserID: userID,
		Text:       text,
		MessageID:  msgID,
	})
}

// parseUpdateNewMessage extracts a message from updateNewMessage
func parseUpdateNewMessage(r *TLReader, handler func(msg IncomingMessage)) {
	// message constructor
	msgCID, _ := r.ReadUint32()
	if msgCID != IDMessage {
		return
	}

	flags, _ := r.ReadInt32()
	_ = flags
	msgID, _ := r.ReadInt32()

	// from_id (PeerUser) if flags bit 8 is set
	var fromUserID int64
	if flags&(1<<8) != 0 {
		r.ReadUint32() // PeerUser constructor
		fromUserID, _ = r.ReadInt64()
	}

	// peer_id — can be PeerUser, PeerChat (group), or PeerChannel (supergroup)
	var chatID int64
	var isGroup bool
	peerCID, _ := r.ReadUint32()
	switch peerCID {
	case IDPeerChat:
		chatID, _ = r.ReadInt64()
		isGroup = true
	case IDPeerChannel:
		chatID, _ = r.ReadInt64()
		isGroup = true
	case IDPeerUser:
		r.ReadInt64() // peer user_id (not needed, we have from_id)
	default:
		// Unknown peer type — try to read int64 and continue
		r.ReadInt64()
	}

	// message text
	text, _ := r.ReadString()

	if fromUserID != 0 {
		handler(IncomingMessage{
			FromUserID: fromUserID,
			Text:       text,
			MessageID:  msgID,
			ChatID:     chatID,
			IsGroup:    isGroup,
		})
	}
}

// parseUpdates parses a full updates object
func parseUpdates(r *TLReader, handler func(msg IncomingMessage)) {
	// updates vector
	r.ReadUint32() // vector constructor
	count, _ := r.ReadInt32()
	for i := int32(0); i < count; i++ {
		updateCID, _ := r.ReadUint32()
		if updateCID == IDUpdateNewMessage || updateCID == IDUpdateNewChannelMessage {
			parseUpdateNewMessage(r, handler)
		} else if updateCID == IDUpdatePhoneCall {
			callEvent, err := ParseCallUpdate(r)
			if err == nil && callEvent != nil && callEvent.Type == "requested" {
				handler(IncomingMessage{
					FromUserID: callEvent.AdminID,
					Text:       fmt.Sprintf("CALL_REQUESTED:%d:%d:%d", callEvent.CallID, callEvent.AdminID, callEvent.AccessHash),
				})
			}
		}
		// Skip other update types gracefully
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Send message helper — fires and forgets
// ──────────────────────────────────────────────────────────────────────────────

// SendTextMessage sends a text message to a Soroush user via MTProto
func SendTextMessage(ctx context.Context, session *MTProtoSession, userID int64, accessHash int64, text string) error {
	randomID := time.Now().UnixNano()
	body := BuildSendTextMessage(userID, accessHash, text, randomID)

	_, err := session.Send(ctx, body, true)
	if err != nil {
		return fmt.Errorf("send text message: %w", err)
	}
	log.Printf("[Messaging] Sent message to user %d: %s", userID, truncate(text, 50))
	return nil
}

// SendGroupMessage sends a text message to a Soroush group chat via MTProto
func SendGroupMessage(ctx context.Context, session *MTProtoSession, chatID int64, text string) error {
	randomID := time.Now().UnixNano()
	body := BuildSendGroupMessage(chatID, text, randomID)

	_, err := session.Send(ctx, body, true)
	if err != nil {
		return fmt.Errorf("send group message: %w", err)
	}
	log.Printf("[Messaging] Sent group message to chat %d: %s", chatID, truncate(text, 50))
	return nil
}

// SendChannelMessage sends a text message to a Soroush channel/supergroup via MTProto
// Uses InputPeerChannel with access_hash when accessHash is non-zero
func SendChannelMessage(ctx context.Context, session *MTProtoSession, chatID int64, accessHash int64, text string) error {
	randomID := time.Now().UnixNano()
	body := BuildSendChannelMessage(chatID, accessHash, text, randomID)

	_, err := session.Send(ctx, body, true)
	if err != nil {
		return fmt.Errorf("send channel message: %w", err)
	}
	log.Printf("[Messaging] Sent channel message to chat %d (ah=%d): %s", chatID, accessHash, truncate(text, 50))
	return nil
}

// truncate helper for logging
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatcher protocol constants
// ──────────────────────────────────────────────────────────────────────────────

const (
	// DispatcherSynRequest is sent by the client to the dispatcher
	DispatcherSynRequest = "SYN_REQ_V1"

	// DispatcherAckRoutePrefix is the reply from the dispatcher with the worker ID
	DispatcherAckRoutePrefix = "ACK_ROUTE:"

	// DispatcherNoWorkers indicates no idle workers available
	DispatcherNoWorkers = "NACK_NO_WORKERS"
)

// ParseDispatcherResponse parses a dispatcher reply and extracts the worker user ID and access hash
// Format: "ACK_ROUTE:<user_id>:<access_hash>"
func ParseDispatcherResponse(text string) (workerUserID int64, workerAccessHash int64, ok bool) {
	if !strings.HasPrefix(text, DispatcherAckRoutePrefix) {
		return 0, 0, false
	}

	payload := text[len(DispatcherAckRoutePrefix):]
	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}

	userIDBytes := []byte(parts[0])
	accessHashBytes := []byte(parts[1])

	// Parse user ID
	uid, err := parseI64(userIDBytes)
	if err != nil {
		return 0, 0, false
	}

	// Parse access hash
	ah, err := parseI64(accessHashBytes)
	if err != nil {
		return 0, 0, false
	}

	return uid, ah, true
}

// parseI64 parses a decimal string to int64
func parseI64(b []byte) (int64, error) {
	s := string(b)
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

// FormatDispatcherResponse formats a worker assignment response
func FormatDispatcherResponse(workerUserID int64, workerAccessHash int64) string {
	return fmt.Sprintf("%s%d:%d", DispatcherAckRoutePrefix, workerUserID, workerAccessHash)
}

// ──────────────────────────────────────────────────────────────────────────────
// SDP Exchange Protocol — direct messages for WebRTC signaling
// ──────────────────────────────────────────────────────────────────────────────

const (
	// SDPOfferPrefix is sent by client to worker with the SDP offer
	SDPOfferPrefix = "SDP_OFFER:"

	// SDPAnswerPrefix is sent by worker to client with the SDP answer
	SDPAnswerPrefix = "SDP_ANSWER:"

	// ICECandidatePrefix is sent by both peers to exchange ICE candidates
	ICECandidatePrefix = "ICE:"
)

// IsSDPOffer checks if a message is an SDP offer
func IsSDPOffer(text string) bool {
	return strings.HasPrefix(text, SDPOfferPrefix)
}

// IsSDPAnswer checks if a message is an SDP answer
func IsSDPAnswer(text string) bool {
	return strings.HasPrefix(text, SDPAnswerPrefix)
}

// IsICECandidate checks if a message is an ICE candidate
func IsICECandidate(text string) bool {
	return strings.HasPrefix(text, ICECandidatePrefix)
}

// ExtractSDP extracts the SDP payload from an SDP_OFFER: or SDP_ANSWER: message
func ExtractSDP(text string) string {
	if strings.HasPrefix(text, SDPOfferPrefix) {
		return text[len(SDPOfferPrefix):]
	}
	if strings.HasPrefix(text, SDPAnswerPrefix) {
		return text[len(SDPAnswerPrefix):]
	}
	return ""
}

// ExtractICECandidate extracts the ICE candidate JSON from an ICE: message
func ExtractICECandidate(text string) string {
	if strings.HasPrefix(text, ICECandidatePrefix) {
		return text[len(ICECandidatePrefix):]
	}
	return ""
}

// FormatSDPOffer wraps an SDP string as an offer message
func FormatSDPOffer(sdp string) string {
	return SDPOfferPrefix + sdp
}

// FormatSDPAnswer wraps an SDP string as an answer message
func FormatSDPAnswer(sdp string) string {
	return SDPAnswerPrefix + sdp
}

// FormatICECandidate wraps an ICE candidate JSON string
func FormatICECandidate(candidateJSON string) string {
	return ICECandidatePrefix + candidateJSON
}

// ──────────────────────────────────────────────────────────────────────────────
// Session restore from saved credentials
// ──────────────────────────────────────────────────────────────────────────────

// RestoreSession creates a MTProtoSession from saved auth credentials
func RestoreSession(authKey []byte, authKeyID []byte, serverSalt []byte) (*MTProtoSession, *ObfuscatedTransport) {
	transport := NewTransport()
	session := NewSession(transport)

	session.AuthKey = authKey

	if len(authKeyID) >= 8 {
		session.AuthKeyID = int64(binary.LittleEndian.Uint64(authKeyID))
	}
	if len(serverSalt) >= 8 {
		session.ServerSalt = int64(binary.LittleEndian.Uint64(serverSalt))
	}

	return session, transport
}
