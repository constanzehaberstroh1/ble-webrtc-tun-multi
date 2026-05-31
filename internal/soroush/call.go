package soroush

import (
	"sync"
)
//
// These are derived from the Telegram MTProto TL schema that Soroush uses.
// Soroush voice calls follow the same phone.requestCall / phone.acceptCall
// flow as Telegram's VoIP implementation.
// ──────────────────────────────────────────────────────────────────────────────

const (
	// phone.requestCall — initiates a call
	IDPhoneRequestCall uint32 = 0x42FF96ED

	// phone.acceptCall — accepts an incoming call
	IDPhoneAcceptCall uint32 = 0x3BD2B4A0

	// phone.confirmCall — confirms call after key exchange
	IDPhoneConfirmCall uint32 = 0x2EFE1722

	// phone.discardCall — ends a call
	IDPhoneDiscardCall uint32 = 0xB2CBC1C0

	// phone.receivedCall — acknowledges call receipt
	IDPhoneReceivedCall uint32 = 0x17D54F61

	// phone.setCallRating — rates a call
	IDPhoneSetCallRating uint32 = 0x59EAD627

	// phone.saveCallDebug — saves call debug info
	IDPhoneSaveCallDebug uint32 = 0x277ADD7E

	// phoneCallProtocol — protocol description
	IDPhoneCallProtocol uint32 = 0xFC878FC8

	// phoneCallRequested — incoming call update
	IDPhoneCallRequested uint32 = 0x14B0ED0C

	// phoneCallAccepted — call was accepted
	IDPhoneCallAccepted uint32 = 0x3660C311

	// phoneCall — active call
	IDPhoneCall uint32 = 0x967F7C67

	// phoneCallDiscarded — call ended
	IDPhoneCallDiscarded uint32 = 0x50CA4DE1

	// phoneCallWaiting — call is ringing
	IDPhoneCallWaiting uint32 = 0xC5226F17

	// inputPhoneCall — reference to a call
	IDInputPhoneCall uint32 = 0x1E36FDED

	// updatePhoneCall — update wrapper for call events
	IDUpdatePhoneCall uint32 = 0xAB0F6B1E

	// phone.phoneCall result wrapper
	IDPhonePhoneCall uint32 = 0xEC82E140

	// phoneConnection — TURN/STUN connection info
	IDPhoneConnection uint32 = 0x9CC123C7

	// phoneConnectionWebrtc — WebRTC-specific connection
	IDPhoneConnectionWebrtc uint32 = 0x635FE375
)

// ──────────────────────────────────────────────────────────────────────────────
// Soroush ICE Server Configuration (from research WebRTC internals dump)
// ──────────────────────────────────────────────────────────────────────────────

// SoroushTURNServers contains the TURN/STUN servers discovered from
// Soroush's WebRTC internals dump. These are domestic Iranian servers.
var SoroushTURNServers = []ICEServerConfig{
	{
		URLs:       []string{"turn:185.60.139.28:1400", "turn:185.60.139.28:1400?transport=tcp"},
		Username:   "",
		Credential: "",
	},
	{
		URLs:       []string{"stun:185.60.139.28:1400"},
		Username:   "",
		Credential: "",
	},
	{
		URLs:       []string{"turn:185.60.137.28:1400", "turn:185.60.137.28:1400?transport=tcp"},
		Username:   "",
		Credential: "",
	},
	{
		URLs:       []string{"stun:185.60.137.28:1400"},
		Username:   "",
		Credential: "",
	},
	{
		URLs:       []string{"turn:185.60.137.29:1400", "turn:185.60.137.29:1400?transport=tcp"},
		Username:   "",
		Credential: "",
	},
	{
		URLs:       []string{"stun:185.60.137.29:1400"},
		Username:   "",
		Credential: "",
	},
}

// ICEServerConfig holds STUN/TURN server configuration
type ICEServerConfig struct {
	URLs       []string
	Username   string
	Credential string
}

// ──────────────────────────────────────────────────────────────────────────────
// TL Builders for phone call signaling
// ──────────────────────────────────────────────────────────────────────────────

// BuildPhoneCallProtocol builds a phoneCallProtocol TL object
// Matches Soroush's observed config:
//   - minLayer: 92, maxLayer: 92 (Soroush specific)
//   - libraryVersions: ["7.0.0"]
func BuildPhoneCallProtocol() []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneCallProtocol)

	// flags: bit 0 = udp_p2p, bit 1 = udp_reflector
	w.WriteInt32(0x03) // both UDP P2P and reflector enabled

	// min_layer
	w.WriteInt32(92)
	// max_layer
	w.WriteInt32(92)

	// library_versions vector
	w.WriteUint32(0x1CB5C415) // vector constructor
	w.WriteInt32(1)           // count = 1
	w.WriteString("7.0.0")

	return w.GetBytes()
}

// BuildPhoneRequestCall builds a phone.requestCall TL request
// This initiates a voice call to a peer user.
// gAHash is the DH g_a_hash for E2E encryption (32 bytes)
// sdpOffer is the WebRTC SDP offer encoded as bytes
func BuildPhoneRequestCall(userID int64, accessHash int64, randomID int32, gAHash []byte) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneRequestCall)

	// flags = 0x01 (bit 0 = video, we set it to look like a video call for maximum bandwidth)
	w.WriteInt32(0x01)

	// user_id = InputPeerUser
	w.WriteUint32(IDInputPeerUser)
	w.WriteInt64(userID)
	w.WriteInt64(accessHash)

	// random_id
	w.WriteInt32(randomID)

	// g_a_hash (32 bytes raw)
	w.WriteBytes(gAHash)

	// protocol = phoneCallProtocol
	w.WriteRaw(BuildPhoneCallProtocol())

	return w.GetBytes()
}

// BuildPhoneAcceptCall builds a phone.acceptCall TL request
// Used by the server/worker to accept an incoming call
func BuildPhoneAcceptCall(callID int64, callAccessHash int64, gB []byte) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneAcceptCall)

	// peer = inputPhoneCall
	w.WriteUint32(IDInputPhoneCall)
	w.WriteInt64(callID)
	w.WriteInt64(callAccessHash)

	// g_b
	w.WriteBytes(gB)

	// protocol
	w.WriteRaw(BuildPhoneCallProtocol())

	return w.GetBytes()
}

// BuildPhoneConfirmCall builds a phone.confirmCall TL request
// Sent by the caller after receiving the accepted call with g_b
func BuildPhoneConfirmCall(callID int64, callAccessHash int64, gA []byte, keyFingerprint int64) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneConfirmCall)

	// peer = inputPhoneCall
	w.WriteUint32(IDInputPhoneCall)
	w.WriteInt64(callID)
	w.WriteInt64(callAccessHash)

	// g_a
	w.WriteBytes(gA)

	// key_fingerprint
	w.WriteInt64(keyFingerprint)

	// protocol
	w.WriteRaw(BuildPhoneCallProtocol())

	return w.GetBytes()
}

// BuildPhoneDiscardCall builds a phone.discardCall TL request
func BuildPhoneDiscardCall(callID int64, callAccessHash int64, duration int32) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneDiscardCall)

	// flags = 0
	w.WriteInt32(0)

	// peer = inputPhoneCall
	w.WriteUint32(IDInputPhoneCall)
	w.WriteInt64(callID)
	w.WriteInt64(callAccessHash)

	// duration
	w.WriteInt32(duration)

	// reason = phoneCallDiscardReasonHangup (0x57ADC690)
	w.WriteUint32(0x57ADC690)

	// connection_id
	w.WriteInt64(0)

	return w.GetBytes()
}

// BuildPhoneReceivedCall builds a phone.receivedCall TL request
// Acknowledges reception of an incoming call
func BuildPhoneReceivedCall(callID int64, callAccessHash int64) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPhoneReceivedCall)

	// peer = inputPhoneCall
	w.WriteUint32(IDInputPhoneCall)
	w.WriteInt64(callID)
	w.WriteInt64(callAccessHash)

	return w.GetBytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Call event parsing
// ──────────────────────────────────────────────────────────────────────────────

// CallEvent represents a parsed Soroush call event
type CallEvent struct {
	Type           string // "requested", "accepted", "confirmed", "discarded", "waiting"
	CallID         int64
	AccessHash     int64
	AdminID        int64  // caller user ID
	ParticipantID  int64  // callee user ID
	GAHash         []byte // g_a_hash from caller
	GB             []byte // g_b from callee
	GA             []byte // g_a from caller (in confirm)
	KeyFingerprint int64
	Connections    []PhoneConnectionInfo
}

// PhoneConnectionInfo holds TURN/STUN connection details from the call
type PhoneConnectionInfo struct {
	ID       int64
	IP       string
	IPv6     string
	Port     int32
	Username string
	Password string
	Turn     bool
	Stun     bool
}

// ParseCallUpdate parses an updatePhoneCall and returns the call event
func ParseCallUpdate(r *TLReader) (*CallEvent, error) {
	// The inner phone_call object
	callCID, _ := r.ReadUint32()

	event := &CallEvent{}

	switch callCID {
	case IDPhoneCallRequested:
		event.Type = "requested"
		flags, _ := r.ReadInt32()
		event.CallID, _ = r.ReadInt64()
		event.AccessHash, _ = r.ReadInt64()
		r.ReadInt32() // date
		event.AdminID, _ = r.ReadInt64()
		event.ParticipantID, _ = r.ReadInt64()
		event.GAHash, _ = r.ReadBytes()
		_ = flags
		// protocol follows but we skip it

	case IDPhoneCallAccepted:
		event.Type = "accepted"
		flags, _ := r.ReadInt32()
		event.CallID, _ = r.ReadInt64()
		event.AccessHash, _ = r.ReadInt64()
		r.ReadInt32() // date
		event.AdminID, _ = r.ReadInt64()
		event.ParticipantID, _ = r.ReadInt64()
		event.GB, _ = r.ReadBytes()
		_ = flags

	case IDPhoneCall:
		event.Type = "confirmed"
		flags, _ := r.ReadInt32()
		event.CallID, _ = r.ReadInt64()
		event.AccessHash, _ = r.ReadInt64()
		r.ReadInt32() // date
		event.AdminID, _ = r.ReadInt64()
		event.ParticipantID, _ = r.ReadInt64()
		event.GA, _ = r.ReadBytes()
		event.KeyFingerprint, _ = r.ReadInt64()
		_ = flags

		// Parse connections vector
		r.ReadUint32() // protocol
		// Skip protocol fields
		r.ReadInt32() // flags
		r.ReadInt32() // min_layer
		r.ReadInt32() // max_layer
		// library_versions vector
		r.ReadUint32() // vector cid
		libCount, _ := r.ReadInt32()
		for i := int32(0); i < libCount; i++ {
			r.ReadString()
		}

		// connections vector
		r.ReadUint32() // vector constructor
		connCount, _ := r.ReadInt32()
		for i := int32(0); i < connCount; i++ {
			conn := parsePhoneConnection(r)
			event.Connections = append(event.Connections, conn)
		}

	case IDPhoneCallDiscarded:
		event.Type = "discarded"
		flags, _ := r.ReadInt32()
		event.CallID, _ = r.ReadInt64()
		_ = flags

	case IDPhoneCallWaiting:
		event.Type = "waiting"
		flags, _ := r.ReadInt32()
		event.CallID, _ = r.ReadInt64()
		event.AccessHash, _ = r.ReadInt64()
		_ = flags

	default:
		return nil, nil
	}

	return event, nil
}

// parsePhoneConnection parses a phoneConnection or phoneConnectionWebrtc
func parsePhoneConnection(r *TLReader) PhoneConnectionInfo {
	connCID, _ := r.ReadUint32()
	info := PhoneConnectionInfo{}

	switch connCID {
	case IDPhoneConnection:
		flags, _ := r.ReadInt32()
		info.ID, _ = r.ReadInt64()
		info.IP, _ = r.ReadString()
		info.IPv6, _ = r.ReadString()
		info.Port, _ = r.ReadInt32()
		peerTag, _ := r.ReadBytes()
		_ = peerTag
		info.Turn = flags&(1<<0) != 0
		info.Stun = flags&(1<<1) != 0

	case IDPhoneConnectionWebrtc:
		flags, _ := r.ReadInt32()
		info.ID, _ = r.ReadInt64()
		info.IP, _ = r.ReadString()
		info.IPv6, _ = r.ReadString()
		info.Port, _ = r.ReadInt32()
		info.Username, _ = r.ReadString()
		info.Password, _ = r.ReadString()
		info.Turn = flags&(1<<0) != 0
		info.Stun = flags&(1<<1) != 0
	}

	return info
}

// ParsePhoneCallResult parses the result of phone.requestCall or phone.acceptCall
// Returns the call event from the phone.phoneCall wrapper
func ParsePhoneCallResult(cid uint32, r *TLReader) (*CallEvent, error) {
	if cid == IDRPCError {
		return nil, ParseRPCError(r)
	}

	if cid != IDPhonePhoneCall {
		// Try to parse as a direct call event
		event := &CallEvent{}
		switch cid {
		case IDPhoneCallRequested, IDPhoneCallAccepted, IDPhoneCall,
			IDPhoneCallDiscarded, IDPhoneCallWaiting:
			// Rewind by creating a new reader that includes the CID
			return ParseCallUpdate(r)
		}
		return event, nil
	}

	// phone.phoneCall wrapper
	// phone_call field
	return ParseCallUpdate(r)
}

var (
	callEventsMu       sync.RWMutex
	callEventListeners = make(map[int64]chan *CallEvent)
)

func RegisterCallEventListener(callID int64, ch chan *CallEvent) {
	callEventsMu.Lock()
	defer callEventsMu.Unlock()
	callEventListeners[callID] = ch
}

func UnregisterCallEventListener(callID int64) {
	callEventsMu.Lock()
	defer callEventsMu.Unlock()
	delete(callEventListeners, callID)
}

func DispatchCallEvent(event *CallEvent) {
	callEventsMu.RLock()
	defer callEventsMu.RUnlock()

	if ch, ok := callEventListeners[event.CallID]; ok {
		select {
		case ch <- event:
		default:
		}
		return
	}

	// wildcard listener for incoming calls or pending requests
	if ch, ok := callEventListeners[0]; ok {
		select {
		case ch <- event:
		default:
		}
	}
}

