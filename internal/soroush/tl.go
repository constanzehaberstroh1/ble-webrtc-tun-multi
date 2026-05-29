package soroush

import (
	"encoding/binary"
	"fmt"
)

// ──────────────────────────────────────────────────────────────────────────────
// TLWriter — binary TL serialization (little-endian)
// ──────────────────────────────────────────────────────────────────────────────

type TLWriter struct {
	buf []byte
}

func NewTLWriter() *TLWriter {
	return &TLWriter{}
}

func (w *TLWriter) WriteInt32(v int32) *TLWriter {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	w.buf = append(w.buf, b...)
	return w
}

func (w *TLWriter) WriteUint32(v uint32) *TLWriter {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	w.buf = append(w.buf, b...)
	return w
}

func (w *TLWriter) WriteInt64(v int64) *TLWriter {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	w.buf = append(w.buf, b...)
	return w
}

func (w *TLWriter) WriteUint64(v uint64) *TLWriter {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	w.buf = append(w.buf, b...)
	return w
}

// WriteBytes writes TL-encoded bytes (length-prefixed with padding)
func (w *TLWriter) WriteBytes(data []byte) *TLWriter {
	n := len(data)
	if n < 254 {
		w.buf = append(w.buf, byte(n))
		w.buf = append(w.buf, data...)
		pad := (-(n + 1)) % 4
		if pad < 0 {
			pad += 4
		}
		for i := 0; i < pad; i++ {
			w.buf = append(w.buf, 0)
		}
	} else {
		w.buf = append(w.buf, 254, byte(n&0xFF), byte((n>>8)&0xFF), byte((n>>16)&0xFF))
		w.buf = append(w.buf, data...)
		pad := (-n) % 4
		if pad < 0 {
			pad += 4
		}
		for i := 0; i < pad; i++ {
			w.buf = append(w.buf, 0)
		}
	}
	return w
}

// WriteString writes a TL-encoded string (bytes wrapper)
func (w *TLWriter) WriteString(s string) *TLWriter {
	return w.WriteBytes([]byte(s))
}

// WriteRaw appends raw bytes without any encoding
func (w *TLWriter) WriteRaw(data []byte) *TLWriter {
	w.buf = append(w.buf, data...)
	return w
}

func (w *TLWriter) GetBytes() []byte {
	return w.buf
}

// ──────────────────────────────────────────────────────────────────────────────
// TLReader — binary TL deserialization (little-endian)
// ──────────────────────────────────────────────────────────────────────────────

type TLReader struct {
	data []byte
	pos  int
}

func NewTLReader(data []byte) *TLReader {
	return &TLReader{data: data, pos: 0}
}

func (r *TLReader) ReadInt32() (int32, error) {
	if r.pos+4 > len(r.data) {
		return 0, fmt.Errorf("ReadInt32: not enough data at pos=%d, len=%d", r.pos, len(r.data))
	}
	v := int32(binary.LittleEndian.Uint32(r.data[r.pos:]))
	r.pos += 4
	return v, nil
}

func (r *TLReader) ReadUint32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, fmt.Errorf("ReadUint32: not enough data at pos=%d, len=%d", r.pos, len(r.data))
	}
	v := binary.LittleEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *TLReader) ReadInt64() (int64, error) {
	if r.pos+8 > len(r.data) {
		return 0, fmt.Errorf("ReadInt64: not enough data at pos=%d, len=%d", r.pos, len(r.data))
	}
	v := int64(binary.LittleEndian.Uint64(r.data[r.pos:]))
	r.pos += 8
	return v, nil
}

func (r *TLReader) ReadUint64() (uint64, error) {
	if r.pos+8 > len(r.data) {
		return 0, fmt.Errorf("ReadUint64: not enough data at pos=%d, len=%d", r.pos, len(r.data))
	}
	v := binary.LittleEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return v, nil
}

// ReadBytes reads TL-encoded bytes
func (r *TLReader) ReadBytes() ([]byte, error) {
	if r.pos >= len(r.data) {
		return nil, fmt.Errorf("ReadBytes: no data at pos=%d", r.pos)
	}
	first := r.data[r.pos]
	var n int
	if first < 254 {
		n = int(first)
		r.pos++
		if r.pos+n > len(r.data) {
			return nil, fmt.Errorf("ReadBytes: short read n=%d at pos=%d", n, r.pos)
		}
		data := make([]byte, n)
		copy(data, r.data[r.pos:r.pos+n])
		r.pos += n
		pad := (-(n + 1)) % 4
		if pad < 0 {
			pad += 4
		}
		r.pos += pad
		return data, nil
	}
	// n >= 254
	if r.pos+4 > len(r.data) {
		return nil, fmt.Errorf("ReadBytes: not enough data for long length")
	}
	n = int(r.data[r.pos+1]) | int(r.data[r.pos+2])<<8 | int(r.data[r.pos+3])<<16
	r.pos += 4
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("ReadBytes: short read n=%d at pos=%d", n, r.pos)
	}
	data := make([]byte, n)
	copy(data, r.data[r.pos:r.pos+n])
	r.pos += n
	pad := (-n) % 4
	if pad < 0 {
		pad += 4
	}
	r.pos += pad
	return data, nil
}

func (r *TLReader) ReadString() (string, error) {
	b, err := r.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *TLReader) ReadRaw(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("ReadRaw: not enough data n=%d at pos=%d", n, r.pos)
	}
	data := make([]byte, n)
	copy(data, r.data[r.pos:r.pos+n])
	r.pos += n
	return data, nil
}

func (r *TLReader) Remaining() int {
	return len(r.data) - r.pos
}

// ──────────────────────────────────────────────────────────────────────────────
// MTProto constructor IDs (Soroush-specific)
// ──────────────────────────────────────────────────────────────────────────────

const (
	// DH key exchange
	IDReqPQMulti    uint32 = 0xBE7E8EF1
	IDResPQ         uint32 = 0x05162463
	IDReqDHParams   uint32 = 0xD712E4BE
	IDServerDHOK    uint32 = 0xD0E8075C
	IDClientDHInner uint32 = 0x6643B654
	IDSetClientDH   uint32 = 0xF5045F1F
	IDDHGenOK       uint32 = 0x3BCBF734

	// Messages
	IDMsgsAck       uint32 = 0x62D6B459
	IDRPCResult     uint32 = 0xF35C6D01
	IDMsgContainer  uint32 = 0x73F1F8DC
	IDBadServerSalt uint32 = 0xEDAB447B
	IDNewSession    uint32 = 0x9EC20908
	IDPing          uint32 = 0x7ABE77EC
	IDPingDelayDisc uint32 = 0xF3427B8C
	IDPong          uint32 = 0x347773C5

	// Auth
	IDSendCodeRequest uint32 = 0xA677244F
	IDCodeSettings    uint32 = 0xAD253D78
	IDSentCode        uint32 = 0x5E002502
	IDSignInRequest   uint32 = 0x8D52A951

	// Connection wrapping
	IDInvokeWithLayer uint32 = 0xDA9B0D0D
	IDInitConnection  uint32 = 0xC1CD5EA9

	// P_Q inner data
	IDPQInnerData uint32 = 0xA9F55F95

	// Server DH inner data
	IDServerDHInnerData uint32 = 0xB5890DBA

	// RPC error
	IDRPCError uint32 = 0x2144CA19

	// Soroush app credentials (extracted from web.splus.ir PWA)
	SoroushAppID   int32  = 1030400
	SoroushAppHash string = "6edb16cf88714a4e9a805e928c39c937"
)

// ──────────────────────────────────────────────────────────────────────────────
// TL message builders — Soroush-specific auth request constructors
// ──────────────────────────────────────────────────────────────────────────────

// BuildSendCodeRequest builds auth.sendCode TL request
func BuildSendCodeRequest(phone string, apiID int32, apiHash string) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDSendCodeRequest)
	w.WriteString(phone)
	w.WriteInt32(apiID)
	w.WriteString(apiHash)
	// CodeSettings: 0xAD253D78 with flags=0 (no optional fields)
	w.WriteUint32(IDCodeSettings)
	w.WriteInt32(0) // flags = 0
	return w.GetBytes()
}

// BuildSignInRequest builds auth.signIn TL request
func BuildSignInRequest(phone string, codeHash []byte, code string) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDSignInRequest)
	w.WriteInt32(1) // flags = 1 (bit 0 set = phone_code present)
	w.WriteString(phone)
	w.WriteBytes(codeHash)
	w.WriteString(code)
	return w.GetBytes()
}

// WrapInitConnection wraps a query with invokeWithLayer + initConnection
func WrapInitConnection(apiID int32, query []byte) []byte {
	init := NewTLWriter()
	init.WriteUint32(IDInitConnection)
	init.WriteUint32(0) // flags
	init.WriteInt32(apiID)
	init.WriteString("Web")   // device_model
	init.WriteString("1.0")   // system_version
	init.WriteString("1.0")   // app_version
	init.WriteString("fa")    // system_lang_code
	init.WriteString("")      // lang_pack
	init.WriteString("fa")    // lang_code
	init.WriteRaw(query)

	w := NewTLWriter()
	w.WriteUint32(IDInvokeWithLayer)
	w.WriteInt32(182) // layer (Soroush production)
	w.WriteRaw(init.GetBytes())
	return w.GetBytes()
}

// BuildPingDelayDisconnectRequest builds ping_delay_disconnect request
func BuildPingDelayDisconnectRequest(pingID int64, disconnectDelay int32) []byte {
	w := NewTLWriter()
	w.WriteUint32(IDPingDelayDisc)
	w.WriteInt64(pingID)
	w.WriteInt32(disconnectDelay)
	return w.GetBytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Response parsers
// ──────────────────────────────────────────────────────────────────────────────

// ParseSentCodeResponse parses the auth.sentCode response
func ParseSentCodeResponse(cid uint32, r *TLReader) (phoneCodeHash []byte, timeout int32, err error) {
	if cid == IDRPCError {
		return nil, 0, ParseRPCError(r)
	}
	if cid != IDSentCode {
		return nil, 0, fmt.Errorf("unexpected response cid=0x%08X, expected sentCode", cid)
	}

	flags, _ := r.ReadInt32()

	// Read type (SentCodeType constructor)
	typeCID, _ := r.ReadUint32()

	switch typeCID {
	case 0x3DBB5986, 0xC000BBA2, 0x5353E5A7:
		r.ReadInt32() // length
	case 0xAB03C6D9: // FlashCall
		r.ReadString() // pattern
	}

	phoneCodeHash, _ = r.ReadBytes()

	// Optional fields based on flags
	if flags&(1<<1) != 0 {
		r.ReadInt32() // next_type
	}
	if flags&(1<<2) != 0 {
		timeout, _ = r.ReadInt32()
	}

	return phoneCodeHash, timeout, nil
}

// ParseAuthorizationResponse parses the auth.authorization response
func ParseAuthorizationResponse(cid uint32, r *TLReader) (userID int64, firstName, lastName string, accessHash int64, err error) {
	if cid == IDRPCError {
		return 0, "", "", 0, ParseRPCError(r)
	}

	flags, _ := r.ReadInt32()

	if flags&(1<<0) != 0 {
		r.ReadInt32() // tmp_sessions
	}
	if flags&(1<<1) != 0 {
		r.ReadInt32() // otherwise_relogin_days
	}
	if flags&(1<<2) != 0 {
		r.ReadBytes() // future_auth_token
	}

	// User object
	_, _ = r.ReadUint32() // user CID

	uFlags, _ := r.ReadInt32()
	_, _ = r.ReadInt32() // flags2

	userID, _ = r.ReadInt64()

	if uFlags&(1<<0) != 0 {
		accessHash, _ = r.ReadInt64()
	}
	if uFlags&(1<<1) != 0 {
		firstName, _ = r.ReadString()
	}
	if uFlags&(1<<2) != 0 {
		lastName, _ = r.ReadString()
	}

	return userID, firstName, lastName, accessHash, nil
}

// ParseRPCError parses an RPC error response
func ParseRPCError(r *TLReader) error {
	errorCode, _ := r.ReadInt32()
	errorMessage, _ := r.ReadString()
	return fmt.Errorf("RPC error %d: %s", errorCode, errorMessage)
}

// Int64ToBytes converts int64 to little-endian bytes
func Int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

// MaskPhone masks a phone number for logging
func MaskPhone(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-2:]
}
