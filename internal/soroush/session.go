package soroush

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// MTProtoSession — handles encrypted communication over obfuscated transport
// ──────────────────────────────────────────────────────────────────────────────

type MTProtoSession struct {
	Transport *ObfuscatedTransport

	AuthKey    []byte
	AuthKeyID  int64
	ServerSalt int64
	SessionID  int64

	seqNo int32

	mu sync.Mutex
}

func NewSession(transport *ObfuscatedTransport) *MTProtoSession {
	sid := make([]byte, 8)
	rand.Read(sid)
	return &MTProtoSession{
		Transport: transport,
		SessionID: int64(binary.LittleEndian.Uint64(sid)),
	}
}

func (s *MTProtoSession) newMsgID() int64 {
	t := time.Now()
	sec := t.Unix()
	ns := t.UnixNano() - sec*1e9
	return (sec << 32) | (ns & ^int64(3))
}

func (s *MTProtoSession) nextSeq(contentRelated bool) int32 {
	n := s.seqNo * 2
	if contentRelated {
		n += 1
	}
	if contentRelated {
		s.seqNo++
	}
	return n
}

// SendPlain sends an unencrypted MTProto message (for key exchange)
func (s *MTProtoSession) SendPlain(ctx context.Context, body []byte) (int64, error) {
	msgID := s.newMsgID()

	data := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(data[8:], uint64(msgID))
	binary.LittleEndian.PutUint32(data[16:], uint32(len(body)))
	copy(data[20:], body)

	return msgID, s.Transport.Send(ctx, data)
}

// RecvPlain receives an unencrypted MTProto response (for key exchange)
func (s *MTProtoSession) RecvPlain(ctx context.Context) ([]byte, error) {
	raw, err := s.Transport.Recv(ctx)
	if err != nil {
		return nil, err
	}
	if len(raw) < 20 {
		return nil, fmt.Errorf("recvPlain: frame too short: %d", len(raw))
	}
	bodyLen := binary.LittleEndian.Uint32(raw[16:20])
	if 20+int(bodyLen) > len(raw) {
		return nil, fmt.Errorf("recvPlain: body extends past frame")
	}
	return raw[20 : 20+bodyLen], nil
}

// Send sends an encrypted MTProto message
func (s *MTProtoSession) Send(ctx context.Context, body []byte, contentRelated bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgID := s.newMsgID()
	seq := s.nextSeq(contentRelated)

	inner := make([]byte, 32+len(body))
	binary.LittleEndian.PutUint64(inner[0:], uint64(s.ServerSalt))
	binary.LittleEndian.PutUint64(inner[8:], uint64(s.SessionID))
	binary.LittleEndian.PutUint64(inner[16:], uint64(msgID))
	binary.LittleEndian.PutUint32(inner[24:], uint32(seq))
	binary.LittleEndian.PutUint32(inner[28:], uint32(len(body)))
	copy(inner[32:], body)

	padLen := ((-len(inner) - 12) % 16)
	if padLen < 0 {
		padLen += 16
	}
	padLen += 12
	total := 8 + 16 + len(inner) + padLen
	if total%4 != 0 {
		padLen += 4 - (total % 4)
	}
	padding := make([]byte, padLen)
	rand.Read(padding)
	inner = append(inner, padding...)

	mkBuf := make([]byte, 32+len(inner))
	copy(mkBuf, s.AuthKey[88:120])
	copy(mkBuf[32:], inner)
	msgKeyFull := Sha256Sum(mkBuf)
	msgKey := msgKeyFull[8:24]

	key, iv := GenerateKeyIV(s.AuthKey, msgKey, true)
	enc := AesIGEEncrypt(inner, key, iv)

	packet := make([]byte, 8+16+len(enc))
	binary.LittleEndian.PutUint64(packet[0:], uint64(s.AuthKeyID))
	copy(packet[8:], msgKey)
	copy(packet[24:], enc)

	return msgID, s.Transport.Send(ctx, packet)
}

// SendAndWait sends an encrypted message and waits for the RPC response.
// It automatically handles bad_server_salt by updating the salt and retrying.
// Returns the response constructor ID and TLReader, or an error.
func (s *MTProtoSession) SendAndWait(ctx context.Context, body []byte, contentRelated bool) (uint32, *TLReader, error) {
	for attempt := 0; attempt < 3; attempt++ {
		_, err := s.Send(ctx, body, contentRelated)
		if err != nil {
			return 0, nil, fmt.Errorf("send: %w", err)
		}

		// Read response — use parent ctx (coder/websocket kills the socket on context expiry)
		cid, reader, err := s.Recv(ctx)
		if err != nil {
			return 0, nil, fmt.Errorf("recv: %w", err)
		}

		switch cid {
		case IDBadServerSalt:
			// Update salt and retry
			reader.ReadInt64() // bad_msg_id
			reader.ReadInt32() // bad_msg_seqno
			reader.ReadInt32() // error_code
			newSalt, _ := reader.ReadInt64()
			s.ServerSalt = newSalt
			log.Printf("[MTProto] Bad server salt, updated to %d. Retrying (attempt %d)...", newSalt, attempt+1)
			continue

		case IDNewSession:
			// Update salt from new session and retry
			reader.ReadInt64() // first_msg_id
			reader.ReadInt64() // unique_id
			newSalt, _ := reader.ReadInt64()
			s.ServerSalt = newSalt
			log.Printf("[MTProto] New session, salt=%d. Retrying (attempt %d)...", newSalt, attempt+1)
			continue

		case IDMsgsAck:
			// Just an ACK, need to read the actual response
			cid2, reader2, err2 := s.Recv(ctx)
			if err2 != nil {
				return 0, nil, fmt.Errorf("recv after ack: %w", err2)
			}
			return cid2, reader2, nil

		case IDMsgContainer:
			// Parse container to find the actual RPC result
			count, _ := reader.ReadInt32()
			for i := int32(0); i < count; i++ {
				reader.ReadInt64() // msg_id
				reader.ReadInt32() // seq_no
				bodyLen, _ := reader.ReadInt32()
				subBody, _ := reader.ReadRaw(int(bodyLen))
				if len(subBody) >= 4 {
					subCID := binary.LittleEndian.Uint32(subBody[:4])
					if subCID == IDBadServerSalt && len(subBody) >= 28 {
						newSalt := int64(binary.LittleEndian.Uint64(subBody[20:28]))
						s.ServerSalt = newSalt
						log.Printf("[MTProto] Bad salt in container, updated to %d", newSalt)
						break // will retry in outer loop
					}
					if subCID == IDRPCResult || subCID == IDUpdates || subCID == IDUpdateShortSentMessage {
						subReader := NewTLReader(subBody[4:])
						return subCID, subReader, nil
					}
				}
			}
			continue // retry if only salt updates in container

		default:
			return cid, reader, nil
		}
	}
	return 0, nil, fmt.Errorf("SendAndWait: failed after 3 retries (bad_server_salt)")
}

// WarmUpSession sends a lightweight RPC request (updates.getState) and handles
// bad_server_salt / new_session_created responses to prime the session salt.
// Call this BEFORE starting ListenForMessages to ensure the salt is correct.
func (s *MTProtoSession) WarmUpSession(ctx context.Context) error {
	// Build a minimal updates.getState request (constructor 0xedd4882a)
	w := NewTLWriter()
	w.WriteUint32(0xEDD4882A) // updates.getState
	body := w.GetBytes()

	log.Println("[MTProto] Warming up session (updates.getState)...")

	for attempt := 0; attempt < 3; attempt++ {
		_, err := s.Send(ctx, body, true)
		if err != nil {
			return fmt.Errorf("warm up send: %w", err)
		}

		cid, reader, err := s.Recv(ctx)
		if err != nil {
			return fmt.Errorf("warm up recv: %w", err)
		}

		switch cid {
		case IDBadServerSalt:
			reader.ReadInt64() // bad_msg_id
			reader.ReadInt32() // bad_msg_seqno
			reader.ReadInt32() // error_code
			newSalt, _ := reader.ReadInt64()
			s.ServerSalt = newSalt
			log.Printf("[MTProto] Warm-up: updated salt to %d (attempt %d)", newSalt, attempt+1)
			continue

		case IDNewSession:
			reader.ReadInt64() // first_msg_id
			reader.ReadInt64() // unique_id
			newSalt, _ := reader.ReadInt64()
			s.ServerSalt = newSalt
			log.Printf("[MTProto] Warm-up: new session, salt=%d (attempt %d)", newSalt, attempt+1)
			continue

		case IDMsgsAck:
			// ACK received, try to read the actual response
			s.Recv(ctx)
			log.Println("[MTProto] Warm-up: session ready ✅")
			return nil

		case IDMsgContainer:
			// Container — check for salt updates inside, otherwise session is ready
			count, _ := reader.ReadInt32()
			saltUpdated := false
			for i := int32(0); i < count; i++ {
				reader.ReadInt64() // msg_id
				reader.ReadInt32() // seq_no
				bodyLen, _ := reader.ReadInt32()
				subBody, _ := reader.ReadRaw(int(bodyLen))
				if len(subBody) >= 4 {
					subCID := binary.LittleEndian.Uint32(subBody[:4])
					if subCID == IDBadServerSalt && len(subBody) >= 28 {
						newSalt := int64(binary.LittleEndian.Uint64(subBody[20:28]))
						s.ServerSalt = newSalt
						saltUpdated = true
						log.Printf("[MTProto] Warm-up: salt from container = %d", newSalt)
					}
				}
			}
			if saltUpdated {
				continue
			}
			log.Println("[MTProto] Warm-up: session ready ✅")
			return nil

		default:
			// Got an actual response — session is warm
			log.Printf("[MTProto] Warm-up: got CID=0x%08X, session ready ✅", cid)
			return nil
		}
	}
	log.Println("[MTProto] Warm-up: completed after 3 attempts")
	return nil
}

// Recv receives and decrypts an MTProto message.
// Returns (constructor_id, TLReader, error)
func (s *MTProtoSession) Recv(ctx context.Context) (uint32, *TLReader, error) {
	data, err := s.Transport.Recv(ctx)
	if err != nil {
		return 0, nil, err
	}
	if len(data) < 8 {
		return 0, nil, fmt.Errorf("recv: frame too short: %d bytes", len(data))
	}

	authKeyID := int64(binary.LittleEndian.Uint64(data[0:8]))

	if authKeyID == 0 {
		if len(data) < 20 {
			return 0, nil, fmt.Errorf("recv: unencrypted frame too short")
		}
		bodyLen := int(binary.LittleEndian.Uint32(data[16:20]))
		if 20+bodyLen > len(data) {
			return 0, nil, fmt.Errorf("recv: unencrypted bodyLen=%d exceeds frame len=%d", bodyLen, len(data))
		}
		body := data[20 : 20+bodyLen]
		r := NewTLReader(body)
		cid, err := r.ReadUint32()
		if err != nil {
			return 0, nil, err
		}
		return cid, r, nil
	}

	// Encrypted message
	if len(data) < 24 {
		return 0, nil, fmt.Errorf("recv: encrypted frame too short")
	}
	msgKey := data[8:24]
	enc := data[24:]

	key, iv := GenerateKeyIV(s.AuthKey, msgKey, false)
	inner := AesIGEDecrypt(enc, key, iv)

	if len(inner) < 32 {
		return 0, nil, fmt.Errorf("recv: decrypted inner too short: %d", len(inner))
	}

	bodyLen := int(binary.LittleEndian.Uint32(inner[28:32]))
	if 32+bodyLen > len(inner) {
		log.Printf("[MTProto] WARN: bodyLen exceeds decrypted buffer, clamping (bodyLen=%d, innerLen=%d)", bodyLen, len(inner))
		bodyLen = len(inner) - 32
	}
	body := inner[32 : 32+bodyLen]
	r := NewTLReader(body)
	cid, err := r.ReadUint32()
	if err != nil {
		return 0, nil, err
	}
	return cid, r, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// DH Key Exchange — creates the auth key
// ──────────────────────────────────────────────────────────────────────────────

func (s *MTProtoSession) CreateAuthKey(ctx context.Context) error {
	log.Println("[MTProto] Starting DH key exchange...")

	// Step 1: req_pq_multi
	nonce := make([]byte, 16)
	rand.Read(nonce)

	w := NewTLWriter()
	w.WriteUint32(IDReqPQMulti)
	w.WriteRaw(nonce)
	_, err := s.SendPlain(ctx, w.GetBytes())
	if err != nil {
		return fmt.Errorf("send req_pq_multi: %w", err)
	}

	// Read resPQ
	raw, err := s.RecvPlain(ctx)
	if err != nil {
		return fmt.Errorf("recv resPQ: %w", err)
	}
	r := NewTLReader(raw)
	cid, _ := r.ReadUint32()
	if cid != IDResPQ {
		return fmt.Errorf("expected resPQ (0x%08X), got 0x%08X", IDResPQ, cid)
	}

	_, _ = r.ReadRaw(16) // nonce echo
	srvNonce, _ := r.ReadRaw(16)
	pqBytes, _ := r.ReadBytes()
	pq := new(big.Int).SetBytes(pqBytes)

	// Read fingerprints vector
	_, _ = r.ReadUint32() // vector constructor id
	count, _ := r.ReadInt32()
	fingerprints := make([]uint64, count)
	for i := int32(0); i < count; i++ {
		fp, _ := r.ReadUint64()
		fingerprints[i] = fp
	}

	log.Printf("[MTProto] resPQ received: pq=%s, fingerprints=%v", pq.String(), fingerprints)

	// Step 2: factorize pq
	p, q := factorize(pq.Int64())

	newNonce := make([]byte, 32)
	rand.Read(newNonce)

	pBytes := bigIntToBytes(p)
	qBytes := bigIntToBytes(q)
	pqBytesSer := bigIntToBytes(pq.Int64())

	// Build p_q_inner_data
	inner := NewTLWriter()
	inner.WriteUint32(IDPQInnerData)
	inner.WriteBytes(pqBytesSer)
	inner.WriteBytes(pBytes)
	inner.WriteBytes(qBytes)
	inner.WriteRaw(nonce)
	inner.WriteRaw(srvNonce)
	inner.WriteRaw(newNonce)
	inner.WriteInt32(2) // dc_id = 2
	innerData := inner.GetBytes()

	// Find matching RSA fingerprint
	var fp uint64
	found := false
	for _, f := range fingerprints {
		if _, ok := SoroushRSAKeys[f]; ok {
			fp = f
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no matching RSA key for fingerprints: %v", fingerprints)
	}

	fp, encrypted, err := RSAEncrypt(innerData, fp)
	if err != nil {
		return fmt.Errorf("rsa encrypt: %w", err)
	}

	// Step 3: req_DH_params
	w = NewTLWriter()
	w.WriteUint32(IDReqDHParams)
	w.WriteRaw(nonce)
	w.WriteRaw(srvNonce)
	w.WriteBytes(pBytes)
	w.WriteBytes(qBytes)
	w.WriteUint64(fp)
	w.WriteBytes(encrypted)
	_, err = s.SendPlain(ctx, w.GetBytes())
	if err != nil {
		return fmt.Errorf("send req_DH_params: %w", err)
	}

	// Read server_DH_params_ok
	raw, err = s.RecvPlain(ctx)
	if err != nil {
		return fmt.Errorf("recv server_DH_params: %w", err)
	}
	r = NewTLReader(raw)
	cid, _ = r.ReadUint32()
	if cid != IDServerDHOK {
		return fmt.Errorf("expected server_DH_params_ok (0x%08X), got 0x%08X", IDServerDHOK, cid)
	}
	r.ReadRaw(16) // nonce
	r.ReadRaw(16) // server_nonce
	encAnswer, _ := r.ReadBytes()

	log.Printf("[MTProto] server_DH_params_ok received (enc_answer_len=%d)", len(encAnswer))

	// Derive tmp_key and tmp_iv
	nn := newNonce
	sn := srvNonce
	shaNNSN := Sha1Sum(append(nn, sn...))
	shaSNNN := Sha1Sum(append(sn, nn...))
	shaNNNN := Sha1Sum(append(nn, nn...))

	tmpKey := append(shaNNSN, shaSNNN[:12]...)
	tmpIV := make([]byte, 0)
	tmpIV = append(tmpIV, shaSNNN[12:]...)
	tmpIV = append(tmpIV, shaNNNN...)
	tmpIV = append(tmpIV, nn[:4]...)

	// Decrypt the answer
	answerFull := AesIGEDecrypt(encAnswer, tmpKey, tmpIV)
	answer := answerFull[20:] // skip SHA1 hash

	// Parse server_DH_inner_data
	ra := NewTLReader(answer)
	got, _ := ra.ReadUint32()
	if got != IDServerDHInnerData {
		return fmt.Errorf("expected server_DH_inner_data (0x%08X), got 0x%08X", IDServerDHInnerData, got)
	}
	ra.ReadRaw(16) // nonce
	ra.ReadRaw(16) // server_nonce
	g, _ := ra.ReadInt32()
	dhPrimeBytes, _ := ra.ReadBytes()
	gABytes, _ := ra.ReadBytes()

	dhPrime := new(big.Int).SetBytes(dhPrimeBytes)
	gA := new(big.Int).SetBytes(gABytes)

	log.Printf("[MTProto] server_DH_inner_data parsed (g=%d)", g)

	// Step 4: Generate client DH
	bBytes := make([]byte, 256)
	rand.Read(bBytes)
	b := new(big.Int).SetBytes(bBytes)

	gBig := big.NewInt(int64(g))
	gB := new(big.Int).Exp(gBig, b, dhPrime)

	authKeyInt := new(big.Int).Exp(gA, b, dhPrime)
	authKeyBytes := make([]byte, 256)
	akb := authKeyInt.Bytes()
	copy(authKeyBytes[256-len(akb):], akb)

	// Calculate server_salt = xor(new_nonce[:8], server_nonce[:8])
	saltBytes := XorBytes(nn[:8], sn[:8])
	s.ServerSalt = int64(binary.LittleEndian.Uint64(saltBytes))

	// Build client_DH_inner_data
	ci := NewTLWriter()
	ci.WriteUint32(IDClientDHInner)
	ci.WriteRaw(nonce)
	ci.WriteRaw(srvNonce)
	ci.WriteInt64(0) // retry_id
	gBBytes := gB.Bytes()
	ci.WriteBytes(gBBytes)
	ciData := ci.GetBytes()

	// Encrypt: sha1(ci_data) + ci_data + padding
	ciEnc := append(Sha1Sum(ciData), ciData...)
	padLen := (-len(ciEnc)) % 16
	if padLen < 0 {
		padLen += 16
	}
	if padLen > 0 {
		ciEnc = append(ciEnc, make([]byte, padLen)...)
	}
	ciEncrypted := AesIGEEncrypt(ciEnc, tmpKey, tmpIV)

	// Send set_client_DH_params
	w = NewTLWriter()
	w.WriteUint32(IDSetClientDH)
	w.WriteRaw(nonce)
	w.WriteRaw(srvNonce)
	w.WriteBytes(ciEncrypted)
	_, err = s.SendPlain(ctx, w.GetBytes())
	if err != nil {
		return fmt.Errorf("send set_client_DH: %w", err)
	}

	// Read dh_gen_ok
	raw, err = s.RecvPlain(ctx)
	if err != nil {
		return fmt.Errorf("recv dh_gen_ok: %w", err)
	}
	r = NewTLReader(raw)
	cid, _ = r.ReadUint32()
	if cid != IDDHGenOK {
		return fmt.Errorf("DH failed: got 0x%08X instead of dh_gen_ok", cid)
	}

	s.AuthKey = authKeyBytes
	akHash := Sha1Sum(authKeyBytes)
	s.AuthKeyID = int64(binary.LittleEndian.Uint64(akHash[12:20]))

	log.Printf("[MTProto] Auth key generated successfully! auth_key_id=%d", s.AuthKeyID)

	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func factorize(pq int64) (int64, int64) {
	if pq%2 == 0 {
		return 2, pq / 2
	}

	rng := make([]byte, 8)
	rand.Read(rng)
	x := int64(binary.LittleEndian.Uint64(rng)%(uint64(pq)-2)) + 2

	rand.Read(rng)
	c := int64(binary.LittleEndian.Uint64(rng)%(uint64(pq)-1)) + 1

	y := x
	d := int64(1)

	for d == 1 {
		x = (mulmod(x, x, pq) + c) % pq
		y = (mulmod(y, y, pq) + c) % pq
		y = (mulmod(y, y, pq) + c) % pq
		diff := x - y
		if diff < 0 {
			diff = -diff
		}
		d = gcd(diff, pq)
	}

	if d == pq {
		for i := int64(3); i*i <= pq; i += 2 {
			if pq%i == 0 {
				return i, pq / i
			}
		}
		fmt.Fprintf(os.Stderr, "factorize: failed for pq=%d\n", pq)
		return 1, pq
	}

	p, q := d, pq/d
	if p > q {
		p, q = q, p
	}
	return p, q
}

func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

func mulmod(a, b, m int64) int64 {
	aBig := big.NewInt(a)
	bBig := big.NewInt(b)
	mBig := big.NewInt(m)
	return new(big.Int).Mod(new(big.Int).Mul(aBig, bBig), mBig).Int64()
}

func bigIntToBytes(n int64) []byte {
	bn := big.NewInt(n)
	b := bn.Bytes()
	return b
}
