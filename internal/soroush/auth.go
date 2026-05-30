package soroush

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/salman/ble-webrtc-tun/internal/provider"
)

type PendingAuth struct {
	phone         int64
	transport     *ObfuscatedTransport
	session       *MTProtoSession
	phoneCodeHash []byte
	cancel        context.CancelFunc
	expiresAt     time.Time
}

var (
	authSessionsMu sync.Mutex
	authSessions   = make(map[string]*PendingAuth)
)

type SoroushAuthAdapter struct {
	mu sync.Mutex
}

func NewSoroushAuthAdapter() *SoroushAuthAdapter {
	return &SoroushAuthAdapter{}
}

// Type implements provider.AuthClient
func (a *SoroushAuthAdapter) Type() provider.ProviderType {
	return provider.ProviderSoroush
}

// executeRPC safely loops until it receives the definitive RPC answer, gracefully 
// handling server ACKs, salts, and session creation notifications.
func executeRPC(ctx context.Context, session *MTProtoSession, req []byte) (uint32, *TLReader, error) {
	_, err := session.Send(ctx, req, true)
	if err != nil {
		return 0, nil, err
	}

	for {
		cid, reader, err := session.Recv(ctx)
		if err != nil {
			return 0, nil, err
		}

		innerCID, innerReader := unwrapResponse(cid, reader)

		switch innerCID {
		case IDBadServerSalt:
			innerReader.ReadInt64() // bad_msg_id
			innerReader.ReadInt32() // bad_msg_seqno
			innerReader.ReadInt32() // error_code
			newSalt, _ := innerReader.ReadInt64()
			session.ServerSalt = newSalt
			// Resend the original request
			_, err = session.Send(ctx, req, true)
			if err != nil {
				return 0, nil, err
			}
			continue

		case IDNewSession:
			innerReader.ReadInt64() // first_msg_id
			innerReader.ReadInt64() // unique_id
			newSalt, _ := innerReader.ReadInt64()
			session.ServerSalt = newSalt
			// Don't resend; server processed it. Continue waiting for the actual RPC result.
			continue

		case IDMsgsAck, IDMsgContainer, IDPing, IDPong:
			// Ignore structural/keepalive messages that aren't our RPC result
			continue

		default:
			// Found the RPC result (e.g., sentCode, auth.authorization, or rpc_error)
			return innerCID, innerReader, nil
		}
	}
}

// unwrapResponse extracts the inner payload if wrapped in RPCResult or MsgContainer
func unwrapResponse(cid uint32, r *TLReader) (uint32, *TLReader) {
	switch cid {
	case IDRPCResult:
		r.ReadInt64() // req_msg_id
		innerCID, _ := r.ReadUint32()
		rem := r.Remaining()
		data, _ := r.ReadRaw(rem)
		return innerCID, NewTLReader(data)

	case IDMsgContainer:
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
			if subCID == IDRPCResult {
				subReader.ReadInt64() // req_msg_id
				innerCID, _ := subReader.ReadUint32()
				rem := subReader.Remaining()
				data, _ := subReader.ReadRaw(rem)
				return innerCID, NewTLReader(data)
			}
			if subCID == IDBadServerSalt || subCID == IDNewSession {
				return subCID, subReader
			}
		}
		return cid, r

	default:
		return cid, r
	}
}

// StartPhoneAuth implements provider.AuthClient
func (a *SoroushAuthAdapter) StartPhoneAuth(phone int64) (string, error) {
	// Format to 937... then force the 98 country code
	phoneStr := strconv.FormatInt(phone, 10)
	if strings.HasPrefix(phoneStr, "9") && len(phoneStr) == 10 {
		phoneStr = "98" + phoneStr
	}
	if !strings.HasPrefix(phoneStr, "+") {
		phoneStr = "+" + phoneStr
	}

	log.Printf("[SoroushAuth] Starting auth flow for phone: %s", MaskPhone(phoneStr))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)

	transport := NewTransport()
	if err := transport.Connect(ctx); err != nil {
		cancel()
		return "", fmt.Errorf("connect websocket: %w", err)
	}

	session := NewSession(transport)
	if err := session.CreateAuthKey(ctx); err != nil {
		cancel()
		transport.Disconnect()
		return "", fmt.Errorf("DH key exchange: %w", err)
	}

	// Warm up to prime the salt and establish session before sending invokeWithLayer
	// if err := session.WarmUpSession(ctx); err != nil {
	// 	log.Printf("[MTProto] WarmUpSession failed (ignoring): %v", err)
	// }

	sendCodeReq := BuildSendCodeRequest(phoneStr, SoroushAppID, SoroushAppHash)
	wrappedReq := WrapInitConnection(SoroushAppID, sendCodeReq)

	// Block safely until we get the parsed sentCode answer
	innerCID, innerReader, err := executeRPC(ctx, session, wrappedReq)
	if err != nil {
		cancel()
		transport.Disconnect()
		return "", fmt.Errorf("executeRPC auth.sendCode: %w", err)
	}

	phoneCodeHash, timeout, err := ParseSentCodeResponse(innerCID, innerReader)
	if err != nil {
		cancel()
		transport.Disconnect()
		return "", fmt.Errorf("parse sendCode response: %w", err)
	}

	cancel()

	// Store pending session globally
	sessionID := fmt.Sprintf("soroush-sess-%d", time.Now().UnixNano())
	bgCtx, bgCancel := context.WithCancel(context.Background())

	authSessionsMu.Lock()
	authSessions[sessionID] = &PendingAuth{
		phone:         phone,
		transport:     transport,
		session:       session,
		phoneCodeHash: phoneCodeHash,
		cancel:        bgCancel,
		expiresAt:     time.Now().Add(10 * time.Minute),
	}
	authSessionsMu.Unlock()

	log.Printf("[SoroushAuth] OTP sent successfully, session: %s, timeout: %d", sessionID, timeout)

	_ = bgCtx // keep context reference

	return sessionID, nil
}

// ValidateCode implements provider.AuthClient
func (a *SoroushAuthAdapter) ValidateCode(txHash string, code string) (*provider.AuthResult, error) {
	authSessionsMu.Lock()
	pending, found := authSessions[txHash]
	if found {
		delete(authSessions, txHash)
	}
	authSessionsMu.Unlock()

	if !found {
		return nil, errors.New("OTP session not found or expired")
	}

	defer func() {
		pending.cancel()
		pending.transport.Disconnect()
	}()

	phoneStr := strconv.FormatInt(pending.phone, 10)
	if strings.HasPrefix(phoneStr, "9") && len(phoneStr) == 10 {
		phoneStr = "98" + phoneStr
	}
	if !strings.HasPrefix(phoneStr, "+") {
		phoneStr = "+" + phoneStr
	}

	log.Printf("[SoroushAuth] Validating OTP for phone: %s (session: %s)", MaskPhone(phoneStr), txHash)

	signInBody := BuildSignInRequest(phoneStr, pending.phoneCodeHash, code)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Re-use executeRPC to avoid hanging on ACKs during validation
	innerCID, innerReader, err := executeRPC(ctx, pending.session, signInBody)
	if err != nil {
		return nil, fmt.Errorf("executeRPC auth.signIn: %w", err)
	}

	userID, firstName, lastName, accessHash, err := ParseAuthorizationResponse(innerCID, innerReader)
	if err != nil {
		return nil, fmt.Errorf("parse authorization response: %w", err)
	}

	displayName := strings.TrimSpace(firstName + " " + lastName)
	if displayName == "" {
		displayName = "Soroush User"
	}

	log.Printf("[SoroushAuth] Verified successfully! UserID: %d, DisplayName: %q", userID, displayName)

	return &provider.AuthResult{
		UserID:      userID,
		AccessHash:  accessHash,
		DisplayName: displayName,
		Phone:       phoneStr,
		AuthKey:     pending.session.AuthKey,
		AuthKeyID:   Int64ToBytes(pending.session.AuthKeyID),
		ServerSalt:  Int64ToBytes(pending.session.ServerSalt),
	}, nil
}
