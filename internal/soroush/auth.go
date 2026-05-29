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

// StartPhoneAuth implements provider.AuthClient
func (a *SoroushAuthAdapter) StartPhoneAuth(phone int64) (string, error) {
	phoneStr := "+" + strconv.FormatInt(phone, 10)
	if !strings.HasPrefix(phoneStr, "+98") && !strings.HasPrefix(phoneStr, "98") {
		// Ensure correct country code format for domestic or test numbers
		if !strings.HasPrefix(phoneStr, "+") {
			phoneStr = "+" + strconv.FormatInt(phone, 10)
		}
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

	// Build and wrap auth.sendCode
	sendCodeReq := BuildSendCodeRequest(phoneStr, SoroushAppID, SoroushAppHash)
	wrappedReq := WrapInitConnection(SoroushAppID, sendCodeReq)

	recvCh := make(chan struct {
		cid    uint32
		reader *TLReader
		err    error
	}, 1)

	go func() {
		cid, reader, err := session.Recv(ctx)
		recvCh <- struct {
			cid    uint32
			reader *TLReader
			err    error
		}{cid: cid, reader: reader, err: err}
	}()

	msgID, err := session.Send(ctx, wrappedReq, true)
	if err != nil {
		cancel()
		transport.Disconnect()
		return "", fmt.Errorf("send auth.sendCode: %w", err)
	}

	var phoneCodeHash []byte
	var timeout int32

	// Wait for response, handling bad_server_salt / new_session retries
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			cancel()
			transport.Disconnect()
			return "", ctx.Err()
		case res := <-recvCh:
			if res.err != nil {
				cancel()
				transport.Disconnect()
				return "", fmt.Errorf("receive sendCode response: %w", res.err)
			}

			innerCID, innerReader := unwrapResponse(res.cid, res.reader, msgID)

			if innerCID == IDBadServerSalt {
				innerReader.ReadInt64() // bad_msg_id
				innerReader.ReadInt32() // bad_msg_seqno
				innerReader.ReadInt32() // error_code
				newSalt, _ := innerReader.ReadInt64()
				session.ServerSalt = newSalt

				// Re-send with new salt
				go func() {
					cid, reader, err := session.Recv(ctx)
					recvCh <- struct {
						cid    uint32
						reader *TLReader
						err    error
					}{cid: cid, reader: reader, err: err}
				}()
				msgID, _ = session.Send(ctx, wrappedReq, true)
				continue
			}

			if innerCID == IDNewSession {
				innerReader.ReadInt64() // first_msg_id
				innerReader.ReadInt64() // unique_id
				newSalt, _ := innerReader.ReadInt64()
				session.ServerSalt = newSalt

				// Continue waiting for RPC response
				go func() {
					cid, reader, err := session.Recv(ctx)
					recvCh <- struct {
						cid    uint32
						reader *TLReader
						err    error
					}{cid: cid, reader: reader, err: err}
				}()
				continue
			}

			phoneCodeHash, timeout, err = ParseSentCodeResponse(innerCID, innerReader)
			if err != nil {
				cancel()
				transport.Disconnect()
				return "", fmt.Errorf("parse sendCode response: %w", err)
			}
			break
		}
	}

	cancel()

	// Store pending session
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

	phoneStr := "+" + strconv.FormatInt(pending.phone, 10)
	log.Printf("[SoroushAuth] Validating OTP for phone: %s (session: %s)", MaskPhone(phoneStr), txHash)

	// Build auth.signIn request
	signInBody := BuildSignInRequest(phoneStr, pending.phoneCodeHash, code)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recvCh := make(chan struct {
		cid    uint32
		reader *TLReader
		err    error
	}, 1)

	go func() {
		cid, reader, err := pending.session.Recv(ctx)
		recvCh <- struct {
			cid    uint32
			reader *TLReader
			err    error
		}{cid: cid, reader: reader, err: err}
	}()

	msgID, err := pending.session.Send(ctx, signInBody, true)
	if err != nil {
		return nil, fmt.Errorf("send auth.signIn: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-recvCh:
		if res.err != nil {
			return nil, fmt.Errorf("receive signIn response: %w", res.err)
		}

		innerCID, innerReader := unwrapResponse(res.cid, res.reader, msgID)

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
}

// unwrapResponse extracts the inner payload if wrapped in RPCResult or MsgContainer
func unwrapResponse(cid uint32, r *TLReader, expectedMsgID int64) (uint32, *TLReader) {
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

var _ provider.AuthClient = (*SoroushAuthAdapter)(nil)
