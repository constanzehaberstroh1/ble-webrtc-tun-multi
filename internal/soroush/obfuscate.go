package soroush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// ──────────────────────────────────────────────────────────────────────────────
// Stealth Encoding — AES-256-GCM + Persian Camouflage
// ──────────────────────────────────────────────────────────────────────────────
//
// Group messages are encrypted with a pre-shared key (PSK) known to both
// client and server. The encrypted payload is base64-encoded and wrapped
// in a Persian conversational prefix to blend in with normal group chat.
//
// Format: <persian_prefix> [<base64_encrypted_payload>]
// Example: سلام خانواده عزیزم ❤️ [dGhpcyBpcyBhIHRlc3Q=]
// ──────────────────────────────────────────────────────────────────────────────

// DefaultPSK is the default pre-shared key for group message encryption.
// In production, this should be configurable via the admin UI.
var DefaultPSK = []byte("soroush-relay-tunnel-psk-2026!key")

// Persian camouflage prefixes — randomly selected to look like normal chat
var persianPrefixes = []string{
	"سلام خانواده عزیزم ❤️",
	"امروز هوا خوبه 🌤️",
	"خوبید همگی؟ 😊",
	"دلم براتون تنگ شده 💕",
	"شب بخیر عزیزانم 🌙",
	"صبح بخیر خانواده 🌅",
	"چه خبر از همه؟ 🤗",
	"امیدوارم حالتون خوب باشه 🙏",
}

// StealthMarker is the bracket pair that wraps the encrypted payload
const StealthMarker = "["

// EncodePayload encrypts JSON bytes with AES-256-GCM and wraps in Persian camouflage
func EncodePayload(jsonBytes []byte, psk []byte) (string, error) {
	// Derive a 32-byte key from PSK using SHA-256
	keyHash := sha256.Sum256(psk)
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt: nonce is prepended to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, jsonBytes, nil)

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// Pick a random Persian prefix
	prefixIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(persianPrefixes))))
	prefix := persianPrefixes[prefixIdx.Int64()]

	return fmt.Sprintf("%s [%s]", prefix, encoded), nil
}

// DecodePayload extracts and decrypts the payload from a stealth-encoded message
func DecodePayload(message string, psk []byte) ([]byte, error) {
	// Find the bracketed payload — use Index for '[' and LastIndex for ']'
	// to handle any edge case where Persian prefix contains brackets
	startIdx := strings.Index(message, "[")
	endIdx := strings.LastIndex(message, "]")
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return nil, fmt.Errorf("no stealth payload found in message")
	}

	encoded := message[startIdx+1 : endIdx]

	// Base64 decode
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	// Derive key
	keyHash := sha256.Sum256(psk)
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// IsStealthMessage checks if a message contains a stealth-encoded payload
func IsStealthMessage(message string) bool {
	startIdx := strings.Index(message, "[")
	endIdx := strings.LastIndex(message, "]")
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return false
	}
	payload := message[startIdx+1 : endIdx]
	// Must be valid base64 and reasonably long (AES-GCM nonce + at least some data)
	_, err := base64.StdEncoding.DecodeString(payload)
	return err == nil && len(payload) > 20
}
