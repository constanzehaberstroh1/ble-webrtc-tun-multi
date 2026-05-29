package config

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// TokenPair holds one client-server Bale/Soroush token pair.
type TokenPair struct {
	Index            int
	Provider         string // "bale" or "soroush"
	ClientToken      string
	ServerToken      string
	TargetUserID     int64 // The user ID that the client calls (server's user ID)
	ExpectedCallerID int64 // The client user ID expected to call this server account
	AuthKey          []byte
	AuthKeyID        []byte
	ServerSalt       []byte
	AccessHash       int64
}

// extractUserIDFromJWT parses a Bale JWT token and extracts the user_id from payload.
func extractUserIDFromJWT(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	// Decode payload (part 1), add padding if needed
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0
	}
	var claims struct {
		Payload struct {
			UserID int64 `json:"user_id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return 0
	}
	return claims.Payload.UserID
}

// LoadTokenPairs reads .env.tokens file and OS environment variables.
// For the client side, it returns pairs with ClientToken + TargetUserID.
// For the server side, it returns pairs with ServerToken + ExpectedCallerID.
func LoadTokenPairs(role string) []TokenPair {
	// Load from .env.tokens file first
	envMap := loadEnvFile(".env.tokens")

	// Helper: check file then os env
	getVal := func(key string) string {
		if v := envMap[key]; v != "" {
			return v
		}
		return os.Getenv(key)
	}

	var pairs []TokenPair
	for i := 1; i <= 8; i++ {
		suffix := strconv.Itoa(i)
		var tp TokenPair
		tp.Index = i

		if role == "client" {
			tp.ClientToken = getVal("BALE_TOKEN_CLIENT_" + suffix)
			if tp.ClientToken == "" {
				continue
			}
			targetStr := getVal("BALE_TARGET_SERVER_" + suffix)
			if targetStr != "" {
				tp.TargetUserID, _ = strconv.ParseInt(targetStr, 10, 64)
			}
		} else {
			tp.ServerToken = getVal("BALE_TOKEN_SERVER_" + suffix)
			if tp.ServerToken == "" {
				continue
			}
			// Load TargetUserID: the server's own user ID (used for call routing)
			targetStr := getVal("BALE_TARGET_SERVER_" + suffix)
			if targetStr != "" {
				tp.TargetUserID, _ = strconv.ParseInt(targetStr, 10, 64)
			}
			// Extract ExpectedCallerID from the paired client JWT token
			clientToken := getVal("BALE_TOKEN_CLIENT_" + suffix)
			if clientToken != "" {
				tp.ExpectedCallerID = extractUserIDFromJWT(clientToken)
			}
		}
		pairs = append(pairs, tp)
	}

	// Fallback: single token from env
	if len(pairs) == 0 {
		singleToken := os.Getenv("BALE_ACCESS_TOKEN")
		if singleToken == "" {
			singleToken = envMap["BALE_ACCESS_TOKEN"]
		}
		targetID, _ := strconv.ParseInt(os.Getenv("BALE_TARGET_USER_ID"), 10, 64)
		if singleToken != "" {
			pairs = append(pairs, TokenPair{
				Index:        1,
				ClientToken:  singleToken,
				ServerToken:  singleToken,
				TargetUserID: targetID,
			})
		}
	}

	return pairs
}

// loadEnvFile reads a simple KEY=VALUE file (ignoring comments and blank lines).
func loadEnvFile(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Remove surrounding quotes
			val = strings.Trim(val, "\"'")
			m[key] = val
		}
	}
	return m
}

// Config holds all application configuration loaded from environment.
type Config struct {
	Role string // "client" or "server"

	// Bale signaling
	BaleAccessToken   string
	BaleTargetUserID  int64

	// LiveKit / Bale signaling
	LiveKitWSURL      string
	LiveKitToken      string

	// ICE / TURN servers
	TURNServerPrimary   string
	TURNServerSecondary string
	STUNServerPrimary   string
	STUNServerSecondary string
	TURNUsername        string
	TURNCredential      string

	// TUN interface
	TUNIP   string
	TUNMask string
	TUNMTU  int
	TUNName string

	// Signaling server (SDP exchange)
	SignalServerAddr string

	// Admin panel (server only)
	AdminListenAddr string
	AdminUsername    string
	AdminPassword   string

	// Obfuscation (anti-DPI)
	ObfuscationSecret string

	// Logging
	LogLevel string
}

// Load reads configuration from .env file and environment variables.
func Load() (*Config, error) {
	// Load .env file if it exists (don't error if missing)
	_ = godotenv.Load()

	cfg := &Config{
		Role: getEnv("ROLE", "client"),

		BaleAccessToken:  getEnv("BALE_ACCESS_TOKEN", ""),
		BaleTargetUserID: int64(getEnvInt("BALE_TARGET_USER_ID", 0)),

		LiveKitWSURL: getEnv("LIVEKIT_WS_URL", ""),
		LiveKitToken: getEnv("LIVEKIT_ACCESS_TOKEN", ""),

		TURNServerPrimary:   getEnv("TURN_SERVER_PRIMARY", "turns:meet-turn.ble.ir:443?transport=tcp"),
		TURNServerSecondary: getEnv("TURN_SERVER_SECONDARY", "turn:2.189.68.97:3478?transport=tcp"),
		STUNServerPrimary:   getEnv("STUN_SERVER_PRIMARY", "stun:2.189.68.115:443"),
		STUNServerSecondary: getEnv("STUN_SERVER_SECONDARY", "stun:stun.l.google.com:19302"),
		TURNUsername:        getEnv("TURN_USERNAME", ""),
		TURNCredential:      getEnv("TURN_CREDENTIAL", ""),

		TUNIP:   getEnv("TUN_IP", "10.0.0.2"),
		TUNMask: getEnv("TUN_MASK", "255.255.255.0"),
		TUNMTU:  getEnvInt("TUN_MTU", 1000),
		TUNName: getEnv("TUN_NAME", "tun-ble"),

		SignalServerAddr: getEnv("SIGNAL_SERVER_ADDR", ""),

		AdminListenAddr: getEnv("ADMIN_LISTEN_ADDR", ":8080"),
		AdminUsername:    getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:    getEnv("ADMIN_PASSWORD", "changeme"),

		ObfuscationSecret: getEnv("OBFUSCATION_SECRET", ""),

		LogLevel: getEnv("LOG_LEVEL", "info"),
	}

	// Set defaults based on role
	if cfg.Role == "server" && cfg.TUNIP == "10.0.0.2" {
		cfg.TUNIP = "10.0.0.1"
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	if c.Role != "client" && c.Role != "server" {
		return fmt.Errorf("ROLE must be 'client' or 'server', got: %s", c.Role)
	}
	// Server can work with just BALE_ACCESS_TOKEN (gets LiveKit dynamically)
	if c.Role == "server" && c.BaleAccessToken == "" && c.LiveKitToken == "" {
		return fmt.Errorf("BALE_ACCESS_TOKEN or LIVEKIT_ACCESS_TOKEN is required for server")
	}
	return nil
}

// ICEServersConfig returns the ICE servers for WebRTC configuration.
func (c *Config) ICEServersConfig() []ICEServer {
	servers := []ICEServer{
		{URLs: []string{c.STUNServerPrimary}},
		{URLs: []string{c.STUNServerSecondary}},
	}

	// Add TURN servers with credentials
	if c.TURNUsername != "" && c.TURNCredential != "" {
		servers = append(servers,
			ICEServer{
				URLs:       []string{c.TURNServerPrimary},
				Username:   c.TURNUsername,
				Credential: c.TURNCredential,
			},
			ICEServer{
				URLs:       []string{c.TURNServerSecondary},
				Username:   c.TURNUsername,
				Credential: c.TURNCredential,
			},
		)
	} else {
		// Add TURN servers without credentials (will be populated from LiveKit)
		servers = append(servers,
			ICEServer{URLs: []string{c.TURNServerPrimary}},
			ICEServer{URLs: []string{c.TURNServerSecondary}},
		)
	}

	return servers
}

// ICEServer represents an ICE server configuration.
type ICEServer struct {
	URLs       []string
	Username   string
	Credential string
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return strings.TrimSpace(v)
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return defaultVal
	}
	return n
}
