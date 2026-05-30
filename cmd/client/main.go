package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/quic-go/quic-go"
	"github.com/salman/ble-webrtc-tun/internal/accounts"
	"github.com/salman/ble-webrtc-tun/internal/api"
	"github.com/salman/ble-webrtc-tun/internal/bale"
	"github.com/salman/ble-webrtc-tun/internal/config"
	"github.com/salman/ble-webrtc-tun/internal/db"
	"github.com/salman/ble-webrtc-tun/internal/dcconn"
	lk "github.com/salman/ble-webrtc-tun/internal/livekit"
	"github.com/salman/ble-webrtc-tun/internal/logger"
	"github.com/salman/ble-webrtc-tun/internal/pool"
	"github.com/salman/ble-webrtc-tun/internal/provider"
	"github.com/salman/ble-webrtc-tun/internal/quicconn"
	"github.com/salman/ble-webrtc-tun/internal/router"
	"github.com/salman/ble-webrtc-tun/internal/soroush"
)

var mainLog = logger.New("main")

// channelState holds the resources for one Bale/Soroush channel.
type channelState struct {
	index  int
	label  string
	client provider.Client
	sfu    *lk.SFUTransport
	pc     *webrtc.PeerConnection
	qconn  quic.Connection // QUIC connection for this channel
	cfg    *config.Config
	pair   config.TokenPair // pairing info for auto-reconnect
}

func main() {
	// Use all CPU cores
	runtime.GOMAXPROCS(0)

	// Initialize logging system
	if err := logger.Init("client"); err != nil {
		mainLog.Fatal("Logger init failed: %v", err)
	}
	defer logger.Close()

	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		logger.SetLevelFromString(lvl)
	}

	mainLog.Info("=== BLE WebRTC Tunnel — Client (Multi-Channel) ===")

	cfg, err := config.Load()
	if err != nil {
		mainLog.Fatal("Config: %v", err)
	}

	// Initialize database
	clientDB, err := db.Init("client")
	if err != nil {
		mainLog.Fatal(" Database init failed: %v", err)
	}
	defer clientDB.Close()

	// Auto-migrate from .env.tokens if DB is empty
	acctCount, _ := clientDB.CountAccounts("", "")
	if acctCount == 0 {
		if _, err := os.Stat(".env.tokens"); err == nil {
			mainLog.Info(" Empty DB — auto-migrating from .env.tokens")
			clientDB.MigrateFromEnvTokens(".env.tokens")
		}
	}

	// Initialize account manager and router
	accountMgr := accounts.NewManager(clientDB)
	callRouter := router.NewRouter(clientDB)
	defer callRouter.Close()

	// Start API server for client management panel
	apiAddr := os.Getenv("API_LISTEN_ADDR")
	if apiAddr == "" {
		apiAddr = ":6681" // Use 6681 for client to prevent conflict with server on 6680
	}
	apiSrv := api.NewServer(clientDB, accountMgr, callRouter, api.Config{})

	// Auto-detect remote server URL (used for manual sync from UI)
	serverURL := detectRemoteServerURL()
	apiSrv.RemoteServerURL = serverURL
	mainLog.Info("Remote server: %s", serverURL)

	// Auto-open browser when admin panel is ready
	go func() {
		time.Sleep(1 * time.Second)
		url := "http://localhost" + apiAddr
		mainLog.Info("Opening admin panel: %s", url)
		exec.Command("xdg-open", url).Start()
	}()

	// --disconnect mode
	if len(os.Args) > 1 && os.Args[1] == "--disconnect" {
		runDisconnect(clientDB)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Graceful shutdown
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		mainLog.Info(" Signal received, shutting down...")
		cancel()
		<-sigCh
		os.Exit(1)
	}()

	// Start API server
	go func() {
		if err := apiSrv.Start(ctx, apiAddr); err != nil {
			mainLog.Info(" API server error: %v", err)
		}
	}()

	// Initialize TunnelManager — loads pairings from DB dynamically on Start()
	tm := NewTunnelManager(cfg, clientDB, accountMgr)

	// Wire up API callbacks
	apiSrv.OnTunnelStart = func() error {
		return tm.Start()
	}
	apiSrv.OnTunnelStop = func() error {
		tm.Stop()
		return nil
	}
	apiSrv.GetTunnelStatus = func() (interface{}, error) {
		return tm.GetDetailedStatus(), nil
	}
	apiSrv.GetClientID = func() string {
		return tm.clientID
	}
	apiSrv.OnForceEndCall = func() (map[string]interface{}, error) {
		return tm.ForceEndCall()
	}

	mainLog.Info("Client initialized. Use admin panel to add accounts, create pairings, and connect.")

	<-ctx.Done()
	tm.Stop()
	mainLog.Info(" Shutting down...")
}

// ===================== Tunnel Manager =====================

// ChannelPhase represents the connection phase of a single channel.
type ChannelPhase string

const (
	PhaseInit          ChannelPhase = "INITIALIZING"
	PhaseBaleConnect   ChannelPhase = "CONNECTING_TO_BALE"
	PhaseCalling       ChannelPhase = "CALLING_SERVER"
	PhaseWaitAccept    ChannelPhase = "WAITING_FOR_ACCEPT"
	PhaseSFUConnect    ChannelPhase = "CONNECTING_TO_SFU"
	PhaseWaitTrack     ChannelPhase = "WAITING_FOR_TRACK"
	PhaseTunnelSetup   ChannelPhase = "SETTING_UP_TUNNEL"
	PhaseTunnelActive  ChannelPhase = "TUNNEL_ACTIVE"
	PhaseDisconnected  ChannelPhase = "DISCONNECTED"
	PhaseError         ChannelPhase = "ERROR"
)

// ChannelStatus tracks the live state of a single channel/pairing.
type ChannelStatus struct {
	Index         int          `json:"index"`
	Label         string       `json:"label"`
	Phase         ChannelPhase `json:"phase"`
	Error         string       `json:"error,omitempty"`
	ClientBaleID  int64        `json:"client_bale_id"`
	ServerBaleID  int64        `json:"server_bale_id"`
	StartedAt     time.Time    `json:"started_at"`
	ConnectedAt   *time.Time   `json:"connected_at,omitempty"`
	BytesSent     int64        `json:"bytes_sent"`
	BytesReceived int64        `json:"bytes_received"`

	// Per-channel health (populated from SFU transport)
	PubICEState  string `json:"pub_ice_state,omitempty"`
	SubICEState  string `json:"sub_ice_state,omitempty"`
	PubConnState string `json:"pub_conn_state,omitempty"`
	DCState      string `json:"dc_state,omitempty"`
	SFUHealthy   bool   `json:"sfu_healthy"`
	DCHealthy    bool   `json:"dc_healthy"`
	DCLatencyMs  int64  `json:"dc_latency_ms"`
}

// TunnelStatus is the detailed status returned by the API.
type TunnelStatus struct {
	Active         bool            `json:"active"`
	Phase          string          `json:"phase"` // overall phase
	ClientID       string          `json:"client_id"`
	Channels       []ChannelStatus `json:"channels"`
	TotalChannels  int             `json:"total_channels"`
	ActiveCount    int             `json:"active_count"`
	TotalSent      int64           `json:"total_sent"`
	TotalReceived  int64           `json:"total_received"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	Error          string          `json:"error,omitempty"`
	Mode           string          `json:"mode"` // "pairing" or "smart"
	ProxyAddresses []ProxyAddress  `json:"proxy_addresses,omitempty"`
}

// ProxyAddress represents a single proxy listener address.
type ProxyAddress struct {
	Type string `json:"type"` // "SOCKS5" or "HTTP"
	Addr string `json:"addr"` // e.g. "192.168.1.5:10909"
}

// TunnelManager controls the VPN tunnel lifecycle.
// It loads pairings from the database dynamically when Start() is called,
// ensuring it always uses the latest account and pairing configuration.
// Each client instance has a unique clientID for multi-user support.
type TunnelManager struct {
	mu       sync.Mutex
	cfg      *config.Config
	database *db.Database
	manager  *accounts.Manager
	clientID string // unique client identity for pairing ownership

	active    bool
	cancel    context.CancelFunc
	pool      *pool.TunnelPool
	pairCount int
	startedAt time.Time
	lastError string
	mode      string // "pairing" or "smart"

	// Per-channel state tracking (thread-safe via channelMu)
	channelMu      sync.RWMutex
	channelStatus  []ChannelStatus

	// Obfuscation layer (shared across all channels)
	obfuscator *dcconn.Obfuscator

}

func NewTunnelManager(cfg *config.Config, database *db.Database, manager *accounts.Manager) *TunnelManager {
	// Generate or load a stable client ID
	clientID := getOrCreateClientID(database)
	mainLog.Info("Client ID: %s", clientID)

	// Create obfuscator from shared secret (both client+server must match)
	var obf *dcconn.Obfuscator
	if cfg.ObfuscationSecret != "" {
		var err error
		obf, err = dcconn.NewObfuscator(cfg.ObfuscationSecret)
		if err != nil {
			mainLog.Error("Failed to create obfuscator: %v (running without obfuscation)", err)
		} else {
			mainLog.Info("ChaCha20-Poly1305 obfuscation enabled (overhead: %d bytes/msg)", obf.Overhead())
		}
	} else {
		mainLog.Warn("No OBFUSCATION_SECRET set — traffic is not obfuscated (DPI visible)")
	}

	return &TunnelManager{
		cfg:        cfg,
		database:   database,
		manager:    manager,
		clientID:   clientID,
		obfuscator: obf,
	}
}

// getOrCreateClientID generates or loads a persistent client ID.
// The ID is stored in the database as a setting. It's derived from
// the hostname + DB path to be unique per machine/instance.
func getOrCreateClientID(database *db.Database) string {
	// Check if already stored
	existing, err := database.GetSetting("client_id")
	if err == nil && existing != "" {
		return existing
	}

	// Generate from hostname + db path (deterministic per machine)
	hostname, _ := os.Hostname()
	seed := hostname + ":" + database.Path()
	hash := sha256.Sum256([]byte(seed))
	clientID := fmt.Sprintf("%x", hash[:8]) // 16-char hex

	// Store for future runs
	database.SetSetting("client_id", clientID)
	return clientID
}

func (tm *TunnelManager) IsActive() bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.active
}

// GetDetailedStatus returns the full tunnel status with per-channel details.
func (tm *TunnelManager) GetDetailedStatus() TunnelStatus {
	tm.mu.Lock()
	active := tm.active
	pairCount := tm.pairCount
	startedAt := tm.startedAt
	lastError := tm.lastError
	mode := tm.mode
	tm.mu.Unlock()

	tm.channelMu.RLock()
	channels := make([]ChannelStatus, len(tm.channelStatus))
	copy(channels, tm.channelStatus)
	tm.channelMu.RUnlock()

	var totalSent, totalRecv int64
	activeCount := 0
	overallPhase := "IDLE"
	if active {
		overallPhase = "CONNECTING"
		for _, ch := range channels {
			totalSent += ch.BytesSent
			totalRecv += ch.BytesReceived
			if ch.Phase == PhaseTunnelActive {
				activeCount++
			}
		}
		if activeCount > 0 {
			overallPhase = "CONNECTED"
		}
	}

	// Build proxy address list from all local IPs
	var proxyAddrs []ProxyAddress
	if active && activeCount > 0 {
		for _, ip := range getLocalIPs() {
			proxyAddrs = append(proxyAddrs, ProxyAddress{Type: "SOCKS5", Addr: ip + ":10909"})
			proxyAddrs = append(proxyAddrs, ProxyAddress{Type: "HTTP", Addr: ip + ":9095"})
		}
	}

	status := TunnelStatus{
		Active:         active,
		Phase:          overallPhase,
		ClientID:       tm.clientID,
		Channels:       channels,
		TotalChannels:  pairCount,
		ActiveCount:    activeCount,
		TotalSent:      totalSent,
		TotalReceived:  totalRecv,
		Error:          lastError,
		Mode:           mode,
		ProxyAddresses: proxyAddrs,
	}
	if !startedAt.IsZero() {
		status.StartedAt = &startedAt
	}
	return status
}

// setChannelPhase updates a channel's phase (thread-safe, non-blocking).
func (tm *TunnelManager) setChannelPhase(idx int, phase ChannelPhase, errMsg string) {
	if idx < 0 {
		return // warm connections don't track phases
	}
	tm.channelMu.Lock()
	if idx < len(tm.channelStatus) {
		tm.channelStatus[idx].Phase = phase
		if errMsg != "" {
			tm.channelStatus[idx].Error = errMsg
		}
		if phase == PhaseTunnelActive {
			now := time.Now()
			tm.channelStatus[idx].ConnectedAt = &now
		}
	}
	tm.channelMu.Unlock()
}

// updateChannelStats updates traffic stats for a channel (called periodically).
func (tm *TunnelManager) updateChannelStats(idx int, sent, recv int64) {
	tm.channelMu.Lock()
	if idx < len(tm.channelStatus) {
		tm.channelStatus[idx].BytesSent = sent
		tm.channelStatus[idx].BytesReceived = recv
	}
	tm.channelMu.Unlock()
}

// updateChannelHealth populates per-channel health from the SFU transport.
func (tm *TunnelManager) updateChannelHealth(idx int, sfu *lk.SFUTransport) {
	if sfu == nil {
		return
	}
	health := sfu.GetHealth()
	tm.channelMu.Lock()
	if idx < len(tm.channelStatus) {
		tm.channelStatus[idx].PubICEState = health.PubICEState
		tm.channelStatus[idx].SubICEState = health.SubICEState
		tm.channelStatus[idx].PubConnState = health.PubConnState
		tm.channelStatus[idx].DCState = health.DCState
		tm.channelStatus[idx].SFUHealthy = health.SFUHealthy
		tm.channelStatus[idx].DCHealthy = health.DCHealthy
		tm.channelStatus[idx].DCLatencyMs = health.DCLatencyMs
	}
	tm.channelMu.Unlock()
}

func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if !tm.active {
		return
	}
	tm.active = false
	if tm.cancel != nil {
		tm.cancel()
		tm.cancel = nil
	}
	if tm.pool != nil {
		tm.pool.CloseAll()
		tm.pool = nil
	}
	// Mark all channels as disconnected
	tm.channelMu.Lock()
	for i := range tm.channelStatus {
		if tm.channelStatus[i].Phase != PhaseError {
			tm.channelStatus[i].Phase = PhaseDisconnected
		}
	}
	tm.channelMu.Unlock()
	mainLog.Info("[Manager] Tunnel stopped.")
}

// ForceEndCall sends BLETUN:ENDCALL to all paired server accounts via Bale,
// waits for BLETUN:ENDCALL_ACK from each, then cleans up messages.
// This forces the server to end any active call and become ready for new calls.
// Works even when the tunnel is not active (e.g. after a sudden disconnect).
func (tm *TunnelManager) ForceEndCall() (map[string]interface{}, error) {
	// Load pairings from database
	pairings, err := tm.database.ListActivePairingsByOwner(tm.clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to load pairings: %w", err)
	}

	// Fallback: if no owner pairings, try all active pairings
	if len(pairings) == 0 {
		pairings, err = tm.database.ListActivePairings()
		if err != nil {
			return nil, fmt.Errorf("failed to load pairings: %w", err)
		}
	}

	if len(pairings) == 0 {
		return nil, fmt.Errorf("no active pairings found")
	}

	results := make([]map[string]interface{}, 0, len(pairings))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range pairings {
		if p.ClientAccount == nil || p.ServerAccount == nil {
			continue
		}
		if p.ClientAccount.Token == "" {
			continue
		}

		wg.Add(1)
		go func(clientToken string, serverBaleID int64, pairingID uint) {
			defer wg.Done()

			result := map[string]interface{}{
				"pairing_id":     pairingID,
				"server_bale_id": serverBaleID,
				"status":         "unknown",
			}

			label := fmt.Sprintf("[EndCall P%d]", pairingID)
			mainLog.Info("%s Connecting to Bale...", label)

			// Connect to Bale
			client := bale.NewClient(clientToken)
			if err := client.Connect(); err != nil {
				mainLog.Error("%s Bale connect failed: %v", label, err)
				result["status"] = "connect_failed"
				result["error"] = err.Error()
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}
			defer client.Close()
			client.StartPingLoop()
			time.Sleep(1 * time.Second)

			// Send ENDCALL command
			mainLog.Info("%s Sending ENDCALL to %d...", label, serverBaleID)
			if err := client.SendTextMessage(serverBaleID, "BLETUN:ENDCALL"); err != nil {
				mainLog.Error("%s Failed to send ENDCALL: %v", label, err)
				result["status"] = "send_failed"
				result["error"] = err.Error()
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}

			// Wait for ENDCALL_ACK (up to 15 seconds)
			mainLog.Info("%s Waiting for ACK (15s timeout)...", label)
			ackReceived := false
			timeout := time.After(15 * time.Second)

			for !ackReceived {
				select {
				case msg := <-client.TextMsgCh:
					if msg == "BLETUN:ENDCALL_ACK" {
						mainLog.Info("%s ✅ ACK received!", label)
						ackReceived = true
					} else {
						mainLog.Info("%s Ignoring message: %s", label, msg)
					}
				case <-timeout:
					mainLog.Warn("%s Timeout waiting for ACK", label)
					result["status"] = "timeout"
					result["error"] = "no ACK received within 15s"
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					// Still clean up messages
					client.CleanupMessages()
					return
				}
			}

			// Clean up all messages (command + ACK)
			mainLog.Info("%s Cleaning up messages...", label)
			time.Sleep(500 * time.Millisecond)
			client.CleanupMessages()
			time.Sleep(500 * time.Millisecond)

			result["status"] = "success"
			mainLog.Info("%s ✅ Force end call complete", label)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(p.ClientAccount.Token, p.ServerAccount.BaleUserID, p.ID)
	}

	wg.Wait()

	// Count successes
	successCount := 0
	for _, r := range results {
		if r["status"] == "success" {
			successCount++
		}
	}

	return map[string]interface{}{
		"total":    len(results),
		"success":  successCount,
		"channels": results,
	}, nil
}

// loadPairsFromDB loads active pairings from the database scoped to this
// client's owner ID, converts them to TokenPair format for initChannel.
// If no pairings exist, it attempts auto-pairing first.
func (tm *TunnelManager) loadPairsFromDB() ([]config.TokenPair, string, error) {
	// First, check for active pairings belonging to this client
	pairings, err := tm.database.ListActivePairingsByOwner(tm.clientID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load pairings: %w", err)
	}

	mode := "pairing"

	// If no pairings for this owner, attempt auto-pairing (smart mode)
	if len(pairings) == 0 {
		count, _ := tm.manager.AutoPairUnmatched(tm.clientID)
		if count > 0 {
			mainLog.Info("[Manager] Smart-paired %d accounts for client %s", count, tm.clientID)
			pairings, _ = tm.database.ListActivePairingsByOwner(tm.clientID)
			mode = "smart"
		}
	}

	// Convert DB pairings to TokenPair format
	var pairs []config.TokenPair
	for i, p := range pairings {
		if p.ClientAccount == nil || p.ServerAccount == nil {
			mainLog.Warn("[Manager] Pairing %d has missing account — skipping", p.ID)
			continue
		}
		clientProv := p.ClientAccount.ProviderType
		if clientProv == "" {
			clientProv = "bale"
		}
		serverProv := p.ServerAccount.ProviderType
		if serverProv == "" {
			serverProv = "bale"
		}

		if clientProv == "bale" && p.ClientAccount.Token == "" {
			mainLog.Warn("[Manager] Client account %d has empty token — skipping", p.ClientAccount.ID)
			continue
		}
		if clientProv == "soroush" && len(p.ClientAccount.AuthKey) == 0 {
			mainLog.Warn("[Manager] Client account %d has empty auth key — skipping", p.ClientAccount.ID)
			continue
		}

		// Always use ExternalID — works for any provider combination (bale↔bale, soroush↔soroush, bale↔soroush)
		targetID := p.ServerAccount.ExternalID
		if targetID == 0 {
			targetID = p.ServerAccount.BaleUserID
		}

		pairs = append(pairs, config.TokenPair{
			Index:        i + 1,
			Provider:     clientProv,
			ClientToken:  p.ClientAccount.Token,
			TargetUserID: targetID,
			AuthKey:      p.ClientAccount.AuthKey,
			AuthKeyID:    p.ClientAccount.AuthKeyID,
			ServerSalt:   p.ClientAccount.ServerSalt,
			AccessHash:   p.ServerAccount.AccessHash,
		})
		mainLog.Info("[Manager] Pair %d: client=%d (%s ext=%d) → server=%d (%s ext=%d) [owner=%s]",
			i+1, p.ClientAccountID, clientProv, p.ClientAccount.ExternalID,
			p.ServerAccountID, serverProv, p.ServerAccount.ExternalID, tm.clientID)
	}

	if len(pairs) == 0 {
		// Check what's missing to give a clear error
		clientCount, _ := tm.database.CountAccounts("CLIENT", "")
		serverCount, _ := tm.database.CountAccounts("SERVER", "")
		if clientCount == 0 && serverCount == 0 {
			return nil, "", fmt.Errorf("no accounts found — add CLIENT and SERVER accounts first via the Accounts page")
		}
		if clientCount == 0 {
			return nil, "", fmt.Errorf("no CLIENT accounts found — add client accounts via the Accounts page")
		}
		if serverCount == 0 {
			return nil, "", fmt.Errorf("no SERVER accounts found — server accounts are synced from the remote server. Check sync status")
		}
		return nil, "", fmt.Errorf("no active pairings for this client (ID=%s) — go to the Pairings page and create pairings or use Auto-Pair", tm.clientID)
	}

	return pairs, mode, nil
}

func (tm *TunnelManager) Start() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.active {
		return fmt.Errorf("tunnel already running")
	}

	// Load pairings from database dynamically
	pairs, mode, err := tm.loadPairsFromDB()
	if err != nil {
		tm.lastError = err.Error()
		return err
	}

	mainLog.Info("[Manager] Starting tunnel with %d pairings (%s mode)", len(pairs), mode)

	// Initialize per-channel status tracking
	tm.channelMu.Lock()
	tm.channelStatus = make([]ChannelStatus, len(pairs))
	for i, p := range pairs {
		tm.channelStatus[i] = ChannelStatus{
			Index:        p.Index,
			Label:        fmt.Sprintf("ch%d", p.Index),
			Phase:        PhaseInit,
			ClientBaleID: 0, // Will be filled from JWT if needed
			ServerBaleID: p.TargetUserID,
			StartedAt:    time.Now(),
		}
	}
	tm.channelMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	tm.active = true
	tm.cancel = cancel
	tm.pool = pool.New()
	tm.pairCount = len(pairs)
	tm.startedAt = time.Now()
	tm.lastError = ""
	tm.mode = mode

	go tm.runTunnels(ctx, tm.pool, pairs)
	return nil
}

func (tm *TunnelManager) runTunnels(ctx context.Context, tunnelPool *pool.TunnelPool, pairs []config.TokenPair) {
	var channels []*channelState
	var mu sync.Mutex
	var proxyOnce sync.Once

	// === PARALLEL CONNECTION ===
	// Dial all channels concurrently so the pool is fully populated before
	// heavy traffic starts. Sequential dialing let ch1 absorb 100% of traffic
	// while ch2..chN were still handshaking — now all connect in parallel.
	//
	// A 2s × index stagger avoids hammering the SFU simultaneously, but total
	// startup time is now ~1 channel RTT + stagger instead of N × RTT.
	var wg sync.WaitGroup
	for i, pair := range pairs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(i int, pair config.TokenPair) {
			defer wg.Done()

			label := fmt.Sprintf("ch%d", pair.Index)

			// Stagger: 2s × index (ch1=0s, ch2=2s, ch3=4s, ch4=6s…)
			if i > 0 {
				tm.setChannelPhase(i, PhaseInit, "")
				stagger := time.Duration(i) * 2 * time.Second
				mainLog.Info("[%s] 🕐 Stagger %.0fs (parallel dial)...", label, stagger.Seconds())
				select {
				case <-ctx.Done():
					return
				case <-time.After(stagger):
				}
			}

			tm.setChannelPhase(i, PhaseBaleConnect, "")
			mainLog.Info("[%s] 🔗 Connecting pair %d/%d (parallel)...", label, i+1, len(pairs))

			ch, qconn := tm.initChannelTracked(ctx, i, pair, label)
			if ch == nil || qconn == nil {
				mainLog.Warn("[%s] ❌ Channel init failed", label)
				tm.setChannelPhase(i, PhaseError, "init failed")
				return
			}

			tm.setChannelPhase(i, PhaseTunnelActive, "")
			tunnelPool.Add(qconn, label)
			mu.Lock()
			channels = append(channels, ch)
			mu.Unlock()
			mainLog.Info("[%s] ✅ Channel ready! (%d/%d connected)", label, tunnelPool.ActiveCount(), len(pairs))

			// Start proxies as soon as first channel is ready
			proxyOnce.Do(func() {
				go startSOCKS5(ctx, "0.0.0.0:10909", tunnelPool)
				go startHTTPProxy(ctx, "0.0.0.0:9095", tunnelPool)
				mainLog.Info(" ✅ Proxies started on ALL interfaces (first channel ready)!")
				for _, ip := range getLocalIPs() {
					mainLog.Info("  SOCKS5: %s:10909  |  HTTP: %s:9095", ip, ip)
				}
			})

			go tm.monitorAndReconnect(ctx, tunnelPool, ch, qconn, i, pair, label, &mu, &channels, &proxyOnce)
		}(i, pair)
	}

	// Wait for all parallel dials to complete before checking results
	wg.Wait()

	if ctx.Err() != nil {
		return
	}

	active := tunnelPool.ActiveCount()
	if active == 0 {
		mainLog.Info("[Main] ❌ No channels established! Cannot start proxy.")
		tm.mu.Lock()
		tm.lastError = "all channels failed to connect"
		tm.mu.Unlock()
		tm.Stop()
		return
	}
	mainLog.Info(" 🟢 %d/%d channels active — READY", active, len(pairs))

	// Health monitor + stats (lightweight sampling, doesn't affect VPN throughput)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mainLog.Info("[Manager] Shutting down connections...")

			// Send END and cleanup on all channels
			mu.Lock()
			chs := make([]*channelState, len(channels))
			copy(chs, channels)
			mu.Unlock()

			for _, ch := range chs {
				ch.client.SendTextMessage(ch.cfg.BaleTargetUserID, "BLETUN:END")
			}
			time.Sleep(300 * time.Millisecond)
			for _, ch := range chs {
				ch.client.CleanupMessages()
				ch.sfu.Close()
				ch.client.Close()
			}
			tunnelPool.CloseAll()
			return

		case <-ticker.C:
			act := tunnelPool.ActiveCount()
			if act == 0 {
				mainLog.Info("[Health] ❌ All channels dead!")
				tm.mu.Lock()
				tm.lastError = "all channels disconnected"
				tm.mu.Unlock()
				tm.Stop()
				return
			}
			// Update per-channel stats and health (lightweight — just read counters)
			mu.Lock()
			for _, ch := range channels {
				stats := ch.sfu.GetStats()
				var sent, recv int64
				if s, ok := stats["bytes_sent"].(int64); ok {
					sent = s
				}
				if r, ok := stats["bytes_received"].(int64); ok {
					recv = r
				}
				tm.updateChannelStats(ch.index-1, sent, recv)
				tm.updateChannelHealth(ch.index-1, ch.sfu)
			}
			mu.Unlock()
		}
	}
}


// monitorAndReconnect watches a QUIC connection and auto-reconnects on failure.
//
// Three detection paths (all trigger immediate reconnect):
//  1. QUIC context cancelled (connection closed by QUIC layer or circuit breaker)
//  2. WebRTC ICE layer disconnected/failed (binds WebRTC to QUIC lifecycle)
//  3. SFU WebSocket unhealthy (no pong for 60s)
func (tm *TunnelManager) monitorAndReconnect(
	ctx context.Context,
	tunnelPool *pool.TunnelPool,
	ch *channelState,
	qconn quic.Connection,
	idx int,
	tp config.TokenPair,
	label string,
	mu *sync.Mutex,
	channels *[]*channelState,
	proxyOnce *sync.Once,
) {
	backoff := 3 * time.Second
	const maxBackoff = 30 * time.Second

	currentQConn := qconn
	currentCh := ch

	for {
		// ── Liveness check every 3s ───────────────────────────────────────
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}

		dead := false

		// Check 1: QUIC connection context (catches circuit-breaker kills too)
		if currentQConn != nil {
			select {
			case <-currentQConn.Context().Done():
				mainLog.Warn("[%s] 💀 QUIC connection dead (context cancelled)", label)
				dead = true
			default:
			}
		}

		// Check 2: WebRTC ICE state — kill QUIC immediately rather than
		// waiting for QUIC's 30-60s idle timeout.
		if !dead && currentCh != nil && currentCh.sfu != nil {
			health := currentCh.sfu.GetHealth()
			if health.PubICEState == "disconnected" || health.PubICEState == "failed" ||
				health.SubICEState == "disconnected" || health.SubICEState == "failed" {
				mainLog.Warn("[%s] ⚠️ WebRTC ICE is %s/%s — force-killing QUIC",
					label, health.PubICEState, health.SubICEState)
				dead = true
			}
			if !dead && !health.SFUHealthy {
				mainLog.Warn("[%s] ⚠️ SFU WS unhealthy — force-killing QUIC", label)
				dead = true
			}
		}

		if !dead {
			continue // still alive
		}

		// ── Reconnect flow ────────────────────────────────────────────────
		mainLog.Warn("[%s] 💀 Channel dead — reconnecting (backoff: %.0fs)", label, backoff.Seconds())
		tm.setChannelPhase(idx, PhaseDisconnected, "channel dead, reconnecting...")

		if currentQConn != nil {
			tunnelPool.Remove(currentQConn)
			currentQConn.CloseWithError(0, "reconnecting")
		}
		if currentCh != nil {
			go func(c *channelState) { c.client.CleanupMessages() }(currentCh)
			time.Sleep(500 * time.Millisecond)
			if currentCh.sfu != nil {
				currentCh.sfu.Close()
			}
			currentCh.client.Close()
		}

		mu.Lock()
		for i, c := range *channels {
			if c == currentCh {
				*channels = append((*channels)[:i], (*channels)[i+1:]...)
				break
			}
		}
		mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		tm.setChannelPhase(idx, PhaseBaleConnect, "")
		newCh, newQConn := tm.initChannelTracked(ctx, idx, tp, label)
		if newCh == nil || newQConn == nil {
			mainLog.Warn("[%s] ❌ Reconnect failed — retrying in %.0fs", label, backoff.Seconds())
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}

		tm.setChannelPhase(idx, PhaseTunnelActive, "")
		tunnelPool.Add(newQConn, label)
		mu.Lock()
		*channels = append(*channels, newCh)
		mu.Unlock()
		mainLog.Info("[%s] ✅ Reconnected!", label)

		backoff = 3 * time.Second
		currentQConn = newQConn
		currentCh = newCh

		proxyOnce.Do(func() {
			go startSOCKS5(ctx, "0.0.0.0:10909", tunnelPool)
			go startHTTPProxy(ctx, "0.0.0.0:9095", tunnelPool)
		})

		// Brief stabilisation pause before resuming monitoring
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// initChannelTracked wraps initChannel with phase tracking callbacks.
func (tm *TunnelManager) initChannelTracked(ctx context.Context, idx int, tp config.TokenPair, label string) (*channelState, quic.Connection) {
	chanCfg := *tm.cfg
	chanCfg.BaleAccessToken = tp.ClientToken
	chanCfg.BaleTargetUserID = tp.TargetUserID

	providerType := tp.Provider
	if providerType == "" {
		providerType = "bale"
	}

	tm.setChannelPhase(idx, PhaseBaleConnect, "Connecting to "+providerType+"...")
	mainLog.Info("[%s] Connecting to %s...", label, providerType)

	factory, ok := provider.GetFactory(provider.ProviderType(providerType))
	if !ok {
		tm.setChannelPhase(idx, PhaseError, "No factory for provider: "+providerType)
		return nil, nil
	}

	acctData := map[string]interface{}{
		"token":       tp.ClientToken,
		"external_id": tp.TargetUserID,
		"access_hash": tp.AccessHash,
		"auth_key":    tp.AuthKey,
		"auth_key_id": tp.AuthKeyID,
		"server_salt": tp.ServerSalt,
	}

	client, err := factory.NewClient(acctData)
	if err != nil {
		tm.setChannelPhase(idx, PhaseError, "Factory initialization failed: "+err.Error())
		return nil, nil
	}

	if err := client.Connect(); err != nil {
		tm.setChannelPhase(idx, PhaseError, providerType+" connection failed: "+err.Error())
		mainLog.Info("[%s] connect: %v", label, err)
		return nil, nil
	}
	client.StartPingLoop()

	mainLog.Info("[%s] Sending warmup message to %d...", label, tp.TargetUserID)
	client.SendTextMessage(tp.TargetUserID, "BLETUN:PING")
	time.Sleep(2 * time.Second)

	tm.setChannelPhase(idx, PhaseCalling, "Calling server...")
	mainLog.Info("[%s] Calling user %d...", label, tp.TargetUserID)

	result, err := client.InitiateCall(ctx, tp.TargetUserID, tp.AccessHash)
	if err != nil {
		tm.setChannelPhase(idx, PhaseError, "Initiate call failed: "+err.Error())
		mainLog.Info("[%s] InitiateCall: %v", label, err)
		client.Close()
		return nil, nil
	}

	if providerType == "bale" {
		wssURL := result.WssURL
		if len(wssURL) > 0 && wssURL[len(wssURL)-1] == '(' {
			wssURL = wssURL[:len(wssURL)-1]
		}
		chanCfg.LiveKitToken = result.LivekitToken
		chanCfg.LiveKitWSURL = wssURL + "/rtc"
		mainLog.Info("[%s] ✅ Call accepted! Room: %s", label, result.RoomID)

		tm.setChannelPhase(idx, PhaseSFUConnect, "Connecting to LiveKit SFU...")
		mainLog.Info("[%s] Connecting to SFU...", label)
		sfu := lk.NewSFUTransport(&chanCfg, tm.obfuscator)
		if err := sfu.Connect(ctx); err != nil {
			tm.setChannelPhase(idx, PhaseError, "SFU connection failed: "+err.Error())
			mainLog.Info("[%s] SFU connect: %v", label, err)
			client.Close()
			return nil, nil
		}

		tm.setChannelPhase(idx, PhaseWaitTrack, "Waiting for media track...")
		mainLog.Info("[%s] Waiting for server track (30s)...", label)
		connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := sfu.WaitForConnection(connCtx); err != nil {
			connCancel()
			tm.setChannelPhase(idx, PhaseError, "Timed out waiting for server media track: "+err.Error())
			mainLog.Info("[%s] Connection timeout: %v", label, err)
			sfu.Close()
			client.Close()
			return nil, nil
		}
		connCancel()

		tm.setChannelPhase(idx, PhaseTunnelSetup, "Dialing QUIC over Opus RTP...")
		rtpConn := sfu.GetRTPConn()
		if rtpConn == nil {
			tm.setChannelPhase(idx, PhaseError, "RTP connection not ready")
			mainLog.Info("[%s] GetRTPConn() returned nil", label)
			sfu.Close()
			client.Close()
			return nil, nil
		}

		opusPC := quicconn.NewClient(rtpConn)
		tlsCfg := quicconn.ClientTLSConfig()
		initPktSize := uint16(1140)
		if tm.obfuscator != nil && tm.obfuscator.Enabled() {
			initPktSize = 1100
		}
		quicCfg := &quic.Config{
			InitialPacketSize:              initPktSize,
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                5 * time.Second,
			InitialStreamReceiveWindow:     2 * 1024 * 1024,
			MaxStreamReceiveWindow:         16 * 1024 * 1024,
			InitialConnectionReceiveWindow: 4 * 1024 * 1024,
			MaxConnectionReceiveWindow:     16 * 1024 * 1024,
			DisablePathMTUDiscovery:        true,
		}

		mainLog.Info("[%s] Dialing QUIC over Opus RTP tunnel...", label)
		dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
		qConn, err := quic.Dial(dialCtx, opusPC, quicconn.RemoteAddr(), tlsCfg, quicCfg)
		dialCancel()
		if err != nil {
			tm.setChannelPhase(idx, PhaseError, "QUIC dial failed: "+err.Error())
			mainLog.Info("[%s] QUIC dial: %v", label, err)
			sfu.Close()
			client.Close()
			return nil, nil
		}
		mainLog.Info("[%s] ✅ QUIC connection established!", label)

		ch := &channelState{
			index:  tp.Index,
			label:  label,
			client: client,
			sfu:    sfu,
			cfg:    &chanCfg,
			pair:   tp,
		}
		return ch, qConn

	} else {
		// ── Soroush P2P: WebRTC DataChannel → DCPacketConn → QUIC ──────────
		mainLog.Info("[%s] ✅ Soroush call accepted! Setting up P2P WebRTC...", label)
		tm.setChannelPhase(idx, PhaseSFUConnect, "Connecting P2P WebRTC...")

		// Build ICE server list from call result
		iceServers := make([]webrtc.ICEServer, 0, len(result.Connections))
		for _, conn := range result.Connections {
			ice := webrtc.ICEServer{URLs: []string{conn.URL}}
			if conn.Username != "" {
				ice.Username = conn.Username
				ice.Credential = conn.Password
				ice.CredentialType = webrtc.ICECredentialTypePassword
			}
			iceServers = append(iceServers, ice)
		}

		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{
			ICEServers:    iceServers,
			BundlePolicy:  webrtc.BundlePolicyMaxBundle,
			RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
		})
		if err != nil {
			tm.setChannelPhase(idx, PhaseError, "PeerConnection failed: "+err.Error())
			client.Close()
			return nil, nil
		}

		// Dummy Opus track for call camouflage (DPI sees a voice call)
		audioTrack, err := webrtc.NewTrackLocalStaticSample(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
			"audio0", "soroush-voice-stream",
		)
		if err != nil || func() error { _, e := pc.AddTrack(audioTrack); return e }() != nil {
			tm.setChannelPhase(idx, PhaseError, "Audio track failed")
			pc.Close()
			client.Close()
			return nil, nil
		}

		// DataChannel — ordered, reliable (message-oriented, so DCPacketConn works directly)
		ordered := true
		dc, err := pc.CreateDataChannel("quic-tunnel", &webrtc.DataChannelInit{Ordered: &ordered})
		if err != nil {
			tm.setChannelPhase(idx, PhaseError, "DataChannel failed: "+err.Error())
			pc.Close()
			client.Close()
			return nil, nil
		}

		// Channels for async signaling
		pendingICE := make(chan string, 64)
		dcOpenCh := make(chan *soroush.DCPacketConn, 1)

		pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c != nil {
				select {
				case pendingICE <- c.ToJSON().Candidate:
				default:
				}
			}
		})

		// Wrap DC as PacketConn the moment it opens
		dc.OnOpen(func() {
			dcOpenCh <- soroush.NewDCPacketConn(dc)
		})

		// Create and send SDP offer
		offer, err := pc.CreateOffer(nil)
		if err != nil || pc.SetLocalDescription(offer) != nil {
			tm.setChannelPhase(idx, PhaseError, "SDP offer failed")
			pc.Close()
			client.Close()
			return nil, nil
		}
		if err := client.SendTextMessage(tp.TargetUserID, soroush.FormatSDPOffer(offer.SDP)); err != nil {
			tm.setChannelPhase(idx, PhaseError, "Send SDP offer failed")
			pc.Close()
			client.Close()
			return nil, nil
		}

		mainLog.Info("[%s] SDP offer sent. Waiting for answer...", label)
		tm.setChannelPhase(idx, PhaseWaitTrack, "Waiting for SDP Answer...")

		// SDP answer + ICE exchange goroutine
		answerDone := make(chan struct{})
		sdpCtx, sdpCancel := context.WithCancel(ctx)
		defer sdpCancel()

		go func() {
			defer close(answerDone)
			for {
				select {
				case <-sdpCtx.Done():
					return
				case text := <-client.GetTextMsgCh():
					if soroush.IsSDPAnswer(text) {
						sdpStr := soroush.ExtractSDP(text)
						if err := pc.SetRemoteDescription(webrtc.SessionDescription{
							Type: webrtc.SDPTypeAnswer, SDP: sdpStr,
						}); err != nil {
							mainLog.Error("[%s] SetRemoteDescription: %v", label, err)
							return
						}
						// Drain pending ICE candidates
						go func() {
							for {
								select {
								case c := <-pendingICE:
									client.SendTextMessage(tp.TargetUserID, soroush.FormatICECandidate(c))
								case <-sdpCtx.Done():
									return
								}
							}
						}()
						return
					}
					if soroush.IsICECandidate(text) {
						pc.AddICECandidate(webrtc.ICECandidateInit{
							Candidate: soroush.ExtractICECandidate(text),
						})
					}
				}
			}
		}()

		// Wait for SDP answer
		select {
		case <-answerDone:
		case <-time.After(30 * time.Second):
			tm.setChannelPhase(idx, PhaseError, "SDP Answer timeout (30s)")
			pc.Close()
			client.Close()
			return nil, nil
		case <-ctx.Done():
			pc.Close()
			client.Close()
			return nil, nil
		}

		mainLog.Info("[%s] SDP answered. Waiting for DataChannel open...", label)
		tm.setChannelPhase(idx, PhaseTunnelSetup, "Waiting for DataChannel...")

		var dcPC *soroush.DCPacketConn
		select {
		case dcPC = <-dcOpenCh:
		case <-time.After(15 * time.Second):
			tm.setChannelPhase(idx, PhaseError, "DataChannel open timeout (15s)")
			pc.Close()
			client.Close()
			return nil, nil
		case <-ctx.Done():
			pc.Close()
			client.Close()
			return nil, nil
		}

		// Dial QUIC over the DataChannel PacketConn
		tm.setChannelPhase(idx, PhaseTunnelSetup, "Dialing QUIC over DataChannel...")
		mainLog.Info("[%s] DataChannel open! Dialing QUIC...", label)

		quicCfg := &quic.Config{
			InitialPacketSize:              1200, // DC has no MTU constraint like Opus RTP
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
			InitialStreamReceiveWindow:     2 * 1024 * 1024,
			MaxStreamReceiveWindow:         16 * 1024 * 1024,
			InitialConnectionReceiveWindow: 4 * 1024 * 1024,
			MaxConnectionReceiveWindow:     16 * 1024 * 1024,
			DisablePathMTUDiscovery:        true,
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
		qConn, err := quic.Dial(dialCtx, dcPC, soroush.RemoteDCAddr(), quicconn.ClientTLSConfig(), quicCfg)
		dialCancel()
		if err != nil {
			tm.setChannelPhase(idx, PhaseError, "QUIC dial failed: "+err.Error())
			mainLog.Info("[%s] QUIC dial: %v", label, err)
			dcPC.Close()
			pc.Close()
			client.Close()
			return nil, nil
		}
		mainLog.Info("[%s] ✅ QUIC connection established over Soroush DataChannel!", label)

		ch := &channelState{
			index:  tp.Index,
			label:  label,
			client: client,
			pc:     pc,
			qconn:  qConn,
			cfg:    &chanCfg,
			pair:   tp,
		}
		return ch, qConn
	}
}

// initChannel is kept for reference but is no longer called.
// All channel initialization goes through initChannelTracked.
func initChannel(_ context.Context, _ *config.Config, _ config.TokenPair, _ string, _ *dcconn.Obfuscator) (*channelState, quic.Connection) {
	return nil, nil
}

// getLocalIPs returns all non-loopback IPv4 addresses from local network
// interfaces, plus 127.0.0.1. These are the addresses the proxy is reachable on.
func getLocalIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"127.0.0.1"}
	}
	for _, iface := range ifaces {
		// Skip down, loopback, and point-to-point interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// Only include IPv4 (not IPv6)
			if ip == nil || ip.To4() == nil {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	// Always include loopback
	ips = append(ips, "127.0.0.1")
	return ips
}

// ===================== SOCKS5 Proxy =====================

func startSOCKS5(ctx context.Context, addr string, p *pool.TunnelPool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		mainLog.Fatal("[SOCKS5] Listen error: %v", err)
	}
	defer ln.Close()
	mainLog.Info("[SOCKS5] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleSOCKS5(conn, p)
	}
}

func handleSOCKS5(conn net.Conn, p *pool.TunnelPool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Greeting
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	// Accept no-auth
	conn.Write([]byte{0x05, 0x00})

	// 2. Request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse address
	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		ip := net.IP(buf[4:8])
		port := binary.BigEndian.Uint16(buf[8:10])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := binary.BigEndian.Uint16(buf[20:22])
		targetAddr = fmt.Sprintf("[%s]:%d", ip, port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})

	dialAndRelay(p, targetAddr, conn)
}

// ===================== HTTP CONNECT Proxy =====================

func startHTTPProxy(ctx context.Context, addr string, p *pool.TunnelPool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		mainLog.Fatal("[HTTP] Listen error: %v", err)
	}
	defer ln.Close()
	mainLog.Info("[HTTP] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleHTTPProxy(conn, p)
	}
}

func handleHTTPProxy(conn net.Conn, p *pool.TunnelPool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	target := parts[1]

	// Read headers
	var headersBuilder strings.Builder
	for {
		hdr, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		headersBuilder.WriteString(hdr)
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}
	headersStr := headersBuilder.String()

	if method == "CONNECT" {
		// HTTPS tunnel
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		conn.SetDeadline(time.Time{})
		dialAndRelay(p, target, conn)
		return
	}

	// Plain HTTP — forward through tunnel
	host := target
	path := target
	if strings.HasPrefix(target, "http://") {
		host = strings.TrimPrefix(target, "http://")
		if idx := strings.Index(host, "/"); idx >= 0 {
			path = host[idx:]
			host = host[:idx]
		} else {
			path = "/"
		}
	}
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	reqLine := fmt.Sprintf("%s %s %s\r\n%s", method, path, parts[2], headersStr)
	conn.SetDeadline(time.Time{})

	// Open stream from pool
	stream, err := p.OpenStream()
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer stream.Close()

	// Send target address as length-prefixed header
	addrBytes := []byte(host)
	hdr := make([]byte, 2+len(addrBytes))
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(addrBytes)))
	copy(hdr[2:], addrBytes)
	if _, err := stream.Write(hdr); err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}

	// Send the HTTP request
	stream.Write([]byte(reqLine))

	// Bidirectional relay using 256KB buffers
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(stream, conn, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(conn, stream, buf)
		done <- struct{}{}
	}()
	<-done
}

// ===================== Common Relay =====================

// dialAndRelay opens a stream from the pool, sends the target address, then relays data.
func dialAndRelay(p *pool.TunnelPool, addr string, localConn net.Conn) {
	stream, err := p.OpenStream()
	if err != nil {
		mainLog.Info("[Relay] pool open: %v", err)
		return
	}
	defer stream.Close()

	// Send target address as length-prefixed header: [2 bytes len][addr]
	addrBytes := []byte(addr)
	hdr := make([]byte, 2+len(addrBytes))
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(addrBytes)))
	copy(hdr[2:], addrBytes)
	if _, err := stream.Write(hdr); err != nil {
		mainLog.Info("[Relay] write addr: %v", err)
		return
	}

	// Bidirectional relay using 256KB buffers (reduces syscall overhead over TURN relay)
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(stream, localConn, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(localConn, stream, buf)
		done <- struct{}{}
	}()
	<-done
}

// runDisconnect connects to each Bale/Soroush account, ends active calls,
// deletes all messages from all chats, and exits cleanly.
func runDisconnect(database *db.Database) {
	mainLog.Info("[Disconnect] 🧹 Cleaning up all accounts...")

	// Load pairings from database
	pairings, _ := database.ListActivePairings()
	var pairs []config.TokenPair
	for i, p := range pairings {
		if p.ClientAccount == nil || p.ServerAccount == nil {
			continue
		}
		clientProv := p.ClientAccount.ProviderType
		if clientProv == "" {
			clientProv = "bale"
		}
		var targetID int64
		if clientProv == "soroush" {
			targetID = p.ServerAccount.ExternalID
		} else {
			targetID = p.ServerAccount.BaleUserID
			if targetID == 0 {
				targetID = p.ServerAccount.ExternalID
			}
		}
		pairs = append(pairs, config.TokenPair{
			Index:        i + 1,
			Provider:     clientProv,
			ClientToken:  p.ClientAccount.Token,
			TargetUserID: targetID,
			AuthKey:      p.ClientAccount.AuthKey,
			AuthKeyID:    p.ClientAccount.AuthKeyID,
			ServerSalt:   p.ClientAccount.ServerSalt,
		})
	}
	if len(pairs) == 0 {
		mainLog.Info("[Disconnect] No active pairings found in database — nothing to disconnect")
		return
	}

	// Kill any lingering proxy processes on SOCKS5/HTTP ports
	for _, port := range []string{"10909", "9095"} {
		out, err := exec.Command("fuser", "-k", port+"/tcp").CombinedOutput()
		if err == nil {
			mainLog.Info("[Disconnect] Killed process on port %s: %s", port, strings.TrimSpace(string(out)))
		} else {
			mainLog.Info("[Disconnect] Port %s: no process found (ok)", port)
		}
	}

	var wg sync.WaitGroup
	for _, tp := range pairs {
		wg.Add(1)
		go func(tp config.TokenPair) {
			defer wg.Done()
			label := fmt.Sprintf("ch%d", tp.Index)
			prov := tp.Provider
			if prov == "" {
				prov = "bale"
			}
			mainLog.Info("[%s] Connecting to %s...", label, prov)
			factory, ok := provider.GetFactory(provider.ProviderType(prov))
			if !ok {
				mainLog.Error("[%s] ❌ Factory not found for %s", label, prov)
				return
			}
			acctData := map[string]interface{}{
				"token":       tp.ClientToken,
				"external_id": tp.TargetUserID,
				"auth_key":    tp.AuthKey,
				"auth_key_id": tp.AuthKeyID,
				"server_salt": tp.ServerSalt,
			}
			client, err := factory.NewClient(acctData)
			if err != nil {
				mainLog.Error("[%s] ❌ NewClient failed: %v", label, err)
				return
			}
			if err := client.Connect(); err != nil {
				mainLog.Error("[%s] ❌ Connect failed: %v", label, err)
				return
			}
			defer client.Close()
			client.StartPingLoop()
			time.Sleep(1 * time.Second)

			// Send END message to signal the server
			mainLog.Info("[%s] Sending END to %d...", label, tp.TargetUserID)
			client.SendTextMessage(tp.TargetUserID, "BLETUN:END")
			time.Sleep(500 * time.Millisecond)

			// Clean up all messages (delete traces)
			mainLog.Info("[%s] Deleting all messages...", label)
			client.CleanupMessages()
			time.Sleep(500 * time.Millisecond)

			mainLog.Info("[%s] ✅ Cleanup done", label)
		}(tp)
	}
	wg.Wait()
	mainLog.Info("[Disconnect] ✅ All accounts cleaned up")
}

// detectRemoteServerURL auto-detects the remote server URL.
// Priority: SERVER_URL env var → clever CLI (from project root) → hardcoded URL
func detectRemoteServerURL() string {
	// 1. Check SERVER_URL environment variable first (most explicit)
	if url := os.Getenv("SERVER_URL"); url != "" {
		return strings.TrimSuffix(url, "/")
	}

	// 2. Try clever CLI — find .clever.json to determine project root
	projectDir := findProjectRoot()
	if projectDir != "" {
		cmd := exec.Command("clever", "domain")
		cmd.Dir = projectDir
		out, err := cmd.CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				domain := strings.TrimSpace(line)
				if domain != "" && strings.Contains(domain, "cleverapps.io") {
					domain = strings.TrimSuffix(domain, "/")
					url := "https://" + domain
					mainLog.Info("Remote server from clever CLI: %s", url)
					return url
				}
			}
		}
	}

	// 3. Hardcoded fallback for known Clever Cloud deployment
	const fallbackURL = "https://app-1940b1ac-3072-43ff-a004-68e1a738e316.cleverapps.io"
	return fallbackURL
}

// findProjectRoot walks up from cwd and executable dir to find .clever.json
func findProjectRoot() string {
	// Try cwd first
	if dir := walkUpFor(".clever.json", ""); dir != "" {
		return dir
	}
	// Try executable directory
	if exe, err := os.Executable(); err == nil {
		if dir := walkUpFor(".clever.json", filepath.Dir(exe)); dir != "" {
			return dir
		}
	}
	return ""
}

// walkUpFor walks up from startDir looking for a file. Empty startDir = cwd.
func walkUpFor(filename, startDir string) string {
	dir := startDir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return ""
		}
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, filename)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

