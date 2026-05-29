package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pion/webrtc/v4"
	"github.com/salman/ble-webrtc-tun/internal/accounts"
	"github.com/salman/ble-webrtc-tun/internal/admin"
	"github.com/salman/ble-webrtc-tun/internal/api"
	"github.com/salman/ble-webrtc-tun/internal/config"
	"github.com/salman/ble-webrtc-tun/internal/db"
	"github.com/salman/ble-webrtc-tun/internal/dcconn"
	"github.com/salman/ble-webrtc-tun/internal/livekit"
	"github.com/salman/ble-webrtc-tun/internal/logger"
	"github.com/salman/ble-webrtc-tun/internal/provider"
	"github.com/salman/ble-webrtc-tun/internal/router"
	"github.com/salman/ble-webrtc-tun/internal/soroush"
	"github.com/salman/ble-webrtc-tun/internal/transport"
)

// Global references for the new DB-driven system
var (
	accountMgr     *accounts.Manager
	callRouter     *router.Router
	serverDB       *db.Database
	serverObf      *dcconn.Obfuscator // shared obfuscator for all channels

	mainLog        = logger.New("main")
)

func main() {
	// Initialize logging system
	if err := logger.Init("server"); err != nil {
		log.Fatalf("Logger init failed: %v", err)
	}
	defer logger.Close()

	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		logger.SetLevelFromString(lvl)
	}

	mainLog.Info("=== BLE WebRTC Tunnel — Server ===")

	os.Setenv("ROLE", "server")

	cfg, err := config.Load()
	if err != nil {
		mainLog.Fatal("Failed to load config: %v", err)
	}

	if port := os.Getenv("PORT"); port != "" {
		cfg.AdminListenAddr = ":" + port
		mainLog.Info("Using PORT from environment: %s", port)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		mainLog.Info("Shutting down...")
		cancel()
	}()

	// Initialize database
	serverDB, err = db.Init("server")
	if err != nil {
		mainLog.Fatal("Database init failed: %v", err)
	}
	defer serverDB.Close()

	// Auto-migrate from .env.tokens if DB is empty
	acctCount, _ := serverDB.CountAccounts("", "")
	if acctCount == 0 {
		if _, err := os.Stat(".env.tokens"); err == nil {
			mainLog.Info("Empty DB — auto-migrating from .env.tokens")
			serverDB.MigrateFromEnvTokens(".env.tokens")
		}
	}

	// Initialize account manager and router
	accountMgr = accounts.NewManager(serverDB)
	callRouter = router.NewRouter(serverDB)
	defer callRouter.Close()

	// Start health checks
	accountMgr.StartHealthCheck(ctx, accounts.DefaultHealthConfig())

	wrtc := transport.NewWebRTCTransport(cfg)
	defer wrtc.Close()

	// Create the admin panel object for state management
	// (AddLog, SetTunnelStatus, SDP channels) but don't start its HTTP listener.
	adminPanel := admin.NewServer(cfg, wrtc)

	// Start unified API + React admin server (replaces both old admin panel and separate API)
	apiAddr := cfg.AdminListenAddr
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	apiSrv := api.NewServer(serverDB, accountMgr, callRouter, api.Config{
		Username: cfg.AdminUsername,
		Password: cfg.AdminPassword,
	})
	// Wire signaling forwarding from the new API server to the admin panel
	apiSrv.SetAdminPanel(adminPanel)
	go func() {
		if err := apiSrv.Start(ctx, apiAddr); err != nil {
			mainLog.Error("API server error: %v", err)
		}
	}()

	adminPanel.AddLog("info", "Server starting...")

	// Probe TUN
	useTUN := probeTUN(cfg)
	if useTUN {
		adminPanel.AddLog("info", "TUN mode enabled")
	} else {
		adminPanel.AddLog("info", "Proxy mode — userspace IP relay")
	}

	// Create obfuscator for anti-DPI payload encryption
	if cfg.ObfuscationSecret != "" {
		var err error
		serverObf, err = dcconn.NewObfuscator(cfg.ObfuscationSecret)
		if err != nil {
			mainLog.Error("Failed to create obfuscator: %v (running without obfuscation)", err)
		} else {
			mainLog.Info("ChaCha20-Poly1305 obfuscation enabled (overhead: %d bytes/msg)", serverObf.Overhead())
		}
	} else {
		mainLog.Warn("No OBFUSCATION_SECRET set — traffic is not obfuscated (DPI visible)")
	}

	// Bale signaling mode: connect to Bale WS, auto-accept calls
	// Hot-reload: will automatically detect new server accounts added via admin panel
	adminPanel.AddLog("info", "Bale signaling mode enabled (hot-reload)")
	runBaleSignaling(ctx, cfg, adminPanel, wrtc, useTUN)
}

// runBaleSignaling connects to Bale WS, waits for calls, auto-accepts, and tunnels.
// Loads SERVER accounts from the database and watches for new ones (hot-reload).
func runBaleSignaling(ctx context.Context, cfg *config.Config, adminPanel *admin.Server, wrtc *transport.WebRTCTransport, useTUN bool) {
	runtime.GOMAXPROCS(0)

	// Track which accounts already have signaling goroutines running
	activeAccounts := make(map[uint]context.CancelFunc)
	var mu sync.Mutex

	startAccount := func(account db.Account) {
		mu.Lock()
		if _, exists := activeAccounts[account.ID]; exists {
			mu.Unlock()
			return // Already running
		}
		acctCtx, acctCancel := context.WithCancel(ctx)
		activeAccounts[account.ID] = acctCancel
		mu.Unlock()

		label := fmt.Sprintf("[Account DB:%d]", account.ID)

		// Get expected caller ID from pairing
		var expectedCallerID int64
		pairing, err := serverDB.GetPairingByServerAccount(account.ID)
		if err == nil && pairing.ClientAccount != nil {
			expectedCallerID = pairing.ClientAccount.BaleUserID
		}
		mainLog.Info("%s BaleID=%d ExpectedCaller=%d — starting signaling", label, account.BaleUserID, expectedCallerID)
		adminPanel.AddLog("info", fmt.Sprintf("%s Starting Bale signaling (BaleID=%d)", label, account.BaleUserID))

		go func() {
			defer func() {
				mu.Lock()
				delete(activeAccounts, account.ID)
				mu.Unlock()
			}()
			runSingleAccountLoopDB(acctCtx, cfg, adminPanel, wrtc, account, expectedCallerID, label, useTUN)
		}()
	}

	// Initial load
	serverAccounts, err := serverDB.ListEnabledAccounts(db.RoleServer)
	if err == nil && len(serverAccounts) > 0 {
		mainLog.Info(" DB mode: %d server accounts", len(serverAccounts))
		adminPanel.AddLog("info", fmt.Sprintf("Multi-channel (DB): %d server accounts", len(serverAccounts)))
		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.TotalChannels = len(serverAccounts)
		})
		for i, acct := range serverAccounts {
			if i > 0 {
				// Sequential stagger: consistent 3s between accounts
				// Avoids overwhelming Bale's WS infrastructure
				time.Sleep(3 * time.Second)
			}
			startAccount(acct)
		}
	} else {
		mainLog.Warn("No SERVER accounts in database — add accounts via admin panel")
		adminPanel.AddLog("warn", "No SERVER accounts found. Add accounts via the admin panel.")
	}

	// Hot-reload: poll for new accounts every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, cancelFn := range activeAccounts {
				cancelFn()
			}
			mu.Unlock()
			return
		case <-ticker.C:
			accounts, err := serverDB.ListEnabledAccounts(db.RoleServer)
			if err != nil {
				continue
			}

			// Start signaling for any new accounts
			mu.Lock()
			currentCount := len(activeAccounts)
			mu.Unlock()

			for _, acct := range accounts {
				mu.Lock()
				_, exists := activeAccounts[acct.ID]
				mu.Unlock()
				if !exists {
					mainLog.Info("🔥 Hot-loading new server account DB:%d (BaleID=%d)", acct.ID, acct.BaleUserID)
					adminPanel.AddLog("info", fmt.Sprintf("Hot-loading new server account: DB:%d", acct.ID))
					startAccount(acct)
				}
			}

			// Update channel count
			mu.Lock()
			newCount := len(activeAccounts)
			mu.Unlock()
			if newCount != currentCount {
				adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
					s.TotalChannels = newCount
				})
			}
		}
	}
}

// runSingleAccountLoop runs the Bale WS + call session loop for one account (legacy .env.tokens mode).
func runSingleAccountLoop(ctx context.Context, cfg *config.Config, adminPanel *admin.Server, wrtc *transport.WebRTCTransport, token string, expectedCallerID int64, label string, useTUN bool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		adminPanel.AddLog("info", label+" Connecting to Bale WS...")
		factory, _ := provider.GetFactory(provider.ProviderBale)
		client, err := factory.NewClient(map[string]interface{}{"token": token})
		if err != nil {
			adminPanel.AddLog("error", label+" Client init failed: "+err.Error())
			time.Sleep(10 * time.Second)
			continue
		}

		if err := client.Connect(); err != nil {
			adminPanel.AddLog("error", label+" Bale connect failed: "+err.Error())
			mainLog.Error("%s Connect failed: %v, retrying in 10s", label, err)
			time.Sleep(10 * time.Second)
			continue
		}

		adminPanel.AddLog("info", label+" Bale WS connected!")
		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.BaleConnected = true
			s.Mode = "multi-channel"
		})
		client.StartPingLoop()
		client.DrainChannels()
		time.Sleep(3 * time.Second)
		client.DrainChannels()

		runSessionLoop(ctx, cfg, adminPanel, wrtc, client, expectedCallerID, useTUN)

		// Erase all chat fingerprints before reconnecting
		client.CleanupMessages()
		client.Close()
		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.BaleConnected = false
		})

		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(2 * time.Second)
		}
	}
}

// runSingleAccountLoopDB runs the Bale WS + call session loop for a DB-managed account.
// Uses the router for call validation and status tracking.
func runSingleAccountLoopDB(ctx context.Context, cfg *config.Config, adminPanel *admin.Server, wrtc *transport.WebRTCTransport, account db.Account, expectedCallerID int64, label string, useTUN bool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		clientProv := account.ProviderType
		if clientProv == "" {
			clientProv = "bale"
		}
		adminPanel.AddLog("info", label+" Connecting to "+clientProv+" WS...")

		factory, ok := provider.GetFactory(provider.ProviderType(clientProv))
		if !ok {
			adminPanel.AddLog("error", label+" No factory for "+clientProv)
			time.Sleep(10 * time.Second)
			continue
		}

		acctData := map[string]interface{}{
			"token":       account.Token,
			"external_id": account.ExternalID,
			"access_hash": account.AccessHash,
			"auth_key":    account.AuthKey,
			"auth_key_id": account.AuthKeyID,
			"server_salt": account.ServerSalt,
		}

		client, err := factory.NewClient(acctData)
		if err != nil {
			adminPanel.AddLog("error", label+" Client init failed: "+err.Error())
			time.Sleep(10 * time.Second)
			continue
		}

		if err := client.Connect(); err != nil {
			adminPanel.AddLog("error", label+" "+clientProv+" connect failed: "+err.Error())
			serverDB.SetAccountError(account.ID, "connect: "+err.Error())
			mainLog.Error("%s Connect failed: %v, retrying in 10s", label, err)
			time.Sleep(10 * time.Second)
			continue
		}

		adminPanel.AddLog("info", label+" "+clientProv+" WS connected!")
		serverDB.SetAccountStatus(account.ID, db.StatusIdle)
		serverDB.TouchAccount(account.ID)
		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.BaleConnected = true
			s.Mode = "multi-channel (DB)"
		})
		client.StartPingLoop()
		client.DrainChannels()
		time.Sleep(3 * time.Second)
		client.DrainChannels()

		runSessionLoopDB(ctx, cfg, adminPanel, wrtc, client, account, expectedCallerID, label, useTUN)

		// Erase all chat fingerprints before reconnecting
		client.CleanupMessages()
		client.Close()
		serverDB.SetAccountStatus(account.ID, db.StatusOffline)
		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.BaleConnected = false
		})

		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(2 * time.Second)
		}
	}
}


// activeCallIDs tracks calls being processed to prevent double-accept (legacy mode).
var (
	activeCallMu  sync.Mutex
	activeCallIDs = make(map[string]bool)
)

// runSessionLoop handles incoming calls on a single Bale client connection (legacy mode).
// expectedCallerID filters calls: only accept from the paired client user.
func runSessionLoop(ctx context.Context, cfg *config.Config, adminPanel *admin.Server, _ *transport.WebRTCTransport, client provider.Client, expectedCallerID int64, useTUN bool) {
	callCh := client.GetCallCh()
	sessionNum := 0

	for {
		client.DrainTextChannels()
		adminPanel.AddLog("info", "👂 Waiting for incoming call...")
		mainLog.Info(" Ready — waiting for call")

		var call *provider.IncomingCall
		select {
		case <-ctx.Done():
			return
		case c, ok := <-callCh:
			if !ok {
				mainLog.Info(" Call channel closed — Bale WS died")
				return
			}
			call = c
		}

		if expectedCallerID != 0 && call.CallerID != expectedCallerID {
			mainLog.Info(" Ignoring call from %d (expected %d)", call.CallerID, expectedCallerID)
			continue
		}

		callKey := fmt.Sprintf("%d", call.CallID)
		activeCallMu.Lock()
		if activeCallIDs[callKey] {
			activeCallMu.Unlock()
			mainLog.Info(" Skipping duplicate call %s (already handled)", callKey)
			continue
		}
		activeCallIDs[callKey] = true
		activeCallMu.Unlock()
		mainLog.Info(" Accepted call %s (caller=%d) — dedup OK", callKey, call.CallerID)

		sessionNum++
		tag := fmt.Sprintf("[Session #%d]", sessionNum)
		mainLog.Info("%s 📞 Incoming call! CallID=%d CallerID=%d",
			tag, call.CallID, call.CallerID)
		adminPanel.AddLog("info", fmt.Sprintf("📞 Call #%d! CallID=%d", sessionNum, call.CallID))

		client.AcceptCall(call.CallID, true)
		client.ReceiveCall(call.CallID)
		client.GetWssURL(call.CallID)

		adminPanel.AddLog("info", "Accepting call, waiting for LiveKit token (30s)...")

		result, err := client.WaitForAccept(30 * time.Second)
		if err != nil {
			adminPanel.AddLog("error", "Token failed: "+err.Error())
			mainLog.Error("%s Token failed: %v", tag, err)
			client.DiscardCall(call.CallID)
			continue
		}

		adminPanel.AddLog("info", "✅ LiveKit token! Room="+result.RoomID)
		mainLog.Info("%s LiveKit: room=%s wss=%s", tag, result.RoomID, result.WssURL)

		wssURL := result.WssURL
		if len(wssURL) > 0 && wssURL[len(wssURL)-1] == '(' {
			wssURL = wssURL[:len(wssURL)-1]
		}

		// Create a per-session config copy to avoid race conditions
		// between concurrent sessions overwriting each other's LiveKit credentials.
		sessionCfg := *cfg
		sessionCfg.LiveKitWSURL = wssURL + "/rtc"
		sessionCfg.LiveKitToken = result.LivekitToken

		adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
			s.LiveKitJoined = true
			s.RoomID = result.RoomID
			s.CallID = itoa64(call.CallID)
			s.TotalSessions++
			s.ActiveChannels++
			s.ConnectedSince = time.Now().Format("15:04:05")
		})

		// Connect to LiveKit SFU directly — no P2P needed
		sessionCtx, sessionCancel := context.WithCancel(ctx)
		mainLog.Info("%s Connecting to LiveKit SFU...", tag)
		adminPanel.AddLog("info", tag+" Connecting to SFU...")

		sfuTransport := livekit.NewSFUTransport(&sessionCfg, serverObf)
		if err := sfuTransport.Connect(sessionCtx); err != nil {
			adminPanel.AddLog("error", tag+" SFU connect failed: "+err.Error())
			mainLog.Error("%s SFU connect failed: %v", tag, err)
			sessionCancel()
			client.DiscardCall(call.CallID)
			sfuTransport.Close()
			continue
		}
		adminPanel.AddLog("info", tag+" ✅ SFU connected, track published!")
		mainLog.Info("%s ✅ SFU connected", tag)

		// Run tunnel session via SFU — in a goroutine so we can handle next call
		go func(sctx context.Context, scancel context.CancelFunc, sfu *livekit.SFUTransport, sessionTag string, cID int64, sNum int) {
			defer scancel()
			defer sfu.Close()

			handleSFUProxy(sctx, cfg, sfu, adminPanel, client, sessionTag, expectedCallerID)

			mainLog.Info("%s Tunnel ended — cleaning up", sessionTag)
			adminPanel.AddLog("info", fmt.Sprintf("Session #%d ended — cleaning up", sNum))
			adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
				s.TunnelActive = false
				s.LiveKitJoined = false
				s.ConnectedSince = ""
				if s.ActiveChannels > 0 {
					s.ActiveChannels--
				}
			})
			client.DiscardCall(cID)
			activeCallMu.Lock()
			delete(activeCallIDs, fmt.Sprintf("%d", cID))
			activeCallMu.Unlock()

			// Erase all Bale message traces
			mainLog.Info("%s Cleaning up Bale messages...", sessionTag)
			adminPanel.AddLog("info", "Erasing message traces from Bale chat...")
			client.CleanupMessages()
			adminPanel.AddLog("info", "✅ Session cleanup complete (messages erased)")
			mainLog.Info("%s ✅ Cleanup done (messages erased)", sessionTag)
		}(sessionCtx, sessionCancel, sfuTransport, tag, call.CallID, sessionNum)

		time.Sleep(1 * time.Second)
	}
}

// runSessionLoopDB handles incoming calls using the DB-driven router for validation.
// Also handles terminal relay messages (BLECMD/BLERSZ/BLEEND) while waiting for calls.
func runSessionLoopDB(ctx context.Context, cfg *config.Config, adminPanel *admin.Server, _ *transport.WebRTCTransport, client provider.Client, account db.Account, expectedCallerID int64, label string, useTUN bool) {
	callCh := client.GetCallCh()
	sessionNum := 0

	for {
		// Drain stale tunnel messages but preserve terminal messages
		drainDone := false
		for !drainDone {
			select {
			case msg := <-client.GetTextMsgCh():
				// Process terminal messages, drop stale tunnel messages
				if strings.HasPrefix(msg, "BLECMD:") || strings.HasPrefix(msg, "BLERSZ:") || strings.HasPrefix(msg, "BLEEND:") {
					// Terminal relay removed — commands now go via VPN proxy
					continue
				}
				// Handle ENDCALL while draining — ACK immediately
				if msg == "BLETUN:ENDCALL" && expectedCallerID != 0 {
					mainLog.Info("%s Received ENDCALL while draining — sending ACK", label)
					adminPanel.AddLog("info", label+" 📴 ENDCALL received (idle) — sending ACK")
					client.SendTextMessage(expectedCallerID, "BLETUN:ENDCALL_ACK")
					// Also force-end in router + set IDLE (in case of stale state)
					callRouter.ForceEndCall(account.ID)
					serverDB.SetAccountStatus(account.ID, db.StatusIdle)
					// Async cleanup — don't block the main loop
					go client.CleanupMessages()
				}
			default:
				drainDone = true
			}
		}
		adminPanel.AddLog("info", label+" 👂 Waiting for incoming call...")
		mainLog.Info("%s Ready — waiting for call", label)

		var call *provider.IncomingCall
		for {
			select {
			case <-ctx.Done():
				return
			case c, ok := <-callCh:
				if !ok {
					mainLog.Info("%s Call channel closed — Bale WS died", label)
					return
				}
				call = c
			case msg := <-client.GetTextMsgCh():
				// Handle terminal relay messages while waiting for calls
				if strings.HasPrefix(msg, "BLECMD:") || strings.HasPrefix(msg, "BLERSZ:") || strings.HasPrefix(msg, "BLEEND:") {
					// Terminal relay removed — commands now go via VPN proxy
					continue
				}
				// Handle ENDCALL while waiting for calls (server is idle, no active call)
				// Send ACK so the client knows the server is ready
				if msg == "BLETUN:ENDCALL" && expectedCallerID != 0 {
					mainLog.Info("%s Received ENDCALL while idle — sending ACK", label)
					adminPanel.AddLog("info", label+" 📴 ENDCALL received (idle) — sending ACK")
					client.SendTextMessage(expectedCallerID, "BLETUN:ENDCALL_ACK")
					// Also force-end in router + set IDLE (in case of stale state)
					callRouter.ForceEndCall(account.ID)
					serverDB.SetAccountStatus(account.ID, db.StatusIdle)
					// Async cleanup — don't block the main loop
					go client.CleanupMessages()
				}
				continue
			}
			break
		}

		// Use router for call validation instead of static filter
		if err := callRouter.ShouldAcceptCall(account.ID, call.CallerID, call.CallID); err != nil {
			mainLog.Warn("%s Rejecting call %d: %v", label, call.CallID, err)
			continue
		}

		sessionNum++
		tag := fmt.Sprintf("%s[S#%d]", label, sessionNum)
		mainLog.Info("%s 📞 Incoming call! CallID=%d CallerID=%d", tag, call.CallID, call.CallerID)
		adminPanel.AddLog("info", fmt.Sprintf("%s 📞 Call! CallID=%d", tag, call.CallID))

		// Reserve via router (IDLE → RESERVED)
		serverDB.SetAccountStatus(account.ID, db.StatusReserved)

		client.AcceptCall(call.CallID, true)
		client.ReceiveCall(call.CallID)
		client.GetWssURL(call.CallID)

		adminPanel.AddLog("info", tag+" Accepting call, waiting for LiveKit token...")
		result, err := client.WaitForAccept(30 * time.Second)
		if err != nil {
			adminPanel.AddLog("error", tag+" Token failed: "+err.Error())
			mainLog.Error("%s Token failed: %v", tag, err)
			client.DiscardCall(call.CallID)
			serverDB.SetAccountStatus(account.ID, db.StatusIdle)
			continue
		}

		if account.ProviderType == "soroush" {
			// Soroush WebRTC P2P connection logic (Server/Answerer side)!
			mainLog.Info("%s ✅ Call accepted! Initializing Soroush P2P WebRTC Answerer...", tag)
			adminPanel.AddLog("info", tag+" P2P Call accepted. Negotiating WebRTC Answerer...")

			iceServers := make([]webrtc.ICEServer, 0)
			for _, conn := range result.Connections {
				ice := webrtc.ICEServer{URLs: []string{conn.URL}}
				if conn.Username != "" {
					ice.Username = conn.Username
					ice.Credential = conn.Password
					ice.CredentialType = webrtc.ICECredentialTypePassword
				}
				iceServers = append(iceServers, ice)
			}

			config := webrtc.Configuration{
				ICEServers:    iceServers,
				BundlePolicy:  webrtc.BundlePolicyMaxBundle,
				RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
			}

			pc, err := webrtc.NewPeerConnection(config)
			if err != nil {
				adminPanel.AddLog("error", tag+" Failed to create PeerConnection: "+err.Error())
				client.DiscardCall(call.CallID)
				serverDB.SetAccountStatus(account.ID, db.StatusIdle)
				continue
			}

			// Dummy Opus track for call camouflage
			audioTrack, err := webrtc.NewTrackLocalStaticSample(
				webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
				"audio0",
				"soroush-voice-stream",
			)
			if err != nil {
				pc.Close()
				client.DiscardCall(call.CallID)
				serverDB.SetAccountStatus(account.ID, db.StatusIdle)
				adminPanel.AddLog("error", tag+" Failed to create audio track: "+err.Error())
				continue
			}

			_, err = pc.AddTrack(audioTrack)
			if err != nil {
				pc.Close()
				client.DiscardCall(call.CallID)
				serverDB.SetAccountStatus(account.ID, db.StatusIdle)
				adminPanel.AddLog("error", tag+" Failed to add audio track: "+err.Error())
				continue
			}

			pendingICE := make(chan string, 64)
			pc.OnICECandidate(func(c *webrtc.ICECandidate) {
				if c == nil {
					return
				}
				select {
				case pendingICE <- c.ToJSON().Candidate:
				default:
				}
			})

			var dc *webrtc.DataChannel
			dcOpenCh := make(chan struct{})
			pc.OnDataChannel(func(d *webrtc.DataChannel) {
				dc = d
				dc.OnOpen(func() {
					close(dcOpenCh)
				})
			})

			// Message listener loop for SDP Offer + Client ICE candidates
			sdpCtx, sdpCancel := context.WithCancel(ctx)
			sdpDone := make(chan bool, 1)

			go func() {
				for {
					select {
					case <-sdpCtx.Done():
						return
					case text := <-client.GetTextMsgCh():
						if soroush.IsSDPOffer(text) {
							sdpStr := soroush.ExtractSDP(text)
							mainLog.Info("[%s] Received SDP offer (%d bytes)", tag, len(sdpStr))

							offer := webrtc.SessionDescription{
								Type: webrtc.SDPTypeOffer,
								SDP:  sdpStr,
							}
							if err := pc.SetRemoteDescription(offer); err != nil {
								mainLog.Error("[%s] SetRemoteDescription failed: %v", tag, err)
								return
							}

							answer, err := pc.CreateAnswer(nil)
							if err != nil {
								mainLog.Error("[%s] CreateAnswer failed: %v", tag, err)
								return
							}

							if err := pc.SetLocalDescription(answer); err != nil {
								mainLog.Error("[%s] SetLocalDescription failed: %v", tag, err)
								return
							}

							// Send SDP Answer back
							answerMsg := soroush.FormatSDPAnswer(answer.SDP)
							client.SendTextMessage(call.CallerID, answerMsg)
							mainLog.Info("[%s] Sent SDP answer", tag)

							// Send buffered ICE candidates
							go func() {
								for {
									select {
									case candidate := <-pendingICE:
										iceMsg := soroush.FormatICECandidate(candidate)
										client.SendTextMessage(call.CallerID, iceMsg)
									case <-sdpCtx.Done():
										return
									}
								}
							}()

							select {
							case sdpDone <- true:
							default:
							}
						}

						if soroush.IsICECandidate(text) {
							candidateStr := soroush.ExtractICECandidate(text)
							if err := pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: candidateStr}); err != nil {
								mainLog.Warn("[%s] AddICECandidate failed: %v", tag, err)
							}
						}
					}
				}
			}()

			// Confirm call in router (RESERVED → IN_CALL)
			session, routerErr := callRouter.ConfirmCall(account.ID, call.CallID, fmt.Sprintf("soroush-room-%d", call.CallID))
			if routerErr != nil {
				mainLog.Info("%s Router confirm failed: %v", tag, routerErr)
			}

			adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
				s.LiveKitJoined = true
				s.RoomID = fmt.Sprintf("soroush-room-%d", call.CallID)
				s.CallID = itoa64(call.CallID)
				s.TotalSessions++
				s.ActiveChannels++
				s.ConnectedSince = time.Now().Format("15:04:05")
			})

			sessionCtx, sessionCancel := context.WithCancel(ctx)

			go func(sctx context.Context, scancel context.CancelFunc, pconn *webrtc.PeerConnection, sTag string, cID int64, sNum int, sess *router.Session) {
				defer scancel()
				defer sdpCancel()
				defer pconn.Close()
				defer func() {
					mainLog.Info("%s Tunnel ended — cleaning up", sTag)
					adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
						s.TunnelActive = false
						s.LiveKitJoined = false
						s.ConnectedSince = ""
						if s.ActiveChannels > 0 {
							s.ActiveChannels--
						}
					})
					client.DiscardCall(cID)

					// End call in router (IN_CALL → IDLE) with stats
					callRouter.EndCall(account.ID, 0, 0, "SESSION_END")

					client.CleanupMessages()
					mainLog.Info("%s ✅ Cleanup done", sTag)
				}()

				// Wait for SDP Offer negotiation
				select {
				case <-sdpDone:
				case <-time.After(30 * time.Second):
					mainLog.Error("%s SDP Offer timeout (30s)", sTag)
					adminPanel.AddLog("error", sTag+" SDP Offer timeout")
					return
				case <-sctx.Done():
					return
				}

				// Wait for data channel open
				select {
				case <-dcOpenCh:
				case <-time.After(15 * time.Second):
					mainLog.Error("%s Data Channel open timeout (15s)", sTag)
					adminPanel.AddLog("error", sTag+" Data Channel open timeout")
					return
				case <-sctx.Done():
					return
				}

				adminPanel.AddLog("info", sTag+" Tunnel established via Soroush P2P!")
				adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
					s.TunnelActive = true
				})

				// Setup yamux server session
				dcConn := soroush.NewDataChannelConn(dc)
				ymuxCfg := yamux.DefaultConfig()
				ymuxCfg.EnableKeepAlive = true
				ymuxCfg.KeepAliveInterval = 15 * time.Second
				ymuxCfg.ConnectionWriteTimeout = 60 * time.Second
				ymuxCfg.StreamCloseTimeout = 120 * time.Second
				ymuxCfg.MaxStreamWindowSize = 16 * 1024 * 1024
				ymuxCfg.AcceptBacklog = 1024
				ymuxCfg.LogOutput = io.Discard

				ymuxSess, err := yamux.Server(dcConn, ymuxCfg)
				if err != nil {
					adminPanel.AddLog("error", sTag+" Yamux server: "+err.Error())
					return
				}
				defer ymuxSess.Close()

				mainLog.Info("%s Yamux proxy active (Soroush P2P)", sTag)
				go handleYamuxSession(ymuxSess)

				// Monitor session termination
				for {
					select {
					case <-sctx.Done():
						return
					case msg := <-client.GetTextMsgCh():
						if msg == "BLETUN:END" {
							adminPanel.AddLog("info", sTag+" Client sent END")
							mainLog.Info("%s Client sent BLETUN:END", sTag)
							return
						}
						if msg == "BLETUN:ENDCALL" {
							mainLog.Info("%s 📴 Received ENDCALL command — ending active call", sTag)
							adminPanel.AddLog("info", sTag+" 📴 ENDCALL received — ending call and sending ACK")
							client.SendTextMessage(call.CallerID, "BLETUN:ENDCALL_ACK")
							return
						}
					}
				}
			}(sessionCtx, sessionCancel, pc, tag, call.CallID, sessionNum, session)

			time.Sleep(1 * time.Second)

		} else {
			adminPanel.AddLog("info", tag+" ✅ LiveKit token! Room="+result.RoomID)
			mainLog.Info("%s LiveKit: room=%s wss=%s", tag, result.RoomID, result.WssURL)

			// Confirm call in router (RESERVED → IN_CALL)
			session, routerErr := callRouter.ConfirmCall(account.ID, call.CallID, result.RoomID)
			if routerErr != nil {
				mainLog.Info("%s Router confirm failed: %v", tag, routerErr)
			}

			wssURL := result.WssURL
			if len(wssURL) > 0 && wssURL[len(wssURL)-1] == '(' {
				wssURL = wssURL[:len(wssURL)-1]
			}

			sessionCfg := *cfg
			sessionCfg.LiveKitWSURL = wssURL + "/rtc"
			sessionCfg.LiveKitToken = result.LivekitToken

			adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
				s.LiveKitJoined = true
				s.RoomID = result.RoomID
				s.CallID = itoa64(call.CallID)
				s.TotalSessions++
				s.ActiveChannels++
				s.ConnectedSince = time.Now().Format("15:04:05")
			})

			sessionCtx, sessionCancel := context.WithCancel(ctx)
			mainLog.Info("%s Connecting to LiveKit SFU...", tag)

			sfuTransport := livekit.NewSFUTransport(&sessionCfg, serverObf)
			if err := sfuTransport.Connect(sessionCtx); err != nil {
				adminPanel.AddLog("error", tag+" SFU connect failed: "+err.Error())
				mainLog.Error("%s SFU connect failed: %v", tag, err)
				sessionCancel()
				client.DiscardCall(call.CallID)
				sfuTransport.Close()
				callRouter.EndCallWithError(account.ID, 0, 0, "SFU connect: "+err.Error())
				continue
			}
			adminPanel.AddLog("info", tag+" ✅ SFU connected!")

			// Run tunnel session in goroutine
			go func(sctx context.Context, scancel context.CancelFunc, sfu *livekit.SFUTransport, sTag string, cID int64, sNum int, sess *router.Session) {
				defer scancel()
				defer sfu.Close()

				handleSFUProxy(sctx, cfg, sfu, adminPanel, client, sTag, expectedCallerID)

				mainLog.Info("%s Tunnel ended — cleaning up", sTag)
				adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
					s.TunnelActive = false
					s.LiveKitJoined = false
					s.ConnectedSince = ""
					if s.ActiveChannels > 0 {
						s.ActiveChannels--
					}
				})
				client.DiscardCall(cID)

				// End call in router (IN_CALL → IDLE) with stats
				stats := sfu.GetStats()
				bytesSent, _ := stats["bytes_sent"].(int64)
				bytesRecv, _ := stats["bytes_received"].(int64)
				callRouter.EndCall(account.ID, bytesSent, bytesRecv, "SESSION_END")

				client.CleanupMessages()
				mainLog.Info("%s ✅ Cleanup done", sTag)
			}(sessionCtx, sessionCancel, sfuTransport, tag, call.CallID, sessionNum, session)

			time.Sleep(1 * time.Second)
		}
	}
}


func handleSFUProxy(ctx context.Context, cfg *config.Config, sfu *livekit.SFUTransport, adminPanel *admin.Server, baleClient provider.Client, tag string, callerID int64) {
	// Wait for remote track (client's video through SFU)
	adminPanel.AddLog("info", tag+" Waiting for client's video track via SFU (30s)...")
	mainLog.Info("%s Waiting for remote track...", tag)

	connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
	defer connCancel()
	if err := sfu.WaitForConnection(connCtx); err != nil {
		adminPanel.AddLog("error", fmt.Sprintf("%s Track timeout: %v", tag, err))
		return
	}

	adminPanel.AddLog("info", tag+" Tunnel established via SFU!")
	adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
		s.TunnelActive = true
	})

	// Setup yamux server session over DataChannel
	dc := sfu.DataConn()
	if dc == nil {
		adminPanel.AddLog("error", tag+" DataConn not ready")
		return
	}

	ymuxCfg := yamux.DefaultConfig()
	ymuxCfg.EnableKeepAlive = true                      // Ping peer to detect dead connections
	ymuxCfg.KeepAliveInterval = 15 * time.Second        // Faster dead detection (match client)
	ymuxCfg.ConnectionWriteTimeout = 60 * time.Second   // Tolerant of KCP retransmission (match client)
	ymuxCfg.StreamCloseTimeout = 120 * time.Second
	ymuxCfg.MaxStreamWindowSize = 16 * 1024 * 1024      // 16MB — must match client (was 1MB)
	ymuxCfg.AcceptBacklog = 1024                         // Handle many parallel connections
	ymuxCfg.LogOutput = io.Discard                      // Silence yamux internal logs

	session, err := yamux.Server(dc, ymuxCfg)
	if err != nil {
		adminPanel.AddLog("error", tag+" Yamux server: "+err.Error())
		return
	}
	defer session.Close()

	mainLog.Info("%s Yamux proxy active", tag)
	go handleYamuxSession(session)

	// Monitor
	// Drain stale text messages (BLETUN:END from previous --disconnect runs)
	// These get buffered in Bale chat and would immediately kill the new session
drainLoop:
	for {
		select {
		case msg := <-baleClient.GetTextMsgCh():
			mainLog.Info("%s Drained stale text message: %s", tag, msg)
		default:
			break drainLoop
		}
	}

	// Grace period: ignore BLETUN:END for 10s after session start.
	// Bale replays unread messages from chat history which may include
	// old END messages from previous --disconnect runs.
	sessionStart := time.Now()
	gracePeriod := 10 * time.Second

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mainLog.Info("%s Context cancelled", tag)
			return
		case msg := <-baleClient.GetTextMsgCh():
			if msg == "BLETUN:END" {
				if time.Since(sessionStart) < gracePeriod {
					mainLog.Info("%s Ignoring stale BLETUN:END (within %v grace period)", tag, gracePeriod)
					continue
				}
				adminPanel.AddLog("info", tag+" Client sent END")
				mainLog.Info("%s Client sent BLETUN:END", tag)
				return
			}
			// Handle ENDCALL command — client requests server to end active call
			// Send ACK immediately, then return to trigger the goroutine's cleanup
			// (DiscardCall + router EndCall + CleanupMessages) which properly ends
			// the Bale call and updates the server UI/router state.
			if msg == "BLETUN:ENDCALL" {
				mainLog.Info("%s 📴 Received ENDCALL command — ending active call", tag)
				adminPanel.AddLog("info", tag+" 📴 ENDCALL received — ending call and sending ACK")
				// Send acknowledgment to the client BEFORE returning
				if callerID != 0 {
					baleClient.SendTextMessage(callerID, "BLETUN:ENDCALL_ACK")
				}
				// Don't call CleanupMessages here — the goroutine cleanup after
				// handleSFUProxy returns will handle DiscardCall (ends Bale call),
				// callRouter.EndCall (updates server UI/router), and CleanupMessages.
				return
			}
			// Handle terminal relay messages (BLECMD, BLERSZ, BLEEND)
			if strings.HasPrefix(msg, "BLECMD:") || strings.HasPrefix(msg, "BLERSZ:") || strings.HasPrefix(msg, "BLEEND:") {
				// Terminal relay removed — commands now go via VPN proxy
				continue
			}
		case <-ticker.C:
			if session.IsClosed() {
				adminPanel.AddLog("warn", tag+" Yamux session closed")
				mainLog.Info("%s Yamux session closed", tag)
				return
			}
			stats := sfu.GetStats()
			bytesSent, _ := stats["bytes_sent"].(int64)
			bytesRecv, _ := stats["bytes_received"].(int64)
			adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
				// Compute speed (delta over 5s interval)
				s.SpeedUp = (bytesSent - s.PrevBytesSent) / 5
				s.SpeedDown = (bytesRecv - s.PrevBytesRecv) / 5
				s.PrevBytesSent = bytesSent
				s.PrevBytesRecv = bytesRecv
				s.BytesSent = bytesSent
				s.BytesReceived = bytesRecv
				s.ActiveConns = session.NumStreams()
			})
		}
	}
}

// handleBaleProxy handles one tunnel session: SDP exchange → WebRTC → proxy traffic.
func handleBaleProxy(ctx context.Context, cfg *config.Config, lkClient *livekit.SignalClient, adminPanel *admin.Server, baleClient provider.Client, callerID int64, sessionNum int) {
	tag := fmt.Sprintf("[Session #%d]", sessionNum)
	adminPanel.AddLog("info", fmt.Sprintf("%s ⏳ Waiting for client SDP offer...", tag))
	mainLog.Info("%s Waiting for SDP offer via Bale", tag)

	// STEP 1: Wait for SDP offer via Bale text message (also detect BLETUN:END)
	var offerSDP string
	timeout := time.After(300 * time.Second)
	for {
		select {
		case msg := <-baleClient.GetTextMsgCh():
			if strings.HasPrefix(msg, "BLETUN:O:") {
				encoded := strings.TrimPrefix(msg, "BLETUN:O:")
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					adminPanel.AddLog("error", tag+" Bad base64 in SDP: "+err.Error())
					continue
				}
				offerSDP = string(decoded)
				adminPanel.AddLog("info", fmt.Sprintf("%s 📥 Got SDP offer (%d bytes)", tag, len(offerSDP)))
			} else if msg == "BLETUN:END" {
				adminPanel.AddLog("info", tag+" Client sent END signal (before SDP)")
				mainLog.Info("%s Client disconnected before SDP exchange", tag)
				return
			} else {
				mainLog.Info("%s Ignoring Bale message: %s", tag, truncStr(msg, 50))
			}
		case msg := <-adminPanel.GetSDPOfferCh():
			offerSDP = msg
			adminPanel.AddLog("info", fmt.Sprintf("%s 📥 Got SDP via HTTP (%d bytes)", tag, len(offerSDP)))
		case <-timeout:
			adminPanel.AddLog("error", tag+" ❌ Timeout waiting for SDP (5min)")
			return
		case <-ctx.Done():
			return
		}
		if offerSDP != "" {
			break
		}
	}

	// STEP 2: Create a fresh WebRTC transport for this session
	newWrtc := transport.NewWebRTCTransport(cfg)
	newWrtc.SetObfuscator(serverObf)
	defer func() {
		mainLog.Info("%s Closing WebRTC transport", tag)
		newWrtc.Close()
	}()

	iceServers := lkClient.GetICEServers()
	adminPanel.AddLog("info", fmt.Sprintf("%s Initializing WebRTC (%d ICE servers)", tag, len(iceServers)))
	if err := newWrtc.Initialize(iceServers); err != nil {
		adminPanel.AddLog("error", tag+" WebRTC init failed: "+err.Error())
		return
	}
	mainLog.Info("%s ✅ WebRTC PeerConnection initialized", tag)

	// Auto-detect video tunnel mode
	isVideo := strings.Contains(offerSDP, "m=video")
	if isVideo {
		adminPanel.AddLog("info", tag+" 📹 Video tunnel mode detected")
		if err := newWrtc.EnableVideoTunnel(); err != nil {
			adminPanel.AddLog("error", tag+" Video tunnel failed: "+err.Error())
			return
		}
		newWrtc.StartKeepalive()
	} else {
		mainLog.Info("%s DataChannel mode", tag)
	}

	// STEP 3: Handle SDP offer → create answer
	answerSDP, err := newWrtc.HandleOffer(offerSDP)
	if err != nil {
		adminPanel.AddLog("error", tag+" SDP handle failed: "+err.Error())
		return
	}
	adminPanel.AddLog("info", fmt.Sprintf("%s 📤 Sending SDP answer (%d bytes)", tag, len(answerSDP)))

	// STEP 4: Send answer via Bale
	if callerID != 0 {
		encodedAnswer := base64.StdEncoding.EncodeToString([]byte(answerSDP))
		answerMsg := "BLETUN:A:" + encodedAnswer
		if err := baleClient.SendTextMessage(callerID, answerMsg); err != nil {
			adminPanel.AddLog("error", tag+" Failed to send SDP answer: "+err.Error())
		} else {
			adminPanel.AddLog("info", tag+" ✅ SDP answer sent via Bale")
		}
	}
	select {
	case adminPanel.GetSDPAnswerCh() <- answerSDP:
	default:
	}

	// STEP 5: P2P proxy - not supported in yamux mode
	mainLog.Info("%s P2P mode: proxy not available in yamux architecture", tag)

	// STEP 6: Wait for connection
	connType := "DataChannel"
	if isVideo {
		connType = "ICE (video)"
	}
	adminPanel.AddLog("info", fmt.Sprintf("%s ⏳ Waiting for %s connection (90s)...", tag, connType))
	connCtx, connCancel := context.WithTimeout(ctx, 90*time.Second)
	defer connCancel()
	if err := newWrtc.WaitForConnection(connCtx); err != nil {
		adminPanel.AddLog("error", fmt.Sprintf("%s ❌ %s timeout: %v", tag, connType, err))
		return
	}

	adminPanel.AddLog("info", fmt.Sprintf("%s 🟢 Tunnel established (%s)!", tag, connType))
	adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
		s.TunnelActive = true
	})

	// STEP 7: Monitor connection + detect BLETUN:END
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mainLog.Info("%s Context cancelled", tag)
			return
		case msg := <-baleClient.GetTextMsgCh():
			if msg == "BLETUN:END" {
				adminPanel.AddLog("info", tag+" 📴 Client sent END — closing session")
				mainLog.Info("%s Client sent BLETUN:END", tag)
				return
			}
			mainLog.Info("%s Ignoring Bale msg during tunnel: %s", tag, truncStr(msg, 50))
		case <-ticker.C:
			if !newWrtc.IsConnected() {
				adminPanel.AddLog("warn", tag+" Client disconnected (WebRTC)")
				mainLog.Info("%s WebRTC disconnected", tag)
				return
			}
			stats := newWrtc.GetStats()
			adminPanel.SetTunnelStatus(func(s *admin.TunnelStatus) {
				s.BytesSent = stats["bytes_sent"].(int64)
				s.BytesReceived = stats["bytes_received"].(int64)
			})
		}
	}
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// probeTUN is a no-op stub — TUN mode has been replaced by SOCKS5/HTTP proxy.
func probeTUN(_ *config.Config) bool {
	mainLog.Info(" TUN probe skipped (proxy mode only)")
	return false
}

// handleWithTUN is deprecated — delegates to handleWithProxy.
func handleWithTUN(ctx context.Context, cfg *config.Config, lkClient *livekit.SignalClient, adminPanel *admin.Server, wrtc *transport.WebRTCTransport, offerSDP string) {
	adminPanel.AddLog("info", "TUN mode deprecated, using proxy mode")
	handleWithProxy(ctx, cfg, lkClient, adminPanel, wrtc, offerSDP)
}

// handleWithProxy uses userspace IP forwarding (no TUN needed).
func handleWithProxy(ctx context.Context, cfg *config.Config, lkClient *livekit.SignalClient, adminPanel *admin.Server, wrtc *transport.WebRTCTransport, offerSDP string) {
	adminPanel.AddLog("info", "Processing client SDP offer (Proxy mode)...")

	newWrtc := transport.NewWebRTCTransport(cfg)
	newWrtc.SetObfuscator(serverObf)
	defer newWrtc.Close()

	iceServers := lkClient.GetICEServers()
	if err := newWrtc.Initialize(iceServers); err != nil {
		adminPanel.AddLog("error", "WebRTC init failed: "+err.Error())
		return
	}

	answerSDP, err := newWrtc.HandleOffer(offerSDP)
	if err != nil {
		adminPanel.AddLog("error", "SDP offer handling failed: "+err.Error())
		return
	}

	adminPanel.GetSDPAnswerCh() <- answerSDP

	mainLog.Info("[Proxy] P2P proxy mode not supported in yamux architecture")

	connCtx, connCancel := context.WithTimeout(ctx, 60*time.Second)
	defer connCancel()
	if err := newWrtc.WaitForConnection(connCtx); err != nil {
		adminPanel.AddLog("error", "DataChannel timeout")
		return
	}

	adminPanel.AddLog("info", "🟢 DataChannel connected (Proxy mode)!")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !newWrtc.IsConnected() {
				adminPanel.AddLog("warn", "Client disconnected")
				return
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 5)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 20)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}


