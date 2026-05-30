package livekit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"github.com/salman/ble-webrtc-tun/internal/logger"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v3"
	"github.com/salman/ble-webrtc-tun/internal/config"
	"github.com/salman/ble-webrtc-tun/internal/dcconn"
	"github.com/salman/ble-webrtc-tun/internal/rtpconn"
	"google.golang.org/protobuf/proto"

	lkproto "github.com/livekit/protocol/livekit"
)

var sfuLog = logger.New("sfu")

const (
	// Opus audio keepalive interval (standard 20ms frame)
	sfuOpusKeepaliveMs = 20
)

// SFUTransport routes tunnel data through the LiveKit SFU using Opus audio RTP.
// VPN data is injected as fake Opus audio samples, making traffic look like
// a normal voice call to DPI systems. TWCC is disabled to prevent SFU throttling.
type SFUTransport struct {
	cfg  *config.Config
	conn *websocket.Conn
	mu   sync.RWMutex

	pubPC  *webrtc.PeerConnection // publisher PC
	subPC  *webrtc.PeerConnection // subscriber PC
	track  *webrtc.TrackLocalStaticSample

	// DataChannel for tunnel data - reliable/ordered SCTP (fallback)
	pubDC   *webrtc.DataChannel // publisher _reliable data channel
	dcReady chan struct{}        // closed when pubDC is open
	dataConn *dcconn.Conn        // io.ReadWriteCloser for yamux (DC mode)

	// RTP audio tunnel (primary — DPI evasion)
	rtpDataConn *rtpconn.Conn // io.ReadWriteCloser for QUIC (RTP mode)
	useRTP      bool          // true = tunnel via Opus RTP

	// Obfuscation layer (anti-DPI)
	obfuscator *dcconn.Obfuscator

	connected   bool
	connectedCh chan struct{}
	done        chan struct{}

	bytesSent atomic.Int64
	bytesRecv atomic.Int64

	// Pending subscriber offer from SFU
	pendingSubOffer *lkproto.SessionDescription
	subOfferCh      chan struct{}

	// Track published confirmation
	trackPublishedCh chan struct{}

	// SFU WS health monitoring
	lastPongTime atomic.Int64 // unix millis of last SFU pong

	// Buffered ICE candidates that arrive before remote description
	pendingPubCandidates []webrtc.ICECandidateInit
	pendingSubCandidates []webrtc.ICECandidateInit
	pubRemoteSet         bool
	subRemoteSet         bool
}

// NewSFUTransport creates a transport that routes through the LiveKit SFU.
// If obfuscator is nil, a passthrough (disabled) obfuscator is used.
func NewSFUTransport(cfg *config.Config, obfuscator *dcconn.Obfuscator) *SFUTransport {
	s := &SFUTransport{
		cfg:              cfg,
		obfuscator:       obfuscator,
		connectedCh:      make(chan struct{}),
		done:             make(chan struct{}),
		dcReady:          make(chan struct{}),
		subOfferCh:       make(chan struct{}, 1),
		trackPublishedCh: make(chan struct{}, 1),
	}
	s.lastPongTime.Store(time.Now().UnixMilli())
	return s
}

// Connect joins the LiveKit room and sets up publisher/subscriber PCs.
func (s *SFUTransport) Connect(ctx context.Context) error {
	// 1. Connect WebSocket to LiveKit SFU
	wsURL, err := s.buildWSURL()
	if err != nil {
		return err
	}

	sfuLog.Info("Connecting to %s", s.cfg.LiveKitWSURL)

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: false},
		HandshakeTimeout: 15 * time.Second,
		Subprotocols:     []string{"lk-protocol-15"},
	}
	headers := http.Header{
		"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		"Origin":     []string{"https://web.ble.ir"},
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("WS dial: %w", err)
	}
	s.conn = conn
	sfuLog.Info("WebSocket connected")

	// 2. Read JoinResponse
	joinResp, iceServers, err := s.readJoinResponse()
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	sfuLog.Info("Room joined: %s, ICE servers: %d",
		joinResp.Room.GetName(), len(iceServers))

	// 3. Create publisher PC with video track
	if err := s.createPublisher(iceServers); err != nil {
		return fmt.Errorf("publisher: %w", err)
	}

	// 4. Create subscriber PC (will handle offers from SFU)
	if err := s.createSubscriber(iceServers); err != nil {
		return fmt.Errorf("subscriber: %w", err)
	}

	// Note: subscriber offer will come via SignalResponse_Offer message

	// 6. Start message reader
	go s.readMessages(ctx)

	// 7. Tell the SFU about our track BEFORE publishing (required by LiveKit)
	// Use AUDIO track (Opus) — DPI sees a normal voice call
	sfuLog.Info("Sending AddTrack request (Opus audio)...")
	addTrackReq := &lkproto.SignalRequest{
		Message: &lkproto.SignalRequest_AddTrack{
			AddTrack: &lkproto.AddTrackRequest{
				Cid:    s.track.ID(),
				Name:   "audio",
				Type:   lkproto.TrackType_AUDIO,
				Source: lkproto.TrackSource_MICROPHONE,
			},
		},
	}
	if err := s.sendSignal(addTrackReq); err != nil {
		return fmt.Errorf("AddTrack: %w", err)
	}

	// 8. Wait for TrackPublished confirmation from SFU
	select {
	case <-s.trackPublishedCh:
		sfuLog.Info("✅ Track registered by SFU")
	case <-time.After(10 * time.Second):
		sfuLog.Warn("⚠️ TrackPublished timeout, publishing anyway")
	}

	// 9. Publish our video track — send offer to SFU
	if err := s.publishTrack(); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// 10. Setup data transport — prefer RTP audio tunnel for DPI evasion
	// Create rtpconn adapter: yamux data flows through Opus RTP packets
	s.mu.Lock()
	s.rtpDataConn = rtpconn.New(s.track, s.obfuscator) // encrypt payloads before they enter the Opus track
	s.useRTP = true
	s.connected = true
	s.mu.Unlock()
	if s.obfuscator != nil && s.obfuscator.Enabled() {
		sfuLog.Info("✅ Opus RTP tunnel mode initialized (DPI evasion + XChaCha20 encryption active)")
	} else {
		sfuLog.Warn("⚠️ Opus RTP tunnel mode initialized (DPI evasion active, NO payload encryption — set OBFUSCATION_SECRET!)")
	}

	// Also setup DataChannel if it opens (for control messages, not data)
	go func() {
		select {
		case <-s.dcReady:
			sfuLog.Info("DataChannel _reliable also available (backup)")
		case <-time.After(20 * time.Second):
			// DC not required in RTP mode
		}
	}()

	// 11. Start Opus silence keepalive + SFU ping
	s.rtpDataConn.StartSilenceLoop()
	go s.sfuPing(ctx)

	return nil
}

func (s *SFUTransport) createPublisher(iceServers []webrtc.ICEServer) error {
	// Use minimal MediaEngine with ONLY Opus codec — no TWCC extensions.
	// Skipping TWCC prevents the SFU's Bandwidth Estimator from throttling
	// our VPN traffic disguised as audio.
	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     webrtc.MimeTypeOpus,
			ClockRate:    48000,
			Channels:     2,
			SDPFmtpLine:  "minptime=10;useinbandfec=1",
			RTCPFeedback: nil, // CRITICAL: disables TWCC/NACK congestion control
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return err
	}
	// NOTE: We deliberately do NOT register TWCC header extensions.
	// RTCPFeedback:nil strips congestion control, SDPFmtpLine mimics real Opus.

	se := webrtc.SettingEngine{}
	se.SetICETimeouts(5*time.Second, 25*time.Second, 2*time.Second)
	se.SetSCTPMaxReceiveBufferSize(8 * 1024 * 1024)
	se.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeTCP4,
		webrtc.NetworkTypeTCP6,
	})

	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(se),
		webrtc.WithMediaEngine(mediaEngine),
	)

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	if err != nil {
		return err
	}

	// Create Opus audio track — DPI sees a normal voice call
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2},
		"vpn-audio", "vpn-stream",
	)
	if err != nil {
		return err
	}
	if _, err := pc.AddTrack(track); err != nil {
		return err
	}


	// No DataChannel needed — all tunnel data flows through Opus RTP.
	// Creating a DataChannel would generate SCTP traffic detectable by DPI.
	// Close dcReady immediately so nothing blocks on it.
	select {
	case <-s.dcReady:
	default:
		close(s.dcReady)
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			sfuLog.Info("[SFU-Pub] ICE candidate: %s %s", c.Typ, c.Address)
			s.sendTrickleCandidate(c, lkproto.SignalTarget_PUBLISHER)
		}
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		sfuLog.Info("[SFU-Pub] ICE: %s", state)
		// NOTE: Never pause the LiveKit WebSocket! The SFU requires continuous
		// ping/pong and signaling or it will terminate the connection within seconds.
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		sfuLog.Info("[SFU-Pub] Connection: %s", state)
	})

	s.pubPC = pc
	s.track = track
	return nil
}

func (s *SFUTransport) createSubscriber(iceServers []webrtc.ICEServer) error {
	// Subscriber also uses Opus-only MediaEngine (no TWCC)
	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     webrtc.MimeTypeOpus,
			ClockRate:    48000,
			Channels:     2,
			SDPFmtpLine:  "minptime=10;useinbandfec=1",
			RTCPFeedback: nil, // Disables congestion control throttling
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return err
	}

	se := webrtc.SettingEngine{}
	se.SetICETimeouts(5*time.Second, 25*time.Second, 2*time.Second)
	se.SetSCTPMaxReceiveBufferSize(8 * 1024 * 1024)
	se.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeTCP4,
		webrtc.NetworkTypeTCP6,
	})

	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(se),
		webrtc.WithMediaEngine(mediaEngine),
	)

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	if err != nil {
		return err
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			sfuLog.Info("[SFU-Sub] ICE candidate: %s %s", c.Typ, c.Address)
			s.sendTrickleCandidate(c, lkproto.SignalTarget_SUBSCRIBER)
		}
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		sfuLog.Info("[SFU-Sub] ICE: %s", state)
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		sfuLog.Info("[SFU-Sub] Connection: %s", state)
	})

	// Handle incoming AUDIO tracks from other participants
	// This is where we receive VPN data disguised as Opus audio
	pc.OnTrack(func(remote *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		sfuLog.Info("[SFU-Sub] 🔊 Got remote track: %s (kind=%s)", remote.Codec().MimeType, remote.Kind())
		s.mu.Lock()
		s.connected = true
		s.mu.Unlock()
		select {
		case <-s.connectedCh:
		default:
			close(s.connectedCh)
		}
		// Read RTP packets and feed payloads into rtpconn
		go s.readRemoteAudioTrack(remote)
	})

	// Reject incoming DataChannels from SFU to prevent SCTP traffic.
	// All tunnel data flows through Opus RTP — keeping DataChannels open
	// creates DPI-detectable SCTP handshakes that can flag the connection.
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		sfuLog.Info("[SFU-Sub] Rejecting DataChannel: %s (id=%d) — audio-only mode", dc.Label(), dc.ID())
		dc.Close()
	})

	s.subPC = pc
	return nil
}

func (s *SFUTransport) publishTrack() error {
	offer, err := s.pubPC.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := s.pubPC.SetLocalDescription(offer); err != nil {
		return err
	}

	// LiveKit uses trickle ICE — send offer immediately, candidates will trickle
	sfuLog.Info("Sending publisher offer (%d bytes)", len(offer.SDP))

	req := &lkproto.SignalRequest{
		Message: &lkproto.SignalRequest_Offer{
			Offer: &lkproto.SessionDescription{
				Type: "offer",
				Sdp:  offer.SDP,
			},
		},
	}
	return s.sendSignal(req)
}

func (s *SFUTransport) handleSubscriberOffer(offer *lkproto.SessionDescription) error {
	if s.subPC == nil {
		return fmt.Errorf("subscriber PC not created")
	}

	sfuLog.Info("Setting subscriber remote description (%d bytes)", len(offer.Sdp))

	if err := s.subPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offer.Sdp,
	}); err != nil {
		return fmt.Errorf("set remote: %w", err)
	}

	// Flush pending subscriber ICE candidates
	s.mu.Lock()
	s.subRemoteSet = true
	pending := s.pendingSubCandidates
	s.pendingSubCandidates = nil
	s.mu.Unlock()
	for _, c := range pending {
		s.subPC.AddICECandidate(c)
	}

	answer, err := s.subPC.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}
	if err := s.subPC.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local: %w", err)
	}

	// LiveKit uses trickle ICE — send answer immediately
	sfuLog.Info("Sending subscriber answer (%d bytes)", len(answer.SDP))

	req := &lkproto.SignalRequest{
		Message: &lkproto.SignalRequest_Answer{
			Answer: &lkproto.SessionDescription{
				Type: "answer",
				Sdp:  answer.SDP,
			},
		},
	}
	return s.sendSignal(req)
}

// GetRTPConn returns the underlying rtpconn for QUIC transport wrapping.
// Returns nil if not in RTP mode. Callers wrap this with quicconn.OpusPacketConn
// and pass it to quic.Dial / quic.Listen.
func (s *SFUTransport) GetRTPConn() *rtpconn.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.useRTP {
		return s.rtpDataConn
	}
	return nil
}

// DataConn is kept for backward compatibility but always returns nil in QUIC mode.
// Use GetRTPConn() instead.
func (s *SFUTransport) DataConn() io.ReadWriteCloser {
	return nil
}

// GetStats returns traffic stats.
func (s *SFUTransport) GetStats() map[string]interface{} {
	s.mu.RLock()
	rtpDC := s.rtpDataConn
	dcConn := s.dataConn
	s.mu.RUnlock()

	if rtpDC != nil {
		sent, recv := rtpDC.Stats()
		return map[string]interface{}{
			"bytes_sent":     sent,
			"bytes_received": recv,
		}
	}
	if dcConn != nil {
		sent, recv := dcConn.Stats()
		return map[string]interface{}{
			"bytes_sent":     sent,
			"bytes_received": recv,
		}
	}
	return map[string]interface{}{
		"bytes_sent":     int64(0),
		"bytes_received": int64(0),
	}
}

// WaitForConnection blocks until the subscriber receives a remote track.
func (s *SFUTransport) WaitForConnection(ctx context.Context) error {
	select {
	case <-s.connectedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return fmt.Errorf("transport closed")
	}
}

// IsConnected returns whether we're receiving tracks from the SFU.
func (s *SFUTransport) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connected
}

// HealthInfo contains per-channel health metrics.
type HealthInfo struct {
	PubICEState  string `json:"pub_ice_state"`
	SubICEState  string `json:"sub_ice_state"`
	PubConnState string `json:"pub_conn_state"`
	DCState      string `json:"dc_state"`
	SFULastPong  int64  `json:"sfu_last_pong_ms"`
	SFUHealthy   bool   `json:"sfu_healthy"`
	DCLatencyMs  int64  `json:"dc_latency_ms"`
	DCHealthy    bool   `json:"dc_healthy"`
}

// GetHealth returns the current health status of this SFU transport.
func (s *SFUTransport) GetHealth() HealthInfo {
	info := HealthInfo{
		SFULastPong: s.lastPongTime.Load(),
	}

	// SFU WS health
	sfuElapsed := time.Since(time.UnixMilli(info.SFULastPong))
	info.SFUHealthy = sfuElapsed < 60*time.Second

	// Publisher PC state
	if s.pubPC != nil {
		info.PubICEState = s.pubPC.ICEConnectionState().String()
		info.PubConnState = s.pubPC.ConnectionState().String()
	}

	// Subscriber PC state
	if s.subPC != nil {
		info.SubICEState = s.subPC.ICEConnectionState().String()
	}

	// DataChannel state
	s.mu.RLock()
	dc := s.pubDC
	s.mu.RUnlock()
	if dc != nil {
		info.DCState = dc.ReadyState().String()
		info.DCHealthy = dc.ReadyState() == webrtc.DataChannelStateOpen
	}

	return info
}

// Close shuts down both PeerConnections and WebSocket.
func (s *SFUTransport) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	if s.pubPC != nil {
		s.pubPC.Close()
	}
	if s.subPC != nil {
		s.subPC.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

// readRemoteAudioTrack reads Opus RTP packets from the SFU and feeds
// their payloads into the rtpconn for yamux reassembly.
func (s *SFUTransport) readRemoteAudioTrack(track *webrtc.TrackRemote) {
	for {
		rtpPacket, _, err := track.ReadRTP()
		if err != nil {
			sfuLog.Error("[SFU-Sub] Audio track read error: %v", err)
			return
		}
		// Feed raw RTP payload into rtpconn for reassembly
		s.mu.RLock()
		rc := s.rtpDataConn
		s.mu.RUnlock()
		if rc != nil {
			rc.HandleRTP(rtpPacket.Payload)
		}
	}
}

func (s *SFUTransport) readMessages(ctx context.Context) {
	defer func() {
		// Signal transport death so auto-reconnect triggers
		s.mu.Lock()
		s.connected = false
		s.mu.Unlock()
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Time{}) // no deadline — pings handle liveness
		_, msg, err := s.conn.ReadMessage()
		if err != nil {
			sfuLog.Warn("SFU WebSocket read error: %v", err)
			return
		}

		resp := &lkproto.SignalResponse{}
		if err := proto.Unmarshal(msg, resp); err != nil {
			continue
		}

		s.handleSignalResponse(resp)
	}
}

func (s *SFUTransport) handleSignalResponse(resp *lkproto.SignalResponse) {
	switch msg := resp.Message.(type) {
	case *lkproto.SignalResponse_Answer:
		sfuLog.Info("Got publisher answer (%d bytes)", len(msg.Answer.Sdp))
		// Bypass IPs from inline SDP candidates to prevent routing loops
		s.bypassSDPIPs(msg.Answer.Sdp)
		if s.pubPC != nil {
			if err := s.pubPC.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer,
				SDP:  msg.Answer.Sdp,
			}); err != nil {
				sfuLog.Error("Set publisher remote desc error: %v", err)
			} else {
				// Apply pending candidates
				s.mu.Lock()
				s.pubRemoteSet = true
				pending := s.pendingPubCandidates
				s.pendingPubCandidates = nil
				s.mu.Unlock()
				for _, c := range pending {
					s.pubPC.AddICECandidate(c)
				}
			}
		}

	case *lkproto.SignalResponse_Offer:
		sfuLog.Info("Got subscriber offer (%d bytes)", len(msg.Offer.Sdp))
		// Bypass IPs from inline SDP candidates to prevent routing loops
		s.bypassSDPIPs(msg.Offer.Sdp)
		// Handle asynchronously to not block readMessages
		go func() {
			if err := s.handleSubscriberOffer(msg.Offer); err != nil {
				sfuLog.Error("Handle subscriber offer error: %v", err)
			}
		}()

	case *lkproto.SignalResponse_Trickle:
		candidate := msg.Trickle.GetCandidateInit()
		if candidate == "" {
			break
		}

		// Dynamic ICE candidate IP bypass — prevent routing loops
		// Parse the candidate SDP line and extract the remote IP
		var init webrtc.ICECandidateInit
		if err := json.Unmarshal([]byte(candidate), &init); err == nil {
			parts := strings.Fields(init.Candidate)
			if len(parts) >= 5 {
				ip := parts[4]
				if net.ParseIP(ip) != nil && strings.Contains(ip, ".") {
					sfuLog.Info("Candidate IP: %s", ip)
				}
			}
		}

		target := msg.Trickle.GetTarget()
		sfuLog.Info("Trickle ICE for target=%d", target)

		candidateInit := webrtc.ICECandidateInit{Candidate: candidate}

		s.mu.Lock()
		if target == lkproto.SignalTarget_PUBLISHER {
			if s.pubRemoteSet {
				s.mu.Unlock()
				if s.pubPC != nil {
					s.pubPC.AddICECandidate(candidateInit)
				}
			} else {
				s.pendingPubCandidates = append(s.pendingPubCandidates, candidateInit)
				s.mu.Unlock()
			}
		} else {
			if s.subRemoteSet {
				s.mu.Unlock()
				if s.subPC != nil {
					s.subPC.AddICECandidate(candidateInit)
				}
			} else {
				s.pendingSubCandidates = append(s.pendingSubCandidates, candidateInit)
				s.mu.Unlock()
			}
		}

	case *lkproto.SignalResponse_Update:
		sfuLog.Info("Participant update")

	case *lkproto.SignalResponse_TrackPublished:
		cid := msg.TrackPublished.GetCid()
		trackInfo := msg.TrackPublished.GetTrack()
		sfuLog.Info("✅ TrackPublished: cid=%s sid=%s", cid, trackInfo.GetSid())
		select {
		case s.trackPublishedCh <- struct{}{}:
		default:
		}

	case *lkproto.SignalResponse_Pong:
		s.lastPongTime.Store(time.Now().UnixMilli())
	case *lkproto.SignalResponse_PongResp:
		s.lastPongTime.Store(time.Now().UnixMilli())
	default:
		// ignore
	}
}

func (s *SFUTransport) sendTrickleCandidate(c *webrtc.ICECandidate, target lkproto.SignalTarget) {
	candidateInit := c.ToJSON()
	req := &lkproto.SignalRequest{
		Message: &lkproto.SignalRequest_Trickle{
			Trickle: &lkproto.TrickleRequest{
				CandidateInit: candidateInit.Candidate,
				Target:        target,
			},
		},
	}
	s.sendSignal(req)
}

func (s *SFUTransport) sendSignal(req *lkproto.SignalRequest) error {
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(websocket.BinaryMessage, data)
}

// keepalive is no longer needed — rtpconn.StartSilenceLoop() handles
// Opus keepalive frames. This is a no-op stub for compatibility.
func (s *SFUTransport) keepalive(ctx context.Context) {
	// Opus silence keepalive is handled by rtpconn.StartSilenceLoop()
}

func (s *SFUTransport) sfuPing(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if SFU has responded recently (WS health monitoring)
			lastPong := s.lastPongTime.Load()
			elapsed := time.Since(time.UnixMilli(lastPong))
			if elapsed > 60*time.Second {
				sfuLog.Warn("SFU WS health: no pong for %.0fs — tearing down", elapsed.Seconds())
				s.mu.Lock()
				s.connected = false
				s.mu.Unlock()
				select {
				case <-s.done:
				default:
					close(s.done)
				}
				return
			}

			req := &lkproto.SignalRequest{
				Message: &lkproto.SignalRequest_Ping{
					Ping: time.Now().UnixMilli(),
				},
			}
			// Always send pings — LiveKit requires continuous signaling
			if err := s.sendSignal(req); err != nil {
				sfuLog.Warn("SFU ping failed: %v — signaling teardown", err)
				s.mu.Lock()
				s.connected = false
				s.mu.Unlock()
				select {
				case <-s.done:
				default:
					close(s.done)
				}
				return
			}
		}
	}
}

func (s *SFUTransport) readJoinResponse() (*lkproto.JoinResponse, []webrtc.ICEServer, error) {
	s.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer s.conn.SetReadDeadline(time.Time{})

	_, msg, err := s.conn.ReadMessage()
	if err != nil {
		return nil, nil, err
	}

	resp := &lkproto.SignalResponse{}
	if err := proto.Unmarshal(msg, resp); err != nil {
		return nil, nil, fmt.Errorf("unmarshal: %w", err)
	}

	join := resp.GetJoin()
	if join == nil {
		return nil, nil, fmt.Errorf("first message not JoinResponse")
	}

	var servers []webrtc.ICEServer
	for _, ice := range join.GetIceServers() {
		srv := webrtc.ICEServer{URLs: ice.GetUrls()}
		if ice.GetUsername() != "" {
			srv.Username = ice.GetUsername()
			srv.Credential = ice.GetCredential()
			srv.CredentialType = webrtc.ICECredentialTypePassword
		}
		servers = append(servers, srv)
		sfuLog.Info("ICE: urls=%v user=%s", ice.GetUrls(), ice.GetUsername())
	}

	return join, servers, nil
}

func (s *SFUTransport) buildWSURL() (string, error) {
	u, err := url.Parse(s.cfg.LiveKitWSURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("access_token", s.cfg.LiveKitToken)
	q.Set("auto_subscribe", "1")
	q.Set("sdk", "js")
	q.Set("version", "2.13.6")
	q.Set("protocol", "15")
	q.Set("adaptive_stream", "1")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// bypassSDPIPs parses inline a=candidate: lines from SDP and adds bypass
// routes for their IPs. This prevents routing loops when the SFU embeds
// candidate IPs directly in the SDP offer/answer (not via trickle).
func (s *SFUTransport) bypassSDPIPs(sdp string) {
	lines := strings.Split(sdp, "\r\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 5 {
			ip := parts[4]
			// Only bypass IPv4 (TUN routing is IPv4 only)
			if net.ParseIP(ip) != nil && strings.Contains(ip, ".") {
				sfuLog.Info("Candidate IP: %s", ip)
			}
		}
	}
}

// bypassICEServerIPs resolves all ICE server hostnames and adds bypass routes.
// Called early in Connect() to ensure TURN connections survive routing changes.
func (s *SFUTransport) bypassICEServerIPs(iceServers []webrtc.ICEServer) {
	for _, server := range iceServers {
		for _, rawURL := range server.URLs {
			// Extract host from TURN/STUN URL (format: turn:host:port?transport=tcp)
			host := rawURL
			// Remove scheme
			for _, prefix := range []string{"turns:", "turn:", "stun:", "stuns:"} {
				host = strings.TrimPrefix(host, prefix)
			}
			// Remove query params
			if idx := strings.Index(host, "?"); idx >= 0 {
				host = host[:idx]
			}
			// Remove port
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			// If it's already an IP, bypass directly
			if ip := net.ParseIP(host); ip != nil {
				if strings.Contains(host, ".") {
					sfuLog.Info("ICE server (direct): %s", host)
				}
				continue
			}

			// Resolve hostname to ALL IPs
			ips, err := net.LookupHost(host)
			if err != nil {
				sfuLog.Info("ICE server resolve %s: %v", host, err)
				continue
			}
			for _, ip := range ips {
				if strings.Contains(ip, ".") { // IPv4 only
					sfuLog.Info("ICE server resolved: %s -> %s", host, ip)
				}
			}
		}
	}
}
