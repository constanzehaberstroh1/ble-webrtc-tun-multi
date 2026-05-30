// Package pool manages a set of QUIC connections (one per WebRTC channel)
// and provides flow-pinned load balancing with a Circuit Breaker.
//
// Circuit Breaker logic:
//   - Channels with ≥3 consecutive stream failures are skipped entirely.
//   - After 5 failures the connection is force-closed so monitorAndReconnect
//     tears it down and re-dials a fresh WebRTC+QUIC channel.
//   - Success resets the failure counter.
//   - Stream timeout is 2s (was 5s) so black-hole connections fail fast.
package pool

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/salman/ble-webrtc-tun/internal/logger"
)

var poolLog = logger.New("pool")

// circuitBreakerThreshold is the number of consecutive stream open failures
// after which a channel is excluded from load balancing.
const circuitBreakerThreshold = int32(3)

// circuitBreakerKill is the number of consecutive failures that triggers a
// force-close of the QUIC connection, causing monitorAndReconnect to re-dial.
const circuitBreakerKill = int32(5)

// streamTimeout is how long OpenStreamSync waits before giving up.
// 2s is intentionally short: failing fast lets the caller retry on a
// healthy channel instead of blocking the proxy for 5-10 seconds.
const streamTimeout = 2 * time.Second

// TunnelPool manages multiple QUIC connections and distributes proxy streams
// using a least-active-streams load balancer with circuit-breaker protection.
type TunnelPool struct {
	mu      sync.RWMutex
	entries []*PoolEntry
	done    chan struct{}
	once    sync.Once
}

// PoolEntry wraps one QUIC connection with stream-count and failure tracking.
type PoolEntry struct {
	Conn         quic.Connection
	Label        string
	ActiveStreams atomic.Int32 // streams currently open on this connection
	FailCount    atomic.Int32 // consecutive stream open failures (circuit breaker)
	addedAt      time.Time
}

// New creates a new empty TunnelPool with a background health monitor.
func New() *TunnelPool {
	p := &TunnelPool{done: make(chan struct{})}
	go p.healthMonitorLoop()
	return p
}

// Add registers a new QUIC connection in the pool.
func (p *TunnelPool) Add(conn quic.Connection, label string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, &PoolEntry{
		Conn:    conn,
		Label:   label,
		addedAt: time.Now(),
	})
	poolLog.Info("Added QUIC connection %s (total: %d)", label, len(p.entries))
}

// Remove removes a specific QUIC connection from the pool.
func (p *TunnelPool) Remove(conn quic.Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.Conn == conn {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			poolLog.Info("Removed QUIC connection %s (remaining: %d)", e.Label, len(p.entries))
			return
		}
	}
}

// OpenStream opens a QUIC stream on the least-loaded HEALTHY connection.
//
// Circuit breaker: channels with ≥ circuitBreakerThreshold consecutive
// failures are excluded. Their effective load is treated as MaxInt32 so
// the balancer always prefers a fresh channel. After circuitBreakerKill
// failures the connection is force-closed to trigger re-dial.
//
// Returns a trackedStream that auto-decrements ActiveStreams on Close().
func (p *TunnelPool) OpenStream() (net.Conn, error) {
	p.mu.RLock()
	entries := make([]*PoolEntry, len(p.entries))
	copy(entries, p.entries)
	p.mu.RUnlock()

	if len(entries) == 0 {
		return nil, fmt.Errorf("no active tunnels")
	}

	// ── Circuit-Breaker Selection ──────────────────────────────────────────
	// Score each entry: activeStreams + huge penalty per failure.
	// Entries with ≥ threshold failures are skipped entirely.
	var best *PoolEntry
	bestScore := int32(math.MaxInt32)

	for _, e := range entries {
		if e.Conn == nil {
			continue
		}
		// Skip connections that are internally dead
		select {
		case <-e.Conn.Context().Done():
			continue
		default:
		}

		fails := e.FailCount.Load()
		if fails >= circuitBreakerThreshold {
			// Channel is in circuit-breaker state — skip it
			poolLog.Warn("[CB] Skipping %s (fails=%d, circuit open)", e.Label, fails)
			continue
		}

		// Score: active streams + 100 penalty per failure (so 2 failures = heavy penalty)
		score := e.ActiveStreams.Load() + fails*100
		if best == nil || score < bestScore {
			bestScore = score
			best = e
		}
	}

	if best == nil {
		// All channels are either dead or circuit-broken.
		// Count how many are just circuit-broken (not fully dead) — they may recover.
		broken := 0
		for _, e := range entries {
			if e.FailCount.Load() >= circuitBreakerThreshold {
				broken++
			}
		}
		if broken > 0 {
			return nil, fmt.Errorf("all %d tunnels in circuit-breaker lockdown (broken=%d)", len(entries), broken)
		}
		return nil, fmt.Errorf("all %d tunnels are closed", len(entries))
	}

	// ── Open Stream with Fast Timeout ─────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), streamTimeout)
	defer cancel()

	stream, err := best.Conn.OpenStreamSync(ctx)
	if err != nil {
		newFails := best.FailCount.Add(1)
		poolLog.Warn("[CB] Stream open failed on %s (fails=%d): %v", best.Label, newFails, err)

		// Kill the connection if it keeps failing — forces monitorAndReconnect
		if newFails >= circuitBreakerKill {
			poolLog.Warn("[CB] Circuit breaker KILL: force-closing %s after %d failures", best.Label, newFails)
			best.Conn.CloseWithError(1, "circuit breaker: stream exhaustion")
		}

		return nil, fmt.Errorf("open stream on %s: %w", best.Label, err)
	}

	// ── Success — reset circuit breaker ───────────────────────────────────
	if old := best.FailCount.Swap(0); old > 0 {
		poolLog.Info("[CB] %s recovered (was fails=%d)", best.Label, old)
	}
	best.ActiveStreams.Add(1)
	poolLog.Info("Opened stream on %s (active: %d)", best.Label, best.ActiveStreams.Load())

	return &trackedStream{
		Conn:  wrapQUICStream(stream, best.Conn),
		entry: best,
	}, nil
}

// ActiveCount returns the number of QUIC connections that are still alive.
func (p *TunnelPool) ActiveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, e := range p.entries {
		if e.Conn != nil {
			select {
			case <-e.Conn.Context().Done():
			default:
				count++
			}
		}
	}
	return count
}

// CloseAll closes all QUIC connections and stops the health monitor.
func (p *TunnelPool) CloseAll() {
	p.once.Do(func() { close(p.done) })
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.Conn != nil {
			e.Conn.CloseWithError(0, "tunnel stopped")
		}
	}
	p.entries = nil
	poolLog.Info("All QUIC connections closed")
}

// healthMonitorLoop logs pool status and evicts zombie entries every 5s.
func (p *TunnelPool) healthMonitorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			live := p.entries[:0]
			for _, e := range p.entries {
				select {
				case <-e.Conn.Context().Done():
					// Dead AND no active streams — safe to evict from pool
					if e.ActiveStreams.Load() <= 0 {
						poolLog.Warn("[Health] Evicting dead entry %s", e.Label)
						continue // don't keep it
					}
				default:
				}
				fails := e.FailCount.Load()
				streams := e.ActiveStreams.Load()
				if fails >= circuitBreakerThreshold {
					poolLog.Warn("[Health] %s: CIRCUIT OPEN (fails=%d, streams=%d)", e.Label, fails, streams)
				} else {
					poolLog.Info("[Health] %s: alive (fails=%d, streams=%d)", e.Label, fails, streams)
				}
				live = append(live, e)
			}
			p.entries = live
			p.mu.Unlock()
		}
	}
}

// ─── trackedStream ────────────────────────────────────────────────────────────

type trackedStream struct {
	net.Conn
	entry *PoolEntry
	once  sync.Once
}

func (s *trackedStream) Close() error {
	s.once.Do(func() {
		if s.entry.ActiveStreams.Add(-1) < 0 {
			s.entry.ActiveStreams.Store(0)
		}
		poolLog.Info("Stream closed on %s (active: %d)", s.entry.Label, s.entry.ActiveStreams.Load())
	})
	return s.Conn.Close()
}

// ─── quicStreamConn ───────────────────────────────────────────────────────────

type quicStreamConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func wrapQUICStream(s quic.Stream, conn quic.Connection) net.Conn {
	return &quicStreamConn{
		Stream: s,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

// ─── Compatibility shims ──────────────────────────────────────────────────────

func (p *TunnelPool) Sessions() []*PoolEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*PoolEntry, len(p.entries))
	copy(out, p.entries)
	return out
}

// LatencyMs returns a placeholder (QUIC pool measures stream counts, not RTT).
func (e *PoolEntry) LatencyMs() int64 { return 0 }

// next is used by legacy callers; no-op in QUIC pool.
var _next uint32

func init() { atomic.StoreUint32(&_next, 0) }
