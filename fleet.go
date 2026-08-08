package trustorchestrator

// fleet: the production wire (architecture §2.2's documented "orchestrator
// accepts one peer at a time" ponytail is now lifted). A FleetServer binds
// the mTLS listener, accepts watchdog connections concurrently, fans their
// (score, p, evidence) frames into the fusion rule in real time, and
// broadcasts the live verdict to every subscriber. FleetPeer is the watchdog
// client: it dials the server and streams each 30s Score as a Wire frame,
// transparently reconnecting when the socket drops.
// ponytail: a stale node (no frame within staleFor) is dropped from the
// live view; the 30s cadence makes frame loss self-healing. Add a quorum of
// auditor servers with a fan-in merge when >1 orchestrator exists.

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// FleetVerdict is one broadcast ensemble decision.
type FleetVerdict struct {
	Detected bool
	Count    int // watchdogs contributing this cycle
	Total    int // watchdogs enrolled in the ensemble
	Scores   []Score
}

// FleetServer accepts mTLS watchdog connections and fans their frames into a
// live ensemble verdict. Subscribers get FleetVerdicts via Subscribe.
type FleetServer struct {
	threshold float64
	quorum    int
	staleFor  time.Duration

	mu       sync.Mutex
	scores   map[string]scoreAt
	enrolled []string
	fans     []chan FleetVerdict
	frames   *limiter // per-peer frame budget (ratelimit.go); mTLS path must not bypass the API throttle

	stop chan struct{}
	once sync.Once
}

// scoreAt pins a score to the time it was seen, so a stale score counts for
// staleFor and is then excluded from the live ensemble view.
type scoreAt struct {
	s Score
	t time.Time
}

// NewFleet creates the server half of the wire. threshold/quorum are the
// Detect fusion rule; staleFor bounds how long a node may be silent before
// its score leaves the live ensemble.
func NewFleet(threshold float64, quorum int, staleFor time.Duration) *FleetServer {
	if quorum < 1 {
		quorum = 3
	}
	if staleFor <= 0 {
		staleFor = 5 * 30 * time.Second // five 30s cycles
	}
	return &FleetServer{threshold: threshold, quorum: quorum,
		staleFor: staleFor, scores: map[string]scoreAt{}, stop: make(chan struct{}),
		frames: newLimiter(wireRate, wireBurst)}
}

// Handle is the server-side per-connection service: one goroutine per peer,
// so a single hostile or dead node stalls only its own stream. This is the
// migration from the documented "sequential Accept" ponytail in transport.go.
func (f *FleetServer) Handle(conn net.Conn) error {
	defer conn.Close()
	return ServeWire(conn, func(m WireMsg) error {
		if !f.frames.allow(conn.RemoteAddr().String()) {
			return errors.New("rate limit exceeded") // flood: drop the peer
		}
		f.Ingest(m)
		return nil
	})
}

// Serve runs the accept loop until Stop. Each accepted connection gets its
// own goroutine (concurrent fan-in).
func (f *FleetServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-f.stop:
				return nil
			default:
			}
			var ne net.Error
			if asNetErr(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go f.Handle(conn)
	}
}

func asNetErr(err error, ne *net.Error) bool {
	if n, ok := err.(net.Error); ok {
		*ne = n
		return true
	}
	return false
}

// Ingest folds one score frame into the ensemble and broadcasts a verdict.
func (f *FleetServer) Ingest(m WireMsg) {
	f.mu.Lock()
	if _, ok := f.scores[m.NodeID]; !ok {
		f.enrolled = append(f.enrolled, m.NodeID)
	}
	f.scores[m.NodeID] = scoreAt{s: Score{NodeID: m.NodeID, Score: m.Score, PValue: m.PValue, Evidence: m.Evidence}, t: time.Now()}
	f.mu.Unlock()
	f.emit()
}

// Subscribe returns a channel that receives a verdict after every frame.
func (f *FleetServer) Subscribe() <-chan FleetVerdict {
	ch := make(chan FleetVerdict, 16)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fans = append(f.fans, ch)
	return ch
}

func (f *FleetServer) broadcast(v FleetVerdict) {
	for _, ch := range f.fans {
		select {
		case ch <- v:
		default: // slow consumer never blocks the server
		}
	}
}

// emit recomputes the live verdict (pruning stale scores) and broadcasts.
func (f *FleetServer) emit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := len(f.enrolled)
	fresh := make([]Score, 0, total)
	for _, sa := range f.scores {
		if time.Since(sa.t) > f.staleFor {
			continue
		}
		fresh = append(fresh, sa.s)
	}
	det := Detect(fresh, f.threshold, f.quorum)
	f.broadcast(FleetVerdict{Detected: det, Count: len(fresh), Total: total, Scores: fresh})
}

// Stop terminates the accept loop and in-flight streams.
func (f *FleetServer) Stop() {
	f.once.Do(func() { close(f.stop) })
}

// Wait blocks until Stop is called.
func (f *FleetServer) Wait() {
	<-f.stop
}

// FleetPeer is the client side of the relay: it dials the fleet server over
// mTLS and streams each incoming Score as a wire frame, reconnecting
// transparently when the socket drops so a watchdog restart does not tear
// down the orchestration.
type FleetPeer struct {
	mu   sync.Mutex
	conn net.Conn
	addr string
	cfg  *tls.Config
}

// NewFleetPeer creates a watchdog client that streams to addr.
func NewFleetPeer(addr string, cfg *tls.Config) *FleetPeer {
	return &FleetPeer{addr: addr, cfg: cfg}
}

// Send writes one score frame, dialing on first use and replacing any dead
// connection after a write error. Frame loss on a dead socket is absorbed
// by the 30s cadence: the next cycle redials.
func (p *FleetPeer) Send(s Score) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		c, err := DialWire(p.addr, p.cfg)
		if err != nil {
			return err
		}
		p.conn = c
	}
	if err := WriteWire(p.conn, WireMsgFromScore(s, "live")); err != nil {
		p.conn.Close()
		p.conn = nil
		return err
	}
	return nil
}

// Close tears down the client socket.
func (p *FleetPeer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		err := p.conn.Close()
		p.conn = nil
		return err
	}
	return nil
}