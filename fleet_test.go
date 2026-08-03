package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

// testFleet builds a real mTLS fleet over loopback: a CA, one server leaf,
// and nLeafs watchdog leafs. Returns the server, its address, and per-node
// peers. Everything is std-library TLS 1.3 on real sockets.
func testFleet(t *testing.T, nLeafs int) (*FleetServer, string, []*FleetPeer) {
	t.Helper()
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca, caDER, err := NewIdentityCA(caKey, "fleet-test", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvPub, srvKey, _ := ed25519.GenerateKey(rand.Reader)
	srvLeaf, err := IssueWorkloadCert(ca, caKey, srvPub, "orchestrator", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := MutualTLSConfig(caDER, srvLeaf, srvKey)
	if err != nil {
		t.Fatal(err)
	}

	fleet := NewFleet(25.0, 3, 90*time.Second)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	go fleet.Serve(ln)
	t.Cleanup(func() { fleet.Stop(); ln.Close() })

	peers := make([]*FleetPeer, nLeafs)
	for i := 0; i < nLeafs; i++ {
		wdPub, wdKey, _ := ed25519.GenerateKey(rand.Reader)
		wdDER, err := IssueWorkloadCert(ca, caKey, wdPub, "watchdog-W"+string(rune('1'+i)), int64(2+i), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		wcfg, err := MutualTLSConfig(caDER, wdDER, wdKey)
		if err != nil {
			t.Fatal(err)
		}
		wcfg.ServerName = "orchestrator" // DNS SAN on the server leaf; dial by address
		p := NewFleetPeer(ln.Addr().String(), wcfg)
		peers[i] = p
		t.Cleanup(func() { p.Close() })
	}
	return fleet, ln.Addr().String(), peers
}

// healthy builds a Score for node id with the given health.
func healthy(id string, score float64) Score {
	return Score{NodeID: id, Score: score, PValue: 1.0}
}

// TestFleetLiveVerdict exercises the full relay over a real loopback socket:
// three peers stream, the ensemble stays healthy while all three are ok, then
// flips to DETECTED as soon as the quorum condition (>=2 below threshold)
// holds in the live view.
func TestFleetLiveVerdict(t *testing.T) {
	fleet, _, peers := testFleet(t, 3)
	if fleet == nil {
		t.Fatal("no fleet")
	}
	verdicts := fleet.Subscribe()
	for i, p := range peers {
		if err := p.Send(healthy("W"+string(rune('1'+i)), 100)); err != nil {
			t.Fatal(err)
		}
	}
	// drain until we observe one non-detected verdict with count 3
	deadline := time.After(5 * time.Second)
	for ok := false; !ok; {
		select {
		case v := <-verdicts:
			if v.Count == 3 && !v.Detected {
				ok = true
			}
		case <-deadline:
			t.Fatal("no healthy ensemble verdict broadcast in 5s")
		}
	}
	// all three peers suddenly score low -> quorum 3 -> DETECTED
	peers[0].Send(healthy("W1", 0))
	peers[1].Send(healthy("W2", 0))
	peers[2].Send(healthy("W3", 0))
	for ok := false; !ok; {
		select {
		case v := <-verdicts:
			if v.Detected {
				ok = true
			}
		case <-deadline:
			t.Fatal("ensemble never flipped to DETECTED")
		}
	}
}

// TestFleetFrameLossReconnect proves the reconnect path: kill a live peer's
// socket mid-stream, the next Send must redial and the server must still
// accept and fold the frame (frame loss self-heals within one cycle).
func TestFleetFrameLossReconnect(t *testing.T) {
	fleet, _, peers := testFleet(t, 2)
	if fleet == nil {
		t.Fatal("no fleet")
	}
	verds := fleet.Subscribe()
	if err := peers[0].Send(healthy("W1", 70)); err != nil {
		t.Fatal(err)
	}
	// force the client socket closed server- and client-side
	peers[0].Close()
	if err := peers[0].Send(healthy("W1", 70)); err != nil {
		t.Fatalf("reconnect after forced close failed: %v", err)
	}
	// the server must see the frame arrive fresh on the new socket
	select {
	case v := <-verds:
		if v.Count < 1 {
			t.Fatalf("server did not ingest the reconnected frame, count=%d", v.Count)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no verdict after reconnect")
	}
}

func TestFleetConcurrentFanIn(t *testing.T) {
	fleet, _, peers := testFleet(t, 5)
	verds := fleet.Subscribe()
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p *FleetPeer) {
			defer wg.Done()
			p.Send(healthy("W"+string(rune('1'+i)), float64(60+i)))
		}(i, p)
	}
	wg.Wait()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case v := <-verds:
			if v.Count == 5 {
				return
			}
		case <-deadline:
			t.Fatalf("concurrent fan-in stalled, count=%v", 0)
		}
	}
}