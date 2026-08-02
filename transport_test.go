package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"
)

// TestWireRealSockets verifies the fleet transport over real TCP + mutual
// TLS: a watchdog dials a gateway, streams a score frame, the gateway reads
// it with full identity verification, and the caller's Channel. Workload
// certs come from the identity CA — the same objects a real deployment uses.
func TestWireRealSockets(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, err := NewIdentityCA(root, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverLeaf, _ := IssueWorkloadCert(ca, root, serverKey.Public().(ed25519.PublicKey), "orchestrator-1", 1, time.Hour)
	serverCfg, _ := MutualTLSConfig(caDER, serverLeaf, serverKey)

	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	clientLeaf, _ := IssueWorkloadCert(ca, root, clientKey.Public().(ed25519.PublicKey), "watchdog-1", 2, time.Hour)
	clientCfg, _ := MutualTLSConfig(caDER, clientLeaf, clientKey)
	clientCfg.ServerName = "orchestrator-1"
	serverCfg.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
		return VerifyPeerIdentity(chains[0][0], "watchdog-1")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var got []WireMsg
	var mu sync.Mutex
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		err = ServeWire(conn, func(m WireMsg) error {
			mu.Lock()
			got = append(got, m)
			mu.Unlock()
			return nil
		})
		serverDone <- err
	}()

	conn, err := DialWire(ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("wire dial failed: %v", err)
	}
	scores := []Score{
		{NodeID: "watchdog-1", Score: 0, PValue: 0.01, Evidence: []byte(`{"bad_index":3}`)},
		{NodeID: "watchdog-1", Score: 100, PValue: 1.0},
	}
	for _, s := range scores {
		if err := WriteWire(conn, WireMsgFromScore(s, "rate_cusum")); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	if len(got) != 2 {
		mu.Unlock()
		t.Fatalf("expected 2 frames over the wire, got %d", len(got))
	}
	if got[0].NodeID != "watchdog-1" || got[0].Score != 0 || got[0].BadIdx != 3 {
		t.Fatalf("frame 0 wrong: %+v", got[0])
	}
	if got[1].Score != 100 || got[1].BadIdx != 0 {
		t.Fatalf("frame 1 wrong: %+v", got[1])
	}
	if got[0].Kind != "rate_cusum" {
		t.Fatalf("kind not carried: %+v", got[0])
	}
	mu.Unlock()
}