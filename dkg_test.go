package trustorchestrator

// The distrustful interactive DKG over the council wire: five members on
// five real mTLS endpoints, no coordinator. Every member ends with ONLY
// its own share; the group key is identical on all of them; a threshold
// of the resulting shares signs and verifies under that group key.

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"testing"
)

func TestPairwiseDkg(t *testing.T) {
	ca, caKey, caDER := testCA(t)
	n, k := 5, 3

	// Bind all listeners first (each member has its own mTLS identity),
	// then build the nodes with the real address map — the addresses are
	// part of the session id, so every member must derive the same one.
	listeners := map[string]net.Listener{}
	var cfgs map[string]*tls.Config
	peers := map[string]string{}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("M%d", i)
		_, cfg := testMemberNode(t, ca, caKey, caDER, id, int64(i))
		ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		if cfgs == nil {
			cfgs = map[string]*tls.Config{}
		}
		cfgs[id] = cfg
		listeners[id] = ln
		peers[id] = ln.Addr().String()
	}
	nodes := map[string]*DkgNode{}
	for id, addr := range peers {
		node, err := NewDkgNode(id, addr, n, k, cfgs[id], peers)
		if err != nil {
			t.Fatal(err)
		}
		nodes[id] = node
	}

	type result struct {
		id  string
		key ed25519.PublicKey
		err error
	}
	ch := make(chan result, n)
	for id, node := range nodes {
		go func(id string, node *DkgNode) {
			g, err := node.RunOn(listeners[id])
			ch <- result{id: id, key: g, err: err}
		}(id, node)
	}
	var group ed25519.PublicKey
	for i := 0; i < n; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatalf("%s: %v", r.id, r.err)
		}
		if group == nil {
			group = r.key
		} else if !r.key.Equal(group) {
			t.Fatalf("%s: group key differs from the others", r.id)
		}
	}

	// The group key is real: a 3-of-5 FROST signature verifies under it.
	signers := []*FrostSigner{nodes["M1"].Signer(), nodes["M3"].Signer(), nodes["M5"].Signer()}
	m := []byte("dkg-era recovery manifest")
	sig, err := FrostRound(group, signers, m)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(group, m, sig) {
		t.Fatal("DKG-derived threshold signature fails stdlib verification")
	}

	// Share files round trip through the ceremony CLI path (GlobalVK).
	file := FrostShareFile{
		ID: "M1", X: nodes["M1"].Signer().X, Y: nodes["M1"].Signer().Share,
		GroupPub: group, PubShare: nodes["M1"].Signer().PubShare,
		GlobalVK: nodes["M1"].Signer().GlobalVK,
	}
	loaded, err := file.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.GroupPub) != string(group) {
		t.Fatal("share file group key mismatch")
	}
}

// TestDkgRejectsCorruptShare: recordPeer (the Feldman gate) must reject a
// share that does not lie on the sender's commitments — a corrupt or
// substituted share kills that pair before it can poison a finalize.
func TestDkgRejectsCorruptShare(t *testing.T) {
	ca, caKey, caDER := testCA(t)
	_, cfg := testMember(t, ca, caKey, caDER, "M1", 1)
	node, err := NewDkgNode("M1", "127.0.0.1:1", 3, 2, cfg,
		map[string]string{"M1": "127.0.0.1:1", "M2": "127.0.0.1:2", "M3": "127.0.0.1:3"})
	if err != nil {
		t.Fatal(err)
	}
	// M2's real polynomial, shared as peers would share it.
	mat, err := DkgGenerate("M2", 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	good := mat.Shares["M1"] // valid f_2(1)
	forged := new(big.Int).Add(good, big.NewInt(1))
	cases := []struct {
		name  string
		share *big.Int
		want  bool
	}{
		{"good share", good, true},
		{"forged share", forged, false},
	}
	for _, c := range cases {
		err := node.recordPeer("M2", hexPts(mat.Commits), scalarBytes(c.share))
		if (err == nil) != c.want {
			t.Fatalf("%s: err=%v want ok=%v", c.name, err, c.want)
		}
	}
	// duplicate exchange and truncated commitment vectors are rejected too
	if err := node.recordPeer("M2", hexPts(mat.Commits), scalarBytes(good)); err == nil {
		t.Fatal("duplicate peer exchange must be rejected")
	}
	if err := node.recordPeer("M3", hexPts(mat.Commits[:1]), scalarBytes(good)); err == nil {
		t.Fatal("short commitment vector must be rejected")
	}
	if err := node.recordPeer("M3", hexPts(mat.Commits), []byte{1, 2, 3}); err == nil {
		t.Fatal("bad share length must be rejected")
	}
}

func testMember(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, caDER []byte, id string, serial int64) (ed25519.PrivateKey, *tls.Config) {
	return testMemberNode(t, ca, caKey, caDER, id, serial)
}