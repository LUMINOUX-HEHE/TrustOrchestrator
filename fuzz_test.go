package trustorchestrator

import (
	"math/big"
	"testing"
)

// FuzzShamirRoundTrip: any secret < p (as a field element) with any valid
// (n, k) must round-trip exactly — the leading-zero seed corruption and the
// secret >= p silent-corruption bug lived here. Secrets >= p must be
// rejected, never shared.
func FuzzShamirRoundTrip(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x02}, 3, 5)
	f.Add(make([]byte, 32), 5, 3)
	f.Add([]byte{0x7f}, 1, 1)
	f.Fuzz(func(t *testing.T, secret []byte, n, k int) {
		if len(secret) < 1 || len(secret) > 64 {
			return
		}
		if k < 1 || n < k || n > 16 {
			return
		}
		if new(big.Int).SetBytes(secret).Cmp(p) >= 0 {
			if _, err := ShamirSplit(secret, n, k); err == nil {
				t.Fatal("secret >= p must be rejected")
			}
			return
		}
		shards, err := ShamirSplit(secret, n, k)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ShamirJoin(shards[:k])
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(secret) {
			t.Fatalf("round-trip: got %d bytes %x, want %d bytes %x", len(got), got, len(secret), secret)
		}
	})
}

// FuzzUnmarshalTimeline: attacker-crafted timeline JSON must parse without
// panicking, and a parsed chain must verify/fold without crashing.
func FuzzUnmarshalTimeline(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"events":[{"type":"ISSUE","timestamp":0,"payload":null,"parent_hash":null,"signature":null}],"public_key":""}`))
	f.Add([]byte(`{"events":null,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tl, err := UnmarshalTimeline(b)
		if err != nil {
			return
		}
		tl.Verify()
		tl.VerifyPrefix(1)
		tl.LocateBadEvent()
		tl.Head()
		tl.Fold()
		_, _ = tl.Marshal(true)
	})
}

// FuzzWireFrame: attacker-controlled (header, payload) must be length-checked
// and JSON-decoded without panic — the ServeWire trust boundary.
func FuzzWireFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, '{', '}'})
	f.Add(make([]byte, 10))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 4 {
			return
		}
		_, _ = ParseWireFrame(b[:4], b[4:])
	})
}
