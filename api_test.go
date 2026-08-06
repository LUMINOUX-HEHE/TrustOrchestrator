package trustorchestrator

// End-to-end gateway checks: auth/RBAC, org lifecycle, issue/revoke,
// detection via scores -> webhook, council recovery via API shards,
// backup/restore roundtrip, audit search. One test per surface, all over
// httptest against the real mux.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestGateway(t *testing.T, dir string) (*Store, string) {
	t.Helper()
	gw, token, err := NewGateway(dir, "")
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gw, token
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, token string, body any) *http.Response {
	t.Helper()
	var rd ioReader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

type ioReader = interface{ Read([]byte) (int, error) }

// doRaw sends a raw byte body (backup bundles must not be re-marshaled).
func doRaw(t *testing.T, srv *httptest.Server, method, path, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestGatewayAuthRBAC(t *testing.T) {
	dir := t.TempDir()
	gw, admin := newTestGateway(t, dir)
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	if resp := doJSON(t, srv, "GET", "/v1/orgs", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", resp.StatusCode)
	}
	// create an org, then a viewer scoped to it
	if resp := doJSON(t, srv, "POST", "/v1/orgs", admin, map[string]string{"name": "acme"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", resp.StatusCode)
	}
	body := decode[map[string]any](t, doJSON(t, srv, "POST", "/v1/users", admin,
		map[string]any{"id": "view", "role": RoleViewer, "orgs": []string{"acme"}}))
	viewer := body["token"].(string)

	// viewer can read state but not issue
	if resp := doJSON(t, srv, "GET", "/v1/orgs/acme/state", viewer, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer read: %d", resp.StatusCode)
	}
	if resp := doJSON(t, srv, "POST", "/v1/orgs/acme/issue", viewer,
		map[string]string{"cert_id": "c1", "identity": "user"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer issue: want 403, got %d", resp.StatusCode)
	}
	// viewer cannot see an org it is not scoped to
	if resp := doJSON(t, srv, "GET", "/v1/orgs/other/state", viewer, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("viewer foreign org: want 404, got %d", resp.StatusCode)
	}
	// admin can list users; viewer cannot
	if resp := doJSON(t, srv, "GET", "/v1/users", viewer, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer users list: want 403, got %d", resp.StatusCode)
	}
}

func TestGatewayLifecycle(t *testing.T) {
	dir := t.TempDir()
	gw, admin := newTestGateway(t, dir)
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	if resp := doJSON(t, srv, "POST", "/v1/orgs", admin, map[string]string{"name": "acme"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", resp.StatusCode)
	}
	if resp := doJSON(t, srv, "POST", "/v1/orgs/acme/issue", admin,
		map[string]string{"cert_id": "c1", "identity": "user", "via": "c0"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue: %d", resp.StatusCode)
	}
	if resp := doJSON(t, srv, "POST", "/v1/orgs/acme/revoke", admin,
		map[string]string{"cert_id": "c1"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	state := decode[struct {
		Certs map[string]Cert `json:"certs"`
	}](t, doJSON(t, srv, "GET", "/v1/orgs/acme/state", admin, nil))
	if c, ok := state.Certs["c1"]; !ok || !c.Revoked {
		t.Fatalf("state: want c1 revoked, got %+v", state.Certs)
	}
	tl := decode[struct {
		Events []map[string]any `json:"events"`
	}](t, doJSON(t, srv, "GET", "/v1/orgs/acme/timeline", admin, nil))
	if len(tl.Events) != 2 {
		t.Fatalf("timeline: want 2 events, got %d", len(tl.Events))
	}
	// audit search finds the issue
	aud := decode[struct {
		Events []map[string]any `json:"events"`
	}](t, doJSON(t, srv, "GET", "/v1/audit?type=ISSUE&identity=user", admin, nil))
	if len(aud.Events) != 1 {
		t.Fatalf("audit: want 1 ISSUE, got %d", len(aud.Events))
	}
}

func TestGatewayDetectAndRecover(t *testing.T) {
	dir := t.TempDir()
	gw, admin := newTestGateway(t, dir)
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	// webhook sink
	var mu sync.Mutex
	var hooks []map[string]any
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		hooks = append(hooks, m)
		mu.Unlock()
	}))
	defer sink.Close()
	if resp := doJSON(t, srv, "POST", "/v1/webhooks", admin,
		map[string]any{"url": sink.URL, "secret": "s3cret", "events": []string{"detected"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("webhook: %d", resp.StatusCode)
	}

	doJSON(t, srv, "POST", "/v1/orgs", admin, map[string]string{"name": "acme"})
	for i := 0; i < 5; i++ { // honest traffic before the attack
		doJSON(t, srv, "POST", "/v1/orgs/acme/issue", admin,
			map[string]string{"cert_id": fmt.Sprintf("c%d", i), "identity": "user"})
	}
	// 3 of 5 watchdogs alarm with evidence pointing at event 3
	for _, n := range []string{"W1", "W2", "W3"} {
		if resp := doJSON(t, srv, "POST", "/v1/orgs/acme/scores", admin,
			map[string]any{"node_id": n, "score": 0, "p_value": 0.01, "evidence": map[string]int{"bad_index": 3}}); resp.StatusCode != http.StatusAccepted {
			t.Fatalf("score %s: %d", n, resp.StatusCode)
		}
	}

	// DETECTED event lands (watcher goroutine), webhook fires
	deadline := time.Now().Add(5 * time.Second)
	for {
		tl := gw.Tenants["acme"].tl.Events()
		var detected bool
		for _, e := range tl {
			detected = detected || e.Type == EvDetected
		}
		mu.Lock()
		gotHook := len(hooks) > 0
		mu.Unlock()
		if detected && gotHook {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("detection did not land (detected=%v hooks=%d)", detected, len(hooks))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// council recovery via API shards (3-of-5 from the tenant root key)
	seed := gw.Tenants["acme"].tl.key.Seed()
	shards, err := ShamirSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]json.RawMessage, 3)
	for i, sh := range shards[:3] {
		b, _ := sh.Marshal()
		raw[i] = b
	}
	resp := doJSON(t, srv, "POST", "/v1/orgs/acme/recover", admin, map[string]any{"shards": raw})
	rep := decode[map[string]any](t, resp)
	if resp.StatusCode != http.StatusOK || rep["verify"] != true {
		t.Fatalf("recover: %d %v", resp.StatusCode, rep)
	}
	// post-recovery state: P3 — c3/c4 are rolled back and can never
	// reappear; c0..c2 survive; user got a fresh cert.
	state := decode[struct {
		Certs map[string]Cert `json:"certs"`
	}](t, doJSON(t, srv, "GET", "/v1/orgs/acme/state", admin, nil))
	if c4, ok := state.Certs["c4"]; ok && !c4.Revoked {
		t.Fatalf("P3: c4 must be revoked or absent, got %+v", c4)
	}
	if c0 := state.Certs["c0"]; c0.Identity != "user" || c0.Revoked {
		t.Fatalf("c0 must survive recovery: %+v", c0)
	}
	reissued := false
	for id := range state.Certs {
		reissued = reissued || id == "user-re1"
	}
	if !reissued {
		t.Fatalf("identity user must be re-issued: %+v", state.Certs)
	}
	// a wrong shard set must block
	bogus, _ := ShamirSplit([]byte("nope-nope-nope-nope"), 5, 3)
	badRaw := make([]json.RawMessage, 3)
	for i, sh := range bogus[:3] {
		b, _ := sh.Marshal()
		badRaw[i] = b
	}
	if resp := doJSON(t, srv, "POST", "/v1/orgs/acme/recover", admin, map[string]any{"shards": badRaw}); resp.StatusCode == http.StatusOK {
		t.Fatalf("bogus shards must not recover")
	}
}

func TestGatewayBackupRestore(t *testing.T) {
	dir1 := t.TempDir()
	gw1, admin1 := newTestGateway(t, dir1)
	srv1 := httptest.NewServer(gw1.Handler())
	defer srv1.Close()

	doJSON(t, srv1, "POST", "/v1/orgs", admin1, map[string]string{"name": "acme"})
	doJSON(t, srv1, "POST", "/v1/orgs/acme/issue", admin1,
		map[string]string{"cert_id": "c1", "identity": "user"})

	// snapshot + download
	bk := decode[map[string]any](t, doJSON(t, srv1, "POST", "/v1/backup", admin1, nil))
	if bk["id"] == nil {
		t.Fatalf("backup: %v", bk)
	}
	dl := doJSON(t, srv1, "GET", "/v1/backup/"+bk["id"].(string)+"/download", admin1, nil)
	b, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if !strings.Contains(string(b), `"version": 1`) {
		t.Fatalf("bundle missing version: %s", b[:200])
	}

	// restore into a fresh gateway
	dir2 := t.TempDir()
	gw2, admin2 := newTestGateway(t, dir2)
	srv2 := httptest.NewServer(gw2.Handler())
	defer srv2.Close()
	if resp := doRaw(t, srv2, "POST", "/v1/restore", admin2, b); resp.StatusCode != http.StatusOK {
		eb, _ := io.ReadAll(resp.Body)
		t.Fatalf("restore: %d %s", resp.StatusCode, eb)
	}
	state := decode[struct {
		Certs map[string]Cert `json:"certs"`
	}](t, doJSON(t, srv2, "GET", "/v1/orgs/acme/state", admin1, nil)) // bundle carries its own users
	if state.Certs["c1"].Identity != "user" {
		t.Fatalf("restored state missing c1: %+v", state.Certs)
	}
	// tampered bundle must be rejected, not crash the store
	bad := strings.Replace(string(b), "acme", "evil", 1)
	if resp := doRaw(t, srv2, "POST", "/v1/restore", admin2, []byte(bad)); resp.StatusCode == http.StatusOK {
		t.Fatalf("tampered bundle must not restore")
	}
}
