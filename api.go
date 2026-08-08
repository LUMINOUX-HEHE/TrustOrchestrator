package trustorchestrator

// api: the gateway REST surface over the engine (management plane).
// stdlib net/http ServeMux (Go 1.22+ method patterns), no framework.
//
//	POST /v1/users                    admin   create user -> token (shown once)
//	POST /v1/users/{id}/tokens        admin   new token (optional per-token orgs scope)
//	GET  /v1/users                    admin   list users
//	POST /v1/orgs                     admin   create tenant (org)
//	GET  /v1/orgs                     any     list visible orgs
//	GET  /v1/orgs/{org}               scoped  tenant detail
//	DELETE /v1/orgs/{org}             admin   delete tenant (files -> trash)
//	GET  /v1/orgs/{org}/pubkey        scoped  org timeline verification key
//	GET  /v1/orgs/{org}/timeline      scoped  events (filter/paginate)
//	POST /v1/orgs/{org}/issue         op+     append ISSUE event
//	POST /v1/orgs/{org}/revoke        op+     append REVOKE event
//	GET  /v1/orgs/{org}/state         scoped  folded trust state
//	GET  /v1/orgs/{org}/graph         scoped  trust graph
//	POST /v1/orgs/{org}/scores        op+     watchdog score frame -> Detect
//	POST /v1/orgs/{org}/recover       op+     apply council-authorized recovery fork
//	GET  /v1/orgs/{org}/pubkey        scoped  org timeline verification key
//	GET  /v1/audit                    aud+    search (timeline events, or actions)
//	GET  /v1/webhooks                 admin   list webhooks
//	POST /v1/webhooks                 admin   register webhook
//	DELETE /v1/webhooks/{id}          admin   remove webhook
//	POST /v1/backup                   admin   snapshot -> {id}
//	GET  /v1/backup/{id}/download     admin   download bundle
//	POST /v1/restore                  admin   restore from bundle
//	GET  /v1/metrics                  viewer+ prometheus text
//	GET  /v1/health                   none    liveness
//
// RBAC: role checks per route + org scoping (user.Orgs) + per-token org
// scoping (TokenOrgs) for tenant routes; mutating POSTs honor
// Idempotency-Key replay. Recovery is council-authorized end to end: the API holds only the
// council's FROST group key (the trust anchor); shards/seeds never cross
// this surface (the seed endpoint is gone). VerifyRecovery post-conditions
// (P3/P5) are enforced by the council before the fork is produced.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxBody = 1 << 20 // wire trust boundary: cap every request body

// NewGateway loads the store and seeds the first admin user. The returned
// raw token is shown once (empty when an admin already exists).
func NewGateway(dir, bootstrapToken string) (*Store, string, error) {
	s, err := NewStore(dir)
	if err != nil {
		return nil, "", err
	}
	var token string
	if len(s.Users) == 0 {
		u, raw, err := NewUser("admin", RoleAdmin, nil)
		if err != nil {
			return nil, "", err
		}
		s.Users["admin"] = u
		if bootstrapToken != "" {
			u.Tokens = append(u.Tokens, tokenHash(bootstrapToken))
			raw = bootstrapToken
		}
		token = raw
		if err := s.saveMeta(); err != nil {
			return nil, "", err
		}
	}
	for _, t := range s.Tenants {
		s.watchOrg(t)
	}
	s.StartWebhookOutbox()
	return s, token, nil
}

// Handler builds the full route table with auth/RBAC/scope middleware.
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	s.route(mux, "GET /v1/health", nil, false, s.handleHealth)
	s.route(mux, "POST /v1/users", []string{RoleAdmin}, false, s.handleCreateUser)
	s.route(mux, "GET /v1/users", []string{RoleAdmin}, false, s.handleListUsers)
	s.route(mux, "POST /v1/users/{id}/tokens", []string{RoleAdmin}, false, s.handleUserToken)
	s.route(mux, "POST /v1/orgs", []string{RoleAdmin}, false, s.handleCreateOrg)
	s.route(mux, "GET /v1/orgs", nil, false, s.handleListOrgs)
	s.route(mux, "GET /v1/orgs/{org}", nil, true, s.handleOrgDetail)
	s.route(mux, "DELETE /v1/orgs/{org}", []string{RoleAdmin}, false, s.handleDeleteOrg)
	s.route(mux, "GET /v1/orgs/{org}/timeline", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleTimeline)
	s.route(mux, "POST /v1/orgs/{org}/issue", []string{RoleOperator, RoleAdmin}, true, s.handleIssue)
	s.route(mux, "POST /v1/orgs/{org}/revoke", []string{RoleOperator, RoleAdmin}, true, s.handleRevoke)
	s.route(mux, "GET /v1/orgs/{org}/state", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleState)
	s.route(mux, "GET /v1/orgs/{org}/graph", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleGraph)
	s.route(mux, "POST /v1/orgs/{org}/scores", []string{RoleOperator, RoleAdmin}, true, s.handleScores)
	s.route(mux, "POST /v1/orgs/{org}/recover", []string{RoleOperator, RoleAdmin}, true, s.handleRecover)
	s.route(mux, "GET /v1/orgs/{org}/pubkey", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleOrgPubKey)
	s.route(mux, "GET /v1/orgs/{org}/ct/sth", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleCTSTH)
	s.route(mux, "GET /v1/orgs/{org}/ct/proof", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleCTProof)
	s.route(mux, "POST /v1/orgs/{org}/ct/gossip", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleCTGossip)
	s.route(mux, "GET /v1/audit", []string{RoleAuditor, RoleOperator, RoleAdmin}, false, s.handleAudit)
	s.route(mux, "GET /v1/webhooks", []string{RoleAdmin}, false, s.handleListWebhooks)
	s.route(mux, "POST /v1/webhooks", []string{RoleAdmin}, false, s.handleCreateWebhook)
	s.route(mux, "DELETE /v1/webhooks/{id}", []string{RoleAdmin}, false, s.handleDeleteWebhook)
	s.route(mux, "POST /v1/backup", []string{RoleAdmin}, false, s.handleBackup)
	s.route(mux, "GET /v1/backup/{id}/download", []string{RoleAdmin}, false, s.handleBackupDownload)
	s.route(mux, "POST /v1/restore", []string{RoleAdmin}, false, s.handleRestore)
	s.route(mux, "POST /v1/rotate", []string{RoleAdmin}, false, s.handleRotate)
	s.route(mux, "GET /v1/metrics", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, false, s.handleMetrics)
	return mux
}

// route wraps one handler with auth, role, org-scope, idempotency and
// audit middleware.
func (s *Store) route(mux *http.ServeMux, pattern string, roles []string, scoped bool, fn func(http.ResponseWriter, *http.Request, *Tenant)) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		var u *User
		var tokenHashStr string
		if pattern != "GET /v1/health" {
			var err error
			u, tokenHashStr, err = s.authenticate(r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err)
				return
			}
			if !hasRole(u.Role, roles) {
				writeErr(w, http.StatusForbidden, errors.New("insufficient role: need "+strings.Join(roles, "|")))
				return
			}
		}
		// token-bucket per identity; health is the liveness probe and stays
		// unthrottled (it has no token).
		if pattern != "GET /v1/health" && !s.apiLimiter.allow(tokenHashStr) {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, errors.New("rate limit exceeded"))
			return
		}
		var t *Tenant
		if scoped {
			org := r.PathValue("org")
			s.mu.Lock()
			t = s.Tenants[org]
			s.mu.Unlock()
			if t == nil {
				writeErr(w, http.StatusNotFound, fmt.Errorf("no such org %q", org))
				return
			}
			if u != nil && !u.inOrg(org) {
				writeErr(w, http.StatusForbidden, fmt.Errorf("user %q not scoped to org %q", u.ID, org))
				return
			}
			if u != nil && !u.tokenInOrg(tokenHashStr, org) {
				writeErr(w, http.StatusForbidden, fmt.Errorf("token not scoped to org %q", org))
				return
			}
		} else if u != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtx{}, u))
		}
		rec := &responseRecorder{ResponseWriter: w, idem: s.idemKey(r)}
		if rec.idem != "" {
			if cached, ok := s.idemLookup(rec.idem); ok {
				rec.header().Set("Content-Type", "application/json")
				rec.WriteHeader(cached.status)
				rec.Write(cached.body)
				s.Audit(AuditEntry{Ts: time.Now().Unix(), User: userID(u), Org: r.PathValue("org"),
					Method: r.Method, Path: r.URL.Path, Status: cached.status, Details: "idempotent replay"})
				return
			}
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					writeErr(rec, http.StatusInternalServerError, fmt.Errorf("panic: %v", p))
				}
			}()
			fn(rec, r, t)
		}()
		if rec.idem != "" {
			s.idemStore(rec.idem, rec.status, rec.buf)
		}
		s.Audit(AuditEntry{Ts: time.Now().Unix(), User: userID(u), Org: r.PathValue("org"),
			Method: r.Method, Path: r.URL.Path, Status: rec.status})
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	buf    []byte
	idem   string // Idempotency-Key, empty = cache nothing
}

func (r *responseRecorder) header() http.Header {
	return r.ResponseWriter.Header()
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.buf = append(r.buf, b...)
	return r.ResponseWriter.Write(b)
}

// idemEntry caches one idempotent response for replay (key -> 24h window).
type idemEntry struct {
	status int
	body   []byte
	ts     int64
}

// idemKey derives the replay key: method|path|token-user|hash(body). The
// token identity keeps one client's replay from serving another's result.
func (s *Store) idemKey(r *http.Request) string {
	key := r.Header.Get("Idempotency-Key")
	if key == "" || (r.Method != "POST" && r.Method != "PUT") {
		return ""
	}
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	u := ""
	if usr, ok := r.Context().Value(userCtx{}).(*User); ok {
		u = usr.ID
	}
	return sha256Hex([]byte(r.Method + "|" + r.URL.Path + "|" + u + "|" + key + "|" + string(body)))
}

func (s *Store) idemLookup(key string) (idemEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.idem[key]
	if ok && time.Now().Unix()-e.ts > 24*3600 {
		delete(s.idem, key)
		return idemEntry{}, false
	}
	return e, ok
}

func (s *Store) idemStore(key string, status int, body []byte) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.idem) > 4096 {
		s.idem = map[string]idemEntry{} // ponytail: blunt; LRU if this ever matters
	}
	s.idem[key] = idemEntry{status: status, body: append([]byte(nil), body...), ts: time.Now().Unix()}
}

func userID(u *User) string {
	if u == nil {
		return ""
	}
	return u.ID
}

func hasRole(role string, want []string) bool {
	if len(want) == 0 {
		return true // route open to any authenticated user
	}
	for _, w := range want {
		if role == w {
			return true
		}
	}
	return false
}

func (s *Store) authenticate(r *http.Request) (*User, string, error) {
	raw, err := BearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return nil, "", err
	}
	hash := tokenHash(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u.Authed(raw) {
			return u, hash, nil
		}
	}
	return nil, "", errors.New("invalid token")
}

// ---------- handlers ----------

func (s *Store) handleHealth(w http.ResponseWriter, r *http.Request, t *Tenant) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ts": time.Now().Unix()})
}

type createUserReq struct {
	ID   string   `json:"id"`
	Role string   `json:"role"`
	Orgs []string `json:"orgs"`
}

func (s *Store) handleCreateUser(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req createUserReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.ID == "" || req.Role == "" {
		writeErr(w, http.StatusBadRequest, errors.New("id and role required"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Users[req.ID] != nil {
		writeErr(w, http.StatusConflict, fmt.Errorf("user %q exists", req.ID))
		return
	}
	u, raw, err := NewUser(req.ID, req.Role, req.Orgs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.Users[req.ID] = u
	if err := s.saveMeta(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": u.ID, "role": u.Role, "orgs": u.Orgs, "token": raw})
}

func (s *Store) handleListUsers(w http.ResponseWriter, r *http.Request, t *Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.Users))
	for id, u := range s.Users {
		out = append(out, map[string]any{"id": id, "role": u.Role, "orgs": u.Orgs, "tokens": len(u.Tokens)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Store) handleUserToken(w http.ResponseWriter, r *http.Request, t *Tenant) {
	id := r.PathValue("id")
	var req struct {
		Orgs []string `json:"orgs,omitempty"` // optional per-token scope subset
	}
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if len(b) > 0 {
			if err := json.Unmarshal(b, &req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[id]
	if u == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no such user %q", id))
		return
	}
	raw, err := u.NewToken(req.Orgs...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.saveMeta(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": u.ID, "token": raw, "orgs": req.Orgs})
}

type createOrgReq struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Store) handleCreateOrg(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req createOrgReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	id := req.ID
	if id == "" {
		id = slugify(req.Name)
	}
	t2, _, err := s.CreateTenant(id, req.Name)
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	s.watchOrg(t2)
	writeJSON(w, http.StatusCreated, map[string]any{"id": t2.ID, "name": t2.Name, "created": t2.Created})
}

func slugify(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else if c == ' ' {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return fmt.Sprintf("org-%d", time.Now().UnixNano()%1e6)
	}
	return b.String()
}

func (s *Store) visibleOrgs(u *User) []*Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Tenant
	for _, t := range s.Tenants {
		if u.inOrg(t.ID) {
			out = append(out, t)
		}
	}
	return out
}

func (s *Store) handleListOrgs(w http.ResponseWriter, r *http.Request, t *Tenant) {
	u := mustUser(r)
	out := make([]map[string]any, 0)
	for _, t := range s.visibleOrgs(u) {
		out = append(out, orgJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": out})
}

func orgJSON(t *Tenant) map[string]any {
	return map[string]any{"id": t.ID, "name": t.Name, "created": t.Created,
		"events": int64(len(t.tl.Events())), "detected": t.detected}
}

func (s *Store) handleOrgDetail(w http.ResponseWriter, r *http.Request, t *Tenant) {
	writeJSON(w, http.StatusOK, orgJSON(t))
}

func (s *Store) handleDeleteOrg(w http.ResponseWriter, r *http.Request, t *Tenant) {
	if err := s.DeleteTenant(r.PathValue("org")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("org")})
}

// handleOrgPubKey exposes the org timeline's verification key (public only —
// the seed-over-API endpoint is gone; the shard ceremony no longer needs
// it since the council FROST shares are independent of the org root).
func (s *Store) handleOrgPubKey(w http.ResponseWriter, r *http.Request, t *Tenant) {
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "pubkey_hex": hex.EncodeToString(t.tl.Pub()),
	})
}

// orgMerkle is the transparent view of one org: the RFC 9162 log whose
// leaves are the hashes of its signed events, in append order.
func orgMerkle(t *Tenant) *MerkleLog {
	m := NewMerkleLog()
	for _, e := range t.tl.Events() {
		m.Append(e.Hash())
	}
	return m
}

func (s *Store) ctLogPub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(s.LogKey).Public().(ed25519.PublicKey)
}

// handleCTSTH serves the org's signed tree head (RFC 9162 get-sth): tree
// size, root, timestamp and the log signature over the whole STH.
func (s *Store) handleCTSTH(w http.ResponseWriter, r *http.Request, t *Tenant) {
	s.mu.Lock()
	m := orgMerkle(t)
	s.mu.Unlock()
	sth := SignSTH(ed25519.NewKeyFromSeed(s.LogKey), m.Root(), m.Size(), time.Now().Unix())
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "log_key_hex": hex.EncodeToString(s.ctLogPub()),
		"tree_size": sth.TreeSize, "timestamp": sth.Timestamp,
		"root_hex": hex.EncodeToString(sth.Root), "signature_hex": hex.EncodeToString(sth.Signature),
	})
}

// handleCTProof serves inclusion or consistency proofs against a
// requested size: ?index=&size= (inclusion, verifiable against that
// size's root) or ?from=&to= (consistency between the two sizes).
func (s *Store) handleCTProof(w http.ResponseWriter, r *http.Request, t *Tenant) {
	q := r.URL.Query()
	s.mu.Lock()
	m := orgMerkle(t)
	s.mu.Unlock()
	switch {
	case q.Has("index"):
		idx, err := strconv.Atoi(q.Get("index"))
		size, serr := strconv.Atoi(q.Get("size"))
		if err != nil || serr != nil || idx < 0 || size <= 0 {
			writeErr(w, http.StatusBadRequest, errors.New("index and size must be non-negative integers"))
			return
		}
		_, proof, err := m.InclusionProof(idx, size)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"org": t.ID, "index": idx, "size": size,
			"leaf_hash_hex": hex.EncodeToString(m.Hashes()[idx]),
			"root_hex":      hex.EncodeToString(mth(m.Hashes(), 0, size)),
			"proof":         hashesHex(proof),
		})
	case q.Has("from"):
		from, err := strconv.Atoi(q.Get("from"))
		to, serr := strconv.Atoi(q.Get("to"))
		if err != nil || serr != nil || from < 0 || to <= from {
			writeErr(w, http.StatusBadRequest, errors.New("from and to must satisfy 0 <= from < to"))
			return
		}
		oldRoot, newRoot, proof, err := m.ConsistencyProof(from, to)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"org": t.ID, "from": from, "to": to,
			"old_root_hex": hex.EncodeToString(oldRoot), "new_root_hex": hex.EncodeToString(newRoot),
			"proof": hashesHex(proof),
		})
	default:
		writeErr(w, http.StatusBadRequest, errors.New("give index+size (inclusion) or from+to (consistency)"))
	}
}

func hashesHex(p [][]byte) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = hex.EncodeToString(h)
	}
	return out
}

// handleCTGossip is the transparency verifier: a reporter submits an STH
// it saw (signed, with the consistency proof against the size it trusts),
// and the gateway checks the signature and, when the reported head is
// newer, that the gateway's current head is a prefix of it. accepted=false
// with alarm set means the log or the reporter lied.
func (s *Store) handleCTGossip(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var in struct {
		TreeSize  int64    `json:"tree_size"`
		Timestamp int64    `json:"timestamp"`
		Root      []byte   `json:"root_b64"`
		Signature []byte   `json:"signature_b64"`
		ProofFrom int      `json:"proof_from"`
		Proof     []string `json:"proof_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sth := SignedTreeHead{TreeSize: in.TreeSize, Timestamp: in.Timestamp, Root: in.Root, Signature: in.Signature}
	proof := make([][]byte, len(in.Proof))
	for i, h := range in.Proof {
		b, err := hex.DecodeString(h)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		proof[i] = b
	}
	node := NewGossipNode(s.ctLogPub(), &SignedTreeHead{TreeSize: t.ctSize, Root: t.ctRoot})
	accepted, _ := node.Observe(&sth, proof, in.ProofFrom)
	if accepted && sth.TreeSize > t.ctSize {
		t.ctSize, t.ctRoot = sth.TreeSize, sth.Root
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "accepted": accepted,
		"alarm":             node.Alarm(),
		"trusted_tree_size": t.ctSize,
		"trusted_root_hex":  hex.EncodeToString(t.ctRoot),
	})
}

func eventJSON(e TrustEvent) map[string]any {
	out := map[string]any{
		"type": e.Type, "ts": e.Timestamp,
		"payload_b64": base64.StdEncoding.EncodeToString(e.Payload),
		"parent_hash": hex.EncodeToString(e.ParentHash),
		"hash":        hex.EncodeToString(e.Hash()),
	}
	var p issuePayload
	if json.Unmarshal(e.Payload, &p) == nil && p.CertID != "" {
		out["cert_id"], out["identity"] = p.CertID, p.Identity
		if p.Via != "" {
			out["via"] = p.Via
		}
	}
	var r struct {
		CertID string `json:"cert_id"`
	}
	if json.Unmarshal(e.Payload, &r) == nil && r.CertID != "" {
		out["cert_id"] = r.CertID
	}
	return out
}

func (s *Store) handleTimeline(w http.ResponseWriter, r *http.Request, t *Tenant) {
	events := t.tl.Events()
	typ, since, until := r.URL.Query().Get("type"), qint(r, "since"), qint(r, "until")
	limit := int(qint(r, "limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		if typ != "" && e.Type != typ {
			continue
		}
		if since > 0 && e.Timestamp < since || until > 0 && e.Timestamp > until {
			continue
		}
		out = append(out, eventJSON(e))
	}
	total := len(out)
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": t.ID, "count": len(out), "total": total, "events": out})
}

type issueReq struct {
	CertID   string `json:"cert_id"`
	Identity string `json:"identity"`
	Via      string `json:"via"`
}

func (s *Store) handleIssue(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req issueReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.CertID == "" || req.Identity == "" {
		writeErr(w, http.StatusBadRequest, errors.New("cert_id and identity required"))
		return
	}
	s.mu.Lock()
	pl, _ := json.Marshal(issuePayload{CertID: req.CertID, Identity: req.Identity, Via: req.Via})
	h, err := t.tl.Append(EvIssue, pl, time.Now().Unix())
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t.counters["issues"]++
	t.counters["events"]++
	err = s.saveTenant(t)
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.FireWebhooks(t.ID, HookIssue, h, map[string]any{"cert_id": req.CertID, "identity": req.Identity})
	writeJSON(w, http.StatusCreated, map[string]any{"org": t.ID, "hash": hex.EncodeToString(h)})
}

type revokeReq struct {
	CertID string `json:"cert_id"`
}

func (s *Store) handleRevoke(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req revokeReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.CertID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("cert_id required"))
		return
	}
	s.mu.Lock()
	pl, _ := json.Marshal(map[string]string{"cert_id": req.CertID})
	h, err := t.tl.Append(EvRevoke, pl, time.Now().Unix())
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t.counters["revokes"]++
	t.counters["events"]++
	err = s.saveTenant(t)
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.FireWebhooks(t.ID, HookRevoke, h, map[string]any{"cert_id": req.CertID})
	writeJSON(w, http.StatusCreated, map[string]any{"org": t.ID, "hash": hex.EncodeToString(h)})
}

func (s *Store) handleState(w http.ResponseWriter, r *http.Request, t *Tenant) {
	st := t.tl.Fold()
	writeJSON(w, http.StatusOK, map[string]any{"org": t.ID, "certs": st.Certs})
}

func (s *Store) handleGraph(w http.ResponseWriter, r *http.Request, t *Tenant) {
	nodes, edges := map[string]bool{}, [][2]string{}
	for _, e := range t.tl.Events() {
		var p issuePayload
		if e.Type != EvIssue || json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		nodes["id:"+p.Identity] = true
		nodes["cert:"+p.CertID] = true
		if p.Via != "" {
			nodes["cert:"+p.Via] = true
			edges = append(edges, [2]string{"cert:" + p.Via, "cert:" + p.CertID})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": t.ID, "nodes": keysOf(nodes), "edges": edges})
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// handleScores ingests one watchdog frame into the org's FleetServer; the
// watcher goroutine (watchOrg) appends DETECTED and fires webhooks.
func (s *Store) handleScores(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req struct {
		NodeID   string          `json:"node_id"`
		Score    float64         `json:"score"`
		PValue   float64         `json:"p_value"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.NodeID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("node_id required"))
		return
	}
	t.fleet.Ingest(WireMsgFromScore(Score{NodeID: req.NodeID, Score: req.Score,
		PValue: req.PValue, Evidence: req.Evidence}, "api"))
	writeJSON(w, http.StatusAccepted, map[string]any{"org": t.ID, "node": req.NodeID, "score": req.Score})
}

type recoverReq struct {
	Timeline json.RawMessage `json:"timeline"` // the council-produced recovery fork
	Commit   *FrostCommit    `json:"commit"`   // the threshold-signed handoff (also inside the fork)
}

// handleRecover applies a council-authorized recovery fork. The operator
// submits the council's output (fork + handoff); the API verifies the
// handoff against the council FROST group key, the fork's chain integrity,
// and that the fork descends from THIS org's verified prefix before
// adopting it. No shards or seeds ever cross this surface.
func (s *Store) handleRecover(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req recoverReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Commit == nil || len(req.Timeline) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("timeline and commit required"))
		return
	}
	// verify and adopt under the lock; webhooks and the response must not
	// run here — FireWebhooks takes s.mu itself (deadlocks otherwise).
	fork, code, err := func() (*Timeline, int, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.CouncilPub) != ed25519.PublicKeySize {
			return nil, http.StatusUnprocessableEntity, errors.New("council trust anchor not configured")
		}
		if !req.Commit.Valid(s.CouncilPub, quorum) {
			return nil, http.StatusUnprocessableEntity, errors.New("handoff signature invalid")
		}
		fork, err := UnmarshalTimeline(req.Timeline)
		if err != nil {
			return nil, http.StatusUnprocessableEntity, fmt.Errorf("bad fork: %w", err)
		}
		if !fork.Verify() {
			return nil, http.StatusUnprocessableEntity, errors.New("fork chain verification failed")
		}
		// the handoff must be present and be the fork's branch point
		idx := -1
		for i, e := range fork.Events() {
			if e.Type == EvRecovery {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, http.StatusUnprocessableEntity, errors.New("fork has no recovery handoff")
		}
		// the fork must descend from THIS org's verified prefix: events before
		// the handoff are exactly our chain's events (the compromised region
		// beyond the checkpoint is what recovery replaces).
		cur := t.tl.Events()
		if len(cur) < idx {
			return nil, http.StatusUnprocessableEntity, errors.New("fork does not descend from this org's timeline")
		}
		for i := 0; i < idx; i++ {
			if !bytes.Equal(cur[i].Hash(), fork.Events()[i].Hash()) {
				return nil, http.StatusUnprocessableEntity, errors.New("fork prefix mismatch")
			}
		}
		// epochs must advance monotonically (no replay of a stale recovery)
		if lastEpoch(fork) <= lastEpoch(t.tl) {
			return nil, http.StatusUnprocessableEntity, errors.New("fork epoch does not advance")
		}
		t.tl = fork
		t.detected = false
		t.counters["recoveries"]++
		if err := s.saveTenant(t); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return fork, 0, nil
	}()
	if err != nil {
		writeErr(w, code, err)
		return
	}
	s.FireWebhooks(t.ID, HookRecovery, fork.Head(), map[string]any{
		"epoch": req.Commit.Epoch, "issued": len(req.Commit.Members)})
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "epoch": req.Commit.Epoch, "issued": len(req.Commit.Members),
		"head": hex.EncodeToString(fork.Head())})
}

func lastDetected(t *Tenant) (*TrustEvent, error) {
	for i := len(t.tl.events) - 1; i >= 0; i-- {
		if t.tl.events[i].Type == EvDetected {
			return &t.tl.events[i], nil
		}
	}
	return nil, errors.New("no DETECTED event on this org's timeline; post watchdog scores first")
}

func (s *Store) handleAudit(w http.ResponseWriter, r *http.Request, t *Tenant) {
	u := mustUser(r)
	q := r.URL.Query()
	if q.Get("source") == "actions" {
		org := q.Get("org")
		if org != "" && !u.inOrg(org) {
			writeErr(w, http.StatusForbidden, errors.New("not scoped to that org"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"actions": s.SearchAudit(org, q.Get("user"), q.Get("method"), qint(r, "since"), qint(r, "until"), int(qint(r, "limit")))})
		return
	}
	// source=events (default): timeline events across visible orgs.
	typ, identity, cert := q.Get("type"), q.Get("identity"), q.Get("cert")
	since, until := qint(r, "since"), qint(r, "until")
	limit := qint(r, "limit")
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	out := []map[string]any{}
	for _, org := range s.visibleOrgs(u) {
		for _, e := range org.tl.Events() {
			if typ != "" && e.Type != typ {
				continue
			}
			if since > 0 && e.Timestamp < since || until > 0 && e.Timestamp > until {
				continue
			}
			var p issuePayload
			if json.Unmarshal(e.Payload, &p) == nil {
				if identity != "" && p.Identity != identity {
					continue
				}
				if cert != "" && p.CertID != cert {
					continue
				}
			}
			j := eventJSON(e)
			j["org"] = org.ID
			out = append(out, j)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "events": out})
}

type webhookReq struct {
	URL    string   `json:"url"`
	Secret string   `json:"secret"`
	Events []string `json:"events"`
}

func (s *Store) handleListWebhooks(w http.ResponseWriter, r *http.Request, t *Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": s.Webhooks})
}

func (s *Store) handleCreateWebhook(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req webhookReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" {
		// ponytail: loopback http only for local sinks (tests/dev);
		// everything else must be TLS. The outbox retries over the wire.
		if !(u != nil && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			writeErr(w, http.StatusBadRequest, errors.New("webhook url must be https (or http on loopback)"))
			return
		}
	}
	if u == nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid url"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := &Webhook{ID: fmt.Sprintf("wh-%d", time.Now().UnixNano()), URL: req.URL, Secret: req.Secret, Events: req.Events, Active: true}
	s.Webhooks = append(s.Webhooks, h)
	if err := s.saveMeta(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, h)
}

func (s *Store) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, t *Tenant) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, h := range s.Webhooks {
		if h.ID == id {
			s.Webhooks = append(s.Webhooks[:i], s.Webhooks[i+1:]...)
			if err := s.saveMeta(); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
			return
		}
	}
	writeErr(w, http.StatusNotFound, fmt.Errorf("no such webhook %q", id))
}

// handleBackup snapshots the store to data/backups/<id>.json and answers
// with the id (downloadable, or fetch the file directly for offsite copies).
func (s *Store) handleBackup(w http.ResponseWriter, r *http.Request, t *Tenant) {
	b, err := s.Backup()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	dir := backupDir(s.dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	id := fmt.Sprintf("bk-%d", time.Now().Unix())
	if err := writeFileAtomic(backupPath(s.dir, id), b); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "size": len(b),
		"download": "/v1/backup/" + id + "/download"})
}

func (s *Store) handleBackupDownload(w http.ResponseWriter, r *http.Request, t *Tenant) {
	id := r.PathValue("id")
	b, err := os.ReadFile(backupPath(s.dir, id))
	if err != nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no such backup %q", id))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *Store) handleRestore(w http.ResponseWriter, r *http.Request, t *Tenant) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Restore(b); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored": true})
}

// handleRotate is the post-compromise key rotation over the API: the
// request body carries the council's KEK share (a 3-of-5 unwrap session as
// with the -kek-shares boot flag), RotateVault bumps the DEK + epoch and
// re-wraps every tenant. Old DEK snapshots stop working the moment this
// returns.
func (s *Store) handleRotate(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var body struct {
		Shares []Shard `json:"shares"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(&body); err != nil || len(body.Shares) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("rotate: body needs {\"shares\": [3 or more Shard JSON files]}"))
		return
	}
	shares := make([]*Shard, len(body.Shares))
	for i := range body.Shares {
		shares[i] = &body.Shares[i]
	}
	if err := s.RotateVault(shares); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	epoch := s.vault.Epoch
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"rotated": true, "epoch": epoch})
}

func (s *Store) handleMetrics(w http.ResponseWriter, r *http.Request, t *Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "to_uptime_seconds %d\n", int64(time.Since(s.started).Seconds()))
	fmt.Fprintf(&b, "to_users %d\n", len(s.Users))
	fmt.Fprintf(&b, "to_orgs %d\n", len(s.Tenants))
	fmt.Fprintf(&b, "to_audit_entries %d\n", len(s.audit))
	for id, org := range s.Tenants {
		fmt.Fprintf(&b, "to_events_total{org=%q} %d\n", id, org.counters["events"])
		fmt.Fprintf(&b, "to_issues_total{org=%q} %d\n", id, org.counters["issues"])
		fmt.Fprintf(&b, "to_revokes_total{org=%q} %d\n", id, org.counters["revokes"])
		fmt.Fprintf(&b, "to_detections_total{org=%q} %d\n", id, org.counters["detections"])
		fmt.Fprintf(&b, "to_recoveries_total{org=%q} %d\n", id, org.counters["recoveries"])
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

// watchOrg subscribes to one org's fleet verdicts; on the rising edge of
// DETECTED it appends the evidence event, persists, and fires webhooks.
func (s *Store) watchOrg(t *Tenant) {
	verdicts := t.fleet.Subscribe()
	go func() {
		for v := range verdicts {
			var fired []byte
			bad := 0
			s.mu.Lock()
			if v.Detected && !t.detected {
				bad = minBadIndex(v.Scores)
				if bad < 0 {
					bad = len(t.tl.events)
				}
				pl, _ := json.Marshal(map[string]int{"bad_index": bad})
				h, err := t.tl.Append(EvDetected, pl, time.Now().Unix())
				t.detected = true
				t.counters["detections"]++
				t.counters["events"]++
				if err == nil {
					s.saveTenant(t)
					fired = h
				}
			} else if !v.Detected {
				t.detected = false
			}
			s.mu.Unlock()
			if fired != nil {
				s.FireWebhooks(t.ID, HookDetected, fired, map[string]any{"bad_index": bad})
			}
		}
	}()
}

func minBadIndex(scores []Score) int {
	bad := -1
	for _, sc := range scores {
		if sc.Score >= threshold {
			continue
		}
		var ev struct {
			BadIndex int `json:"bad_index"`
		}
		if json.Unmarshal(sc.Evidence, &ev) == nil && ev.BadIndex >= 0 && (bad < 0 || ev.BadIndex < bad) {
			bad = ev.BadIndex
		}
	}
	return bad
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(b, v)
}

func mustUser(r *http.Request) *User {
	if u, ok := r.Context().Value(userCtx{}).(*User); ok {
		return u
	}
	return nil
}

type userCtx struct{}

func qint(r *http.Request, name string) int64 {
	v, err := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func backupDir(dir string) string { return filepath.Join(dir, "backups") }

func backupPath(dir, id string) string { return filepath.Join(backupDir(dir), id+".json") }
