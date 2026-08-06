package trustorchestrator

// api: the gateway REST surface over the engine (management plane).
// stdlib net/http ServeMux (Go 1.22+ method patterns), no framework.
//
//	POST /v1/users                    admin   create user -> token (shown once)
//	POST /v1/users/{id}/tokens        admin   new token for a user
//	GET  /v1/users                    admin   list users
//	POST /v1/orgs                     admin   create tenant (org)
//	GET  /v1/orgs                     any     list visible orgs
//	GET  /v1/orgs/{org}               scoped  tenant detail
//	DELETE /v1/orgs/{org}             admin   delete tenant (files -> trash)
//	GET  /v1/orgs/{org}/keys          admin   root seed for the shard ceremony
//	GET  /v1/orgs/{org}/timeline      scoped  events (filter/paginate)
//	POST /v1/orgs/{org}/issue         op+     append ISSUE event
//	POST /v1/orgs/{org}/revoke        op+     append REVOKE event
//	GET  /v1/orgs/{org}/state         scoped  folded trust state
//	GET  /v1/orgs/{org}/graph         scoped  trust graph
//	POST /v1/orgs/{org}/scores        op+     watchdog score frame -> Detect
//	POST /v1/orgs/{org}/recover       op+     council recovery (shards in body)
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
// RBAC: role checks per route + org scoping (user.Orgs) for tenant routes.
// Ponytail on recovery: the API path reconstructs the root from shards
// in-process and signs the commit with ephemeral member keys — real
// threshold signatures come from cmd/council over mTLS (councilnet.go).
// VerifyRecovery post-conditions (P3/P5) still gate the result.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	s.route(mux, "GET /v1/orgs/{org}/keys", []string{RoleAdmin}, true, s.handleOrgKeys)
	s.route(mux, "GET /v1/orgs/{org}/timeline", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleTimeline)
	s.route(mux, "POST /v1/orgs/{org}/issue", []string{RoleOperator, RoleAdmin}, true, s.handleIssue)
	s.route(mux, "POST /v1/orgs/{org}/revoke", []string{RoleOperator, RoleAdmin}, true, s.handleRevoke)
	s.route(mux, "GET /v1/orgs/{org}/state", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleState)
	s.route(mux, "GET /v1/orgs/{org}/graph", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, true, s.handleGraph)
	s.route(mux, "POST /v1/orgs/{org}/scores", []string{RoleOperator, RoleAdmin}, true, s.handleScores)
	s.route(mux, "POST /v1/orgs/{org}/recover", []string{RoleOperator, RoleAdmin}, true, s.handleRecover)
	s.route(mux, "GET /v1/audit", []string{RoleAuditor, RoleOperator, RoleAdmin}, false, s.handleAudit)
	s.route(mux, "GET /v1/webhooks", []string{RoleAdmin}, false, s.handleListWebhooks)
	s.route(mux, "POST /v1/webhooks", []string{RoleAdmin}, false, s.handleCreateWebhook)
	s.route(mux, "DELETE /v1/webhooks/{id}", []string{RoleAdmin}, false, s.handleDeleteWebhook)
	s.route(mux, "POST /v1/backup", []string{RoleAdmin}, false, s.handleBackup)
	s.route(mux, "GET /v1/backup/{id}/download", []string{RoleAdmin}, false, s.handleBackupDownload)
	s.route(mux, "POST /v1/restore", []string{RoleAdmin}, false, s.handleRestore)
	s.route(mux, "GET /v1/metrics", []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin}, false, s.handleMetrics)
	return mux
}

// route wraps one handler with auth, role, org-scope, and audit middleware.
func (s *Store) route(mux *http.ServeMux, pattern string, roles []string, scoped bool, fn func(http.ResponseWriter, *http.Request, *Tenant)) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		var u *User
		if pattern != "GET /v1/health" {
			var err error
			u, err = s.authenticate(r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err)
				return
			}
			if !hasRole(u.Role, roles) {
				writeErr(w, http.StatusForbidden, errors.New("insufficient role: need "+strings.Join(roles, "|")))
				return
			}
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
		} else if u != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtx{}, u))
		}
		rec := &responseRecorder{ResponseWriter: w}
		func() {
			defer func() {
				if p := recover(); p != nil {
					writeErr(rec, http.StatusInternalServerError, fmt.Errorf("panic: %v", p))
				}
			}()
			fn(rec, r, t)
		}()
		s.Audit(AuditEntry{Ts: time.Now().Unix(), User: userID(u), Org: r.PathValue("org"),
			Method: r.Method, Path: r.URL.Path, Status: rec.status})
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
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
	return r.ResponseWriter.Write(b)
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

func (s *Store) authenticate(r *http.Request) (*User, error) {
	raw, err := BearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u.Authed(raw) {
			return u, nil
		}
	}
	return nil, errors.New("invalid token")
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
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[id]
	if u == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no such user %q", id))
		return
	}
	raw, err := u.NewToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.saveMeta(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": u.ID, "token": raw})
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

func (s *Store) handleOrgKeys(w http.ResponseWriter, r *http.Request, t *Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seed := t.tl.key.Seed()
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "seed_b64": base64.StdEncoding.EncodeToString(seed),
		"ceremony": "to shard --key <seedfile> --shares 5 --threshold 3",
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
	Shards []*Shard `json:"shards"`
}

// handleRecover runs the council recovery with shards supplied by the
// operator (3 of the 5 ceremony shards). Evidence = the latest DETECTED
// event on the org's timeline.
func (s *Store) handleRecover(w http.ResponseWriter, r *http.Request, t *Tenant) {
	var req recoverReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Shards) < quorum {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("need >= %d shards", quorum))
		return
	}
	s.mu.Lock()
	evidence, err := lastDetected(t)
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	members := make([]*CouncilMember, len(req.Shards))
	for i, sh := range req.Shards {
		_, k, kerr := ed25519.GenerateKey(rand.Reader)
		if kerr != nil {
			s.mu.Unlock()
			writeErr(w, http.StatusInternalServerError, kerr)
			return
		}
		members[i] = &CouncilMember{ID: fmt.Sprintf("shard-%d", i+1), Key: k, Shard: sh}
	}
	rep, err := NewCouncil(members).Recover(t.tl, evidence, quorum)
	if err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusUnprocessableEntity, fmt.Errorf("recovery blocked: %w", err))
		return
	}
	t.tl = rep.Timeline
	t.detected = false
	t.counters["recoveries"]++
	if err := s.saveTenant(t); err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Unlock()
	s.FireWebhooks(t.ID, HookRecovery, rep.Timeline.Head(), map[string]any{
		"epoch": rep.Commit.Epoch, "issued": rep.Issued, "verify": rep.Verify.Pass()})
	writeJSON(w, http.StatusOK, map[string]any{
		"org": t.ID, "epoch": rep.Commit.Epoch, "issued": rep.Issued,
		"verify": rep.Verify.Pass(), "head": hex.EncodeToString(rep.Timeline.Head())})
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
	if err != nil || u.Scheme != "https" && u.Scheme != "http" {
		writeErr(w, http.StatusBadRequest, errors.New("url must be http(s)"))
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
