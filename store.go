package trustorchestrator

// store: the gateway's on-disk state — one JSON file per tenant timeline
// plus a gateway.json for users/webhooks/tenant meta. Writes are atomic
// (tmp + rename), serialized by one mutex. Backup = copy data/ ; the
// /v1/backup endpoint is the same data as one JSON bundle.
// ponytail: file-per-tenant, no SQL. Linear scans are fine at this scale;
// move to SQLite when a single org's audit search outgrows a load.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const auditCap = 5000

// AuditEntry is one gateway action (who did what), searchable via /v1/audit.
type AuditEntry struct {
	Ts      int64  `json:"ts"`
	User    string `json:"user"`
	Org     string `json:"org,omitempty"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Details string `json:"details,omitempty"`
}

// Tenant is one isolated trust timeline + live detector ensemble.
type Tenant struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
	KeyHash string `json:"key_hash"` // ponytail: demo tier stores the root key in timeline.json, like evidence dumps

	tl       *Timeline
	fleet    *FleetServer // score fan-in + Detect fusion for this org
	detected bool
	counters map[string]int64 // events/issues/revokes/detections/recoveries totals
}

// Webhook is one outbound notification endpoint (webhooks.go).
type Webhook struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Secret string   `json:"secret"`
	Events []string `json:"events"` // empty = all: detected, recovery, revoke, issue
	Active bool     `json:"active"`
}

// Store is the whole gateway state, persisted under one directory.
type Store struct {
	mu       sync.Mutex
	dir      string
	Users    map[string]*User   `json:"users"`
	Webhooks []*Webhook         `json:"webhooks"`
	Tenants  map[string]*Tenant `json:"tenants"`
	audit    []AuditEntry
	started  time.Time
}

// NewStore loads or initializes the store under dir.
func NewStore(dir string) (*Store, error) {
	s := &Store{dir: dir, Users: map[string]*User{}, Tenants: map[string]*Tenant{}, started: time.Now()}
	if err := os.MkdirAll(filepath.Join(dir, "tenants"), 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "gateway.json"))
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("store: corrupt gateway.json: %w", err)
		}
		for id := range s.Tenants {
			tl, err := LoadTimeline(filepath.Join(dir, "tenants", id, "timeline.json"))
			if err != nil {
				return nil, fmt.Errorf("store: tenant %s: %w", id, err)
			}
			s.Tenants[id].tl = tl
			s.Tenants[id].fleet = NewFleet(threshold, quorum, 0)
			s.Tenants[id].counters = map[string]int64{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// CreateTenant makes a fresh org with its own timeline and detector.
func (s *Store) CreateTenant(id, name string) (*Tenant, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Tenants[id] != nil {
		return nil, "", fmt.Errorf("tenant %q exists", id)
	}
	key, err := genKey()
	if err != nil {
		return nil, "", err
	}
	t := &Tenant{ID: id, Name: name, Created: time.Now().Unix(),
		KeyHash: sha256Hex(key.Seed()), tl: NewTimeline(key),
		fleet: NewFleet(threshold, quorum, 0), counters: map[string]int64{}}
	s.Tenants[id] = t
	if err := s.saveTenant(t); err != nil {
		return nil, "", err
	}
	if err := s.saveMeta(); err != nil {
		return nil, "", err
	}
	return t, fmt.Sprintf("tenant %q created; shards via GET /v1/orgs/%s/keys (offline ceremony)", id, id), nil
}

// DeleteTenant removes an org from the active set; its files are moved aside,
// not deleted (operator can recover from data/trash if it was a mistake).
func (s *Store) DeleteTenant(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Tenants[id] == nil {
		return fmt.Errorf("no such tenant %q", id)
	}
	delete(s.Tenants, id)
	src := filepath.Join(s.dir, "tenants", id)
	trash := filepath.Join(s.dir, "trash", fmt.Sprintf("%s-%d", id, time.Now().Unix()))
	if err := os.Rename(src, trash); err != nil {
		return err
	}
	return s.saveMeta()
}

// saveMeta writes gateway.json (users, webhooks, tenant meta — not the
// timelines, which persist independently).
func (s *Store) saveMeta() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "gateway.json"), b)
}

func (s *Store) saveTenant(t *Tenant) error {
	b, err := t.tl.Marshal(true) // includeKey: demo tier, same as evidence dumps
	if err != nil {
		return err
	}
	dir := filepath.Join(s.dir, "tenants", t.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "timeline.json"), b)
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Audit appends one action to the ring buffer (mutations only).
func (s *Store) Audit(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, e)
	if len(s.audit) > auditCap {
		s.audit = s.audit[len(s.audit)-auditCap:]
	}
}

// SearchAudit filters the ring buffer; all filters optional.
func (s *Store) SearchAudit(org, user, method string, since, until int64, limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AuditEntry
	for _, e := range s.audit {
		if org != "" && e.Org != org {
			continue
		}
		if user != "" && e.User != user {
			continue
		}
		if method != "" && e.Method != method {
			continue
		}
		if since > 0 && e.Ts < since || until > 0 && e.Ts > until {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Backup serializes the entire store (users, webhooks, all tenant timelines)
// to one JSON bundle — the /v1/backup artifact.
func (s *Store) Backup() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle := map[string]any{"version": 1, "created": time.Now().Unix(), "gateway": s}
	tls := map[string]json.RawMessage{}
	for id, t := range s.Tenants {
		b, err := t.tl.Marshal(true)
		if err != nil {
			return nil, err
		}
		tls[id] = b
	}
	bundle["tenants"] = tls
	return json.MarshalIndent(bundle, "", "  ")
}

// Restore validates a backup bundle (every timeline must verify) and swaps
// it in, rewriting all files. The old data dir is not touched until the new
// state is fully written (each tenant timeline written first, meta last).
func (s *Store) Restore(b []byte) error {
	var bundle struct {
		Version int                        `json:"version"`
		Gateway *Store                     `json:"gateway"`
		Tenants map[string]json.RawMessage `json:"tenants"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		return fmt.Errorf("restore: not a backup bundle: %w", err)
	}
	if bundle.Version != 1 || bundle.Gateway == nil {
		return fmt.Errorf("restore: unsupported bundle version %d", bundle.Version)
	}
	gw := bundle.Gateway
	gw.dir = s.dir
	gw.started = time.Now()
	nt := map[string]*Tenant{}
	for id, raw := range bundle.Tenants {
		tl, err := UnmarshalTimeline(raw)
		if err != nil {
			return fmt.Errorf("restore: tenant %s timeline: %w", id, err)
		}
		if !tl.Verify() {
			return fmt.Errorf("restore: tenant %s timeline failed verification", id)
		}
		meta, ok := gw.Tenants[id]
		if !ok {
			meta = &Tenant{ID: id, Name: id}
		}
		meta.tl = tl
		meta.fleet = NewFleet(threshold, quorum, 0)
		if meta.counters == nil {
			meta.counters = map[string]int64{}
		}
		nt[id] = meta
	}
	gw.Tenants = nt
	if err := gw.saveMeta(); err != nil {
		return err
	}
	for _, t := range nt {
		if err := gw.saveTenant(t); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users, s.Webhooks, s.Tenants = gw.Users, gw.Webhooks, gw.Tenants
	return nil
}
