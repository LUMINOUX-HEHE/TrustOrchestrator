package trustorchestrator

// store: the gateway's on-disk state — one JSON file per tenant timeline
// plus a gateway.json for users/webhooks/tenant meta. Writes are atomic
// (tmp + rename), serialized by one mutex. Backup = copy data/ ; the
// /v1/backup endpoint is the same data as one JSON bundle.
// ponytail: file-per-tenant, no SQL. Linear scans are fine at this scale;
// move to SQLite when a single org's audit search outgrows a load.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// encMagic prefixes sealed on-disk blobs; legacy plaintext files lack it.
const encMagic = "TOENC1"

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

	tl         *Timeline
	fleet      *FleetServer // score fan-in + Detect fusion for this org
	detected   bool
	counters   map[string]int64 // events/issues/revokes/detections/recoveries totals
	ctSize     int64            // highest CT tree head accepted via gossip for this org
	ctRoot     []byte           // ...and its root hash
}

// Webhook is one outbound notification endpoint (webhooks.go).
type Webhook struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Secret string   `json:"secret"`
	Events []string `json:"events"` // empty = all: detected, recovery, revoke, issue
	Active bool     `json:"active"`
}

// Store is the whole gateway state, persisted under one directory. The
// seal key (tenant file encryption) lives in gateway.key, NOT in this
// struct, so it never rides along in gateway.json copies/backups.
type Store struct {
	mu         sync.Mutex
	dir        string
	sealKey    []byte             // 32-byte AES key; zero when disabled (legacy dirs)
	vault      *Vault             // envelope encryption (vault.go); nil = legacy v1/plaintext
	Users      map[string]*User   `json:"users"`
	Webhooks   []*Webhook         `json:"webhooks"`
	Tenants    map[string]*Tenant `json:"tenants"`
	CouncilPub []byte             `json:"council_pub,omitempty"` // FROST group key; trust anchor for recoveries
	LogKey     []byte             `json:"log_key,omitempty"`     // CT log signing key (ed25519 seed, RFC 9162 STHs)
	audit      []AuditEntry
	started    time.Time
	outbox     []webhookJob // durable delivery queue (webhooks.go); own file, not gateway.json
	outboxOnce sync.Once
	idem       map[string]idemEntry // Idempotency-Key replay cache (api.go), in-memory
	apiLimiter *limiter             // per-token budget on the REST surface (ratelimit.go)
}

// SetCouncilPub installs the council FROST group key (trust anchor) and
// persists it. Test/operator wiring: cmd/gateway or integration tests.
func (s *Store) SetCouncilPub(pub ed25519.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CouncilPub = append([]byte(nil), pub...)
	return s.saveMeta()
}

// CouncilPublicKey returns the configured trust anchor, or nil.
func (s *Store) CouncilPublicKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.CouncilPub...)
}

// NewStore loads or initializes the store under dir. The seal key is
// created once (gateway.key); a data-dir without one runs unencrypted
// (legacy), which loadTenantTimeline tolerates.
func NewStore(dir string) (*Store, error) {
	s := &Store{dir: dir, Users: map[string]*User{}, Tenants: map[string]*Tenant{}, started: time.Now(), idem: map[string]idemEntry{}, apiLimiter: newLimiter(apiRate, apiBurst)}
	if err := os.MkdirAll(filepath.Join(dir, "tenants"), 0o700); err != nil {
		return nil, err
	}
	s.sealKey, _ = os.ReadFile(filepath.Join(dir, "gateway.key"))
	if len(s.sealKey) != 32 {
		s.sealKey = make([]byte, 32)
		if _, err := rand.Read(s.sealKey); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "gateway.key"), s.sealKey, 0o600); err != nil {
			return nil, err
		}
		// legacy files written without a key stay plaintext on disk;
		// every write from here on is sealed
	}
	b, err := os.ReadFile(filepath.Join(dir, "gateway.json"))
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("store: corrupt gateway.json: %w", err)
		}
		s.loadOutbox()
		for id := range s.Tenants {
			tl, err := s.loadTenantTimeline(id)
			if err != nil {
				// vault-sealed file with no unlocked vault: defer the tenant
				// to UnlockVault (the -kek-shares session) instead of dying —
				// the files stay unreadable until the shares arrive.
				if errors.Is(err, errVaultUnlocked) {
					s.Tenants[id].fleet = NewFleet(threshold, quorum, 0) // keep watchOrg wired; feed scores after unlock
					s.Tenants[id].counters = map[string]int64{}
					continue
				}
				return nil, fmt.Errorf("store: tenant %s: %w", id, err)
			}
			if len(s.CouncilPub) == ed25519.PublicKeySize && len(tl.CouncilPub()) == 0 {
				tl.SetCouncilPub(s.CouncilPub) // re-stamp after a reload
			}
			s.Tenants[id].tl = tl
			s.Tenants[id].fleet = NewFleet(threshold, quorum, 0)
			s.Tenants[id].counters = map[string]int64{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if len(s.LogKey) != ed25519.SeedSize {
		s.LogKey = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(s.LogKey); err != nil {
			return nil, err
		}
		if err := s.saveMeta(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

var errVaultUnlocked = errors.New("store: tenant is vault-sealed but no vault is unlocked (start the gateway with -kek-shares)")

// loadTenantTimeline reads one tenant's timeline file, sealed or legacy.
// v2 (vaultMagic) files require an unlocked vault; errVaultUnlocked is how
// a boot without the 3-of-5 session defers, never silently guessing.
func (s *Store) loadTenantTimeline(id string) (*Timeline, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "tenants", id, "timeline.json"))
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(b, []byte(vaultMagic)) {
		if s.vault == nil {
			return nil, errVaultUnlocked
		}
		raw, err := s.vault.Open(id, b)
		if err != nil {
			return nil, fmt.Errorf("store: vault open: %w", err)
		}
		return UnmarshalTimeline(raw)
	}
	if !bytes.HasPrefix(b, []byte(encMagic)) {
		return UnmarshalTimeline(b) // legacy plaintext
	}
	raw, err := openSealed(s.sealKey, b)
	if err != nil {
		return nil, err
	}
	return UnmarshalTimeline(raw)
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
	if len(s.CouncilPub) == ed25519.PublicKeySize {
		t.tl.SetCouncilPub(s.CouncilPub) // org chains live under the council anchor
	}
	s.Tenants[id] = t
	if err := s.saveTenant(t); err != nil {
		return nil, "", err
	}
	if err := s.saveMeta(); err != nil {
		return nil, "", err
	}
	return t, fmt.Sprintf("tenant %q created (root key local to gateway; recovery is council-authorized)", id), nil
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
	return s.saveTenantBlob(t, b)
}

// saveTenantBlob writes one tenant timeline, sealed under the vault when
// enabled, else the legacy v1 seal key (or plaintext when neither exists).
func (s *Store) saveTenantBlob(t *Tenant, b []byte) error {
	var err error
	if s.vault != nil {
		if b, err = s.vault.Seal(t.ID, b); err != nil {
			return err
		}
	} else if len(s.sealKey) == 32 {
		if b, err = seal(s.sealKey, b); err != nil {
			return err
		}
	}
	dir := filepath.Join(s.dir, "tenants", t.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "timeline.json"), b)
}

// seal adds a magic prefix, random nonce, then AES-256-GCM (the iv rides
// along). openSealed reverses it. Non-encrypting callers (Restore against a
// keyless store) need Key; a keyed store re-encrypts via saveTenant.
func seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(encMagic), nonce...)
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(out, nonce, plain, nil), nil
}

func openSealed(key, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("store: timeline is sealed but no seal key (gateway.key)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := blob[len(encMagic):len(encMagic)+12], blob[len(encMagic)+12:]
	return aead.Open(nil, nonce, ct, nil)
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
	// ponytail: the bundle is an operator export, same trust tier as
	// evidence dumps (keys included) — at-rest files are the seal target.
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
	gw.sealKey = append([]byte(nil), s.sealKey...) // re-encrypt under our key
	gw.vault = s.vault                              // or under our vault envelope
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

// UnlockVault is the boot unwrap session (threshold-as-KMS): ≥3 council
// shares reconstruct the KEK, which unseals gateway.keys into the live
// vault. First boot on an unkeyed/legacy store: mints a fresh vault, seals
// it, and re-encodes every tenant under it. The KEK lives only in this
// stack frame (zeroBytes). After this, stores run with envelope encryption.
func (s *Store) UnlockVault(shares []*Shard) error {
	kek, err := JoinKEK(shares)
	if err != nil {
		return fmt.Errorf("vault: unwrap session: %w", err)
	}
	defer zeroBytes(kek)
	s.mu.Lock()
	defer s.mu.Unlock()
	keysPath := filepath.Join(s.dir, "gateway.keys")
	v, err := readVaultKeyFile(keysPath, kek)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if v == nil {
		if v, err = NewVault(); err != nil {
			return err
		}
		if err := writeVaultKeyFile(keysPath, kek, v); err != nil {
			return err
		}
	}
	s.vault = v
	if err := s.loadVaultedTenants(); err != nil { // boot-deferred tenants (vault-sealed at NewStore)
		return err
	}
	return s.reSealAllTenants() // upgrade any legacy v1/plaintext files
}

// RotateVault is the post-compromise rotation: with the council's KEK back
// in a fresh unwrap session, a new DEK + epoch are sealed and every tenant
// file is re-sealed. Pre-rotation snapshots — DEK or tenant files — cannot
// open anything written afterwards: the leak survives only until the next
// rotation it missed. Payload data is re-wrapped in place, not re-encrypted
// (v1 → v2 upgrade comes with UnlockVault).
func (s *Store) RotateVault(shares []*Shard) error {
	kek, err := JoinKEK(shares)
	if err != nil {
		return fmt.Errorf("vault: unwrap session: %w", err)
	}
	defer zeroBytes(kek)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return errors.New("vault: no active vault (gateway booted without -kek-shares)")
	}
	nv, err := NewVault()
	if err != nil {
		return err
	}
	nv.Epoch = s.vault.Epoch + 1
	if err := writeVaultKeyFile(filepath.Join(s.dir, "gateway.keys"), kek, nv); err != nil {
		return err
	}
	s.vault = nv
	if err := s.loadVaultedTenants(); err != nil {
		return err
	}
	return s.reSealAllTenants()
}

// loadVaultedTenants hydrates tenants that NewStore deferred (vault-sealed
// file, no shares at boot): they become live once the vault is unlocked.
func (s *Store) loadVaultedTenants() error {
	for id := range s.Tenants {
		t := s.Tenants[id]
		if t.tl != nil {
			continue
		}
		tl, err := s.loadTenantTimeline(id)
		if err != nil {
			return fmt.Errorf("store: tenant %s (vault): %w", id, err)
		}
		if len(s.CouncilPub) == ed25519.PublicKeySize && len(tl.CouncilPub()) == 0 {
			tl.SetCouncilPub(s.CouncilPub)
		}
		t.tl = tl
		t.fleet = NewFleet(threshold, quorum, 0)
		t.counters = map[string]int64{}
	}
	return nil
}

// reSealAllTenants re-encodes every tenant file under the current vault:
// on Unlock it upgrades v1/plaintext, on Rotate it re-seals with fresh
// epoch keys. Reads from the in-memory timelines, so no old-format reads.
func (s *Store) reSealAllTenants() error {
	if s.vault == nil {
		return nil
	}
	for _, t := range s.Tenants {
		if err := s.saveTenant(t); err != nil {
			return err
		}
	}
	return nil
}
