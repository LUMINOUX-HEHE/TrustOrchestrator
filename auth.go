package trustorchestrator

// auth: users, bearer tokens, RBAC (gateway management plane).
// ponytail: API tokens only — no passwords to hash. Tokens are 32 random
// bytes shown once at creation, stored as SHA-256 hashes. If username
// passwords are ever needed, PBKDF2 (stdlib, Go 1.24+) slots in behind the
// same User struct.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func genKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Roles, coarsest to finest. A role's permission set is checked by
// requireRole against the route table in api.go.
const (
	RoleAdmin    = "admin"    // everything: users, orgs, webhooks, backup, recovery
	RoleOperator = "operator" // issue/revoke/recover/scores within own orgs
	RoleAuditor  = "auditor"  // read + audit search within own orgs
	RoleViewer   = "viewer"   // read-only dashboards within own orgs
)

var validRoles = map[string]bool{RoleAdmin: true, RoleOperator: true, RoleAuditor: true, RoleViewer: true}

// User is one gateway account. Orgs empty = all orgs (admin); otherwise the
// user is scoped to exactly these org ids (logical tenancy, API layer).
type User struct {
	ID     string   `json:"id"`
	Role   string   `json:"role"`
	Orgs   []string `json:"orgs,omitempty"`
	Tokens []string `json:"tokens"` // SHA-256(token) hashes, never raw
}

func (u *User) inOrg(org string) bool {
	if len(u.Orgs) == 0 {
		return true
	}
	for _, o := range u.Orgs {
		if o == org {
			return true
		}
	}
	return false
}

// NewToken generates one raw API token and registers its hash. Returns the
// raw token exactly once — the caller shows it to the operator, then it is
// unrecoverable.
func (u *User) NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := hex.EncodeToString(b)
	u.Tokens = append(u.Tokens, tokenHash(raw))
	return raw, nil
}

func tokenHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Authed checks raw against the user's registered token hashes.
func (u *User) Authed(raw string) bool {
	want := tokenHash(raw)
	for _, t := range u.Tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// BearerToken extracts the token from an Authorization header value.
func BearerToken(authHeader string) (string, error) {
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("missing or malformed Authorization header")
	}
	return parts[1], nil
}

// NewUser validates role/orgs and returns a user with one fresh token.
func NewUser(id, role string, orgs []string) (*User, string, error) {
	if !validRoles[role] {
		return nil, "", fmt.Errorf("unknown role %q", role)
	}
	u := &User{ID: id, Role: role, Orgs: orgs}
	raw, err := u.NewToken()
	if err != nil {
		return nil, "", err
	}
	return u, raw, nil
}
