package trustorchestrator

// Client: the Go SDK — a thin typed REST client over the gateway API.
// The full engine library (Timeline, Council, ShamirSplit, Watchdog, ...)
// is the rest of this package; Client is for management-plane automation.
// Zero deps: net/http + encoding/json.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to one gateway. base is like "http://localhost:8080".
type Client struct {
	base  string
	token string
	hc    *http.Client
}

func NewClient(base, token string) *Client {
	return &Client{base: base, token: token, hc: &http.Client{Timeout: 30 * time.Second}}
}

// APIError carries the gateway's status and {"error": ...} message.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("gateway: %d %s", e.Status, e.Body) }

func (c *Client) do(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &APIError{Status: resp.StatusCode, Body: string(b)}
	}
	return b, nil
}

func (c *Client) json(method, path string, body, out any) error {
	b, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// OrgInfo is the tenant summary from /v1/orgs.
type OrgInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	Events   int64  `json:"events"`
	Detected bool   `json:"detected"`
}

func (c *Client) Orgs() ([]OrgInfo, error) {
	var out struct {
		Orgs []OrgInfo `json:"orgs"`
	}
	return out.Orgs, c.json("GET", "/v1/orgs", nil, &out)
}

func (c *Client) CreateOrg(name, id string) (OrgInfo, error) {
	var out OrgInfo
	return out, c.json("POST", "/v1/orgs", map[string]string{"name": name, "id": id}, &out)
}

func (c *Client) DeleteOrg(id string) error { return c.json("DELETE", "/v1/orgs/"+id, nil, nil) }

// Issue appends an ISSUE event; returns the event hash.
func (c *Client) Issue(org, certID, identity, via string) (string, error) {
	var out struct {
		Hash string `json:"hash"`
	}
	err := c.json("POST", "/v1/orgs/"+org+"/issue",
		map[string]string{"cert_id": certID, "identity": identity, "via": via}, &out)
	return out.Hash, err
}

// Revoke appends a REVOKE event; returns the event hash.
func (c *Client) Revoke(org, certID string) (string, error) {
	var out struct {
		Hash string `json:"hash"`
	}
	err := c.json("POST", "/v1/orgs/"+org+"/revoke", map[string]string{"cert_id": certID}, &out)
	return out.Hash, err
}

// State is the folded trust state of an org.
func (c *Client) State(org string) (map[string]Cert, error) {
	var out struct {
		Certs map[string]Cert `json:"certs"`
	}
	return out.Certs, c.json("GET", "/v1/orgs/"+org+"/state", nil, &out)
}

// Event is one timeline entry as served by the API (payload base64).
type Event struct {
	Type     string `json:"type"`
	Ts       int64  `json:"ts"`
	CertID   string `json:"cert_id"`
	Identity string `json:"identity"`
	Via      string `json:"via"`
	Hash     string `json:"hash"`
	Parent   string `json:"parent_hash"`
}

func (c *Client) Timeline(org string, typ string, limit int) ([]Event, error) {
	path := fmt.Sprintf("/v1/orgs/%s/timeline?limit=%d", org, limit)
	if typ != "" {
		path += "&type=" + typ
	}
	var out struct {
		Events []Event `json:"events"`
	}
	return out.Events, c.json("GET", path, nil, &out)
}

// Scores posts one watchdog frame (node_id, score, optional bad_index).
func (c *Client) Scores(org, nodeID string, score float64, badIndex int) error {
	ev := json.RawMessage(nil)
	if badIndex >= 0 {
		ev = json.RawMessage(fmt.Sprintf(`{"bad_index":%d}`, badIndex))
	}
	return c.json("POST", "/v1/orgs/"+org+"/scores", map[string]any{
		"node_id": nodeID, "score": score, "p_value": 0.01, "evidence": ev}, nil)
}

// Recover runs council recovery with >= 3 ceremony shards (see ShamirSplit).
func (c *Client) Recover(org string, shards []*Shard) error {
	return c.json("POST", "/v1/orgs/"+org+"/recover", map[string]any{"shards": shards}, nil)
}

// Audit searches timeline events across visible orgs.
func (c *Client) Audit(org, typ, identity, cert string, limit int) ([]Event, error) {
	path := fmt.Sprintf("/v1/audit?limit=%d", limit)
	if org != "" {
		path += "&org=" + org
	}
	if typ != "" {
		path += "&type=" + typ
	}
	if identity != "" {
		path += "&identity=" + identity
	}
	if cert != "" {
		path += "&cert=" + cert
	}
	var out struct {
		Events []Event `json:"events"`
	}
	return out.Events, c.json("GET", path, nil, &out)
}

// Metrics returns the prometheus text from /v1/metrics.
func (c *Client) Metrics() (string, error) {
	b, err := c.do("GET", "/v1/metrics", nil)
	return string(b), err
}

// Backup creates a snapshot and returns its id; Download fetches the bundle.
func (c *Client) Backup() (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	return out.ID, c.json("POST", "/v1/backup", nil, &out)
}

func (c *Client) DownloadBackup(id string) ([]byte, error) {
	return c.do("GET", "/v1/backup/"+id+"/download", nil)
}

// Restore validates and swaps in a backup bundle.
func (c *Client) Restore(bundle []byte) error {
	req, err := http.NewRequest("POST", c.base+"/v1/restore", bytes.NewReader(bundle))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode, Body: string(b)}
	}
	return nil
}

// CreateUser registers a user and returns the one-time raw token.
func (c *Client) CreateUser(id, role string, orgs []string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.json("POST", "/v1/users", map[string]any{"id": id, "role": role, "orgs": orgs}, &out)
	return out.Token, err
}

func (c *Client) Users() ([]map[string]any, error) {
	var out struct {
		Users []map[string]any `json:"users"`
	}
	return out.Users, c.json("GET", "/v1/users", nil, &out)
}

type WebhookInfo struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Active bool     `json:"active"`
}

func (c *Client) Webhooks() ([]WebhookInfo, error) {
	var out struct {
		Webhooks []WebhookInfo `json:"webhooks"`
	}
	return out.Webhooks, c.json("GET", "/v1/webhooks", nil, &out)
}

func (c *Client) CreateWebhook(url, secret string, events []string) error {
	return c.json("POST", "/v1/webhooks",
		map[string]any{"url": url, "secret": secret, "events": events}, nil)
}

func (c *Client) DeleteWebhook(id string) error {
	return c.json("DELETE", "/v1/webhooks/"+id, nil, nil)
}
