package trustorchestrator

// webhooks: outbound notifications on trust events. On every trigger the
// dispatcher POSTs {org, type, ts, event_hash, details} JSON to each
// matching endpoint, signed with HMAC-SHA256 over the body
// (X-TO-Signature header), 3 attempts with a fixed backoff.
// ponytail: in-memory queue — a crash between trigger and delivery drops
// the notification. Add a durable outbox when delivery guarantees matter.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Webhook event types (subset of timeline event types + recovery).
const (
	HookDetected = "detected"
	HookRecovery = "recovery"
	HookRevoke   = "revoke"
	HookIssue    = "issue"
)

func (s *Store) hookMatches(h *Webhook, typ string) bool {
	if !h.Active {
		return false
	}
	for _, e := range h.Events {
		if e == typ || e == "*" {
			return true
		}
	}
	return len(h.Events) == 0 // empty = all events
}

// FireWebhooks dispatches one event to every matching endpoint (locking
// internally — callers must NOT hold s.mu). Goroutines do the network I/O.
func (s *Store) FireWebhooks(org, typ string, eventHash []byte, details map[string]any) {
	s.mu.Lock()
	hooks := make([]*Webhook, 0, len(s.Webhooks))
	for _, h := range s.Webhooks {
		if s.hookMatches(h, typ) {
			hooks = append(hooks, h)
		}
	}
	s.mu.Unlock()
	body, err := json.Marshal(map[string]any{
		"org": org, "type": typ, "ts": time.Now().Unix(),
		"event_hash": hex.EncodeToString(eventHash), "details": details,
	})
	if err != nil {
		return
	}
	for _, h := range hooks {
		go deliver(h, body)
	}
}

func deliver(h *Webhook, body []byte) {
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TO-Signature", hmacHex(h.Secret, body))
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
		if attempt < 3 {
			time.Sleep(2 * time.Second)
		}
	}
}

func hmacHex(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}
