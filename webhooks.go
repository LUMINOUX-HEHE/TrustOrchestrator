package trustorchestrator

// webhooks: outbound notifications on trust events. On every trigger the
// dispatcher POSTs {org, type, ts, event_hash, details} JSON to each
// matching endpoint, signed with HMAC-SHA256 over the body
// (X-TO-Signature header). Deliveries go through a durable outbox
// (outbox.json in the data dir): a crash between trigger and delivery
// replays the pending jobs on restart. Backoff 5s→15s→1m→5m, dropped
// after 5 attempts (the event itself stays in the org timeline).

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Webhook event types (subset of timeline event types + recovery).
const (
	HookDetected = "detected"
	HookRecovery = "recovery"
	HookRevoke   = "revoke"
	HookIssue    = "issue"
)

const (
	outboxMaxAttempts = 5
	outboxPath        = "outbox.json"
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

// webhookJob is one pending delivery, persisted between restarts.
type webhookJob struct {
	URL      string `json:"url"`
	Secret   string `json:"secret"`
	Events   string `json:"events"`
	Body     string `json:"body"`
	Attempts int    `json:"attempts"`
	NextAt   int64  `json:"next_at"`
}

// FireWebhooks dispatches one event to every matching endpoint. It only
// queues; the drain loop (StartWebhookOutbox) does the network I/O.
// Callers must NOT hold s.mu.
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
	s.mu.Lock()
	for _, h := range hooks {
		s.outbox = append(s.outbox, webhookJob{
			URL: h.URL, Secret: h.Secret,
			Events: strings.Join(h.Events, ","),
			Body:   string(body), NextAt: time.Now().Unix(),
		})
	}
	s.saveOutboxLocked()
	s.mu.Unlock()
}

// StartWebhookOutbox spins up the delivery drain loop (idempotent).
// Called by cmd/gateway at boot; tests drive FireWebhooks directly through
// the loop via newTestGateway.
func (s *Store) StartWebhookOutbox() {
	s.outboxOnce.Do(func() {
		go s.outboxLoop()
	})
}

func (s *Store) outboxLoop() {
	// ponytail: eager first pass (fresh trigger after boot delivers fast),
	// then a 1s ticker; backoff keeps network load low.
	time.Sleep(100 * time.Millisecond)
	s.drainOutbox()
	for range time.Tick(1 * time.Second) {
		s.drainOutbox()
	}
}

func (s *Store) drainOutbox() {
	now := time.Now().Unix()
	var due []webhookJob
	s.mu.Lock()
	kept := s.outbox[:0]
	for _, j := range s.outbox {
		if j.NextAt <= now {
			due = append(due, j)
		} else {
			kept = append(kept, j)
		}
	}
	s.outbox = kept
	s.mu.Unlock()
	for _, j := range due {
		s.tryDeliver(j)
	}
}

func (s *Store) tryDeliver(j webhookJob) {
	ok := deliver(j)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.outbox {
		if s.outbox[i].URL == j.URL && s.outbox[i].Body == j.Body {
			if ok {
				s.outbox = append(s.outbox[:i], s.outbox[i+1:]...)
			} else {
				s.outbox[i].Attempts++
				if s.outbox[i].Attempts >= outboxMaxAttempts {
					s.outbox = append(s.outbox[:i], s.outbox[i+1:]...)
				} else {
					s.outbox[i].NextAt = time.Now().Unix() + backoff(s.outbox[i].Attempts)
				}
			}
			break
		}
	}
	s.saveOutboxLocked()
}

// backoff: 5s, 15s, 1m, 5m (attempts 1..4); callers cap after 5 attempts.
func backoff(attempt int) int64 {
	switch attempt {
	case 1:
		return 5
	case 2:
		return 15
	case 3:
		return 60
	default:
		return 300
	}
}

func (s *Store) loadOutbox() {
	b, err := os.ReadFile(filepath.Join(s.dir, outboxPath))
	if err != nil {
		return // absent = fresh store; corrupt = drop, outbox is at-most-once
	}
	if err := json.Unmarshal(b, &s.outbox); err != nil {
		fmt.Fprintf(os.Stderr, "outbox: ignoring corrupt %s: %v\n", outboxPath, err)
	}
}

func (s *Store) saveOutboxLocked() {
	if s.outbox == nil {
		return
	}
	b, err := json.Marshal(s.outbox)
	if err != nil {
		return
	}
	// ponytail: direct write, tolerate torn writes — worst case a dup re-fire
	_ = writeFileAtomic(filepath.Join(s.dir, outboxPath), b)
}

func deliver(j webhookJob) bool {
	req, err := http.NewRequest(http.MethodPost, j.URL, bytes.NewBufferString(j.Body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TO-Signature", hmacHex(j.Secret, []byte(j.Body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func hmacHex(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}
