package trustorchestrator

// Consumer is a state observer (FR5.3, architecture §5.5): it holds a view
// of the trust state and applies deltas. Rollback therefore propagates as an
// incremental change — never a restart. Restarts are tracked so tests can
// assert they never happen.
type Consumer struct {
	State    *State
	Restarts int
}

func NewConsumer(s *State) *Consumer { return &Consumer{State: s} }

// Delta is the incremental state change a consumer applies (FR5.3).
type Delta struct {
	Revoked []string
	Issued  []string
}

// Diff computes the delta from the consumer's current view to the new
// state: certs that disappeared or became revoked vs certs newly valid.
func (c *Consumer) Diff(post *State) *Delta {
	d := &Delta{}
	for id, cert := range c.State.Certs {
		pc, ok := post.Certs[id]
		if !ok || cert.Revoked != pc.Revoked {
			d.Revoked = append(d.Revoked, id)
		}
	}
	for id, pc := range post.Certs {
		if c.State.Certs[id].Identity != pc.Identity {
			d.Issued = append(d.Issued, id)
		}
	}
	return d
}

// ApplyDelta brings the consumer view to the new state. A consumer that
// applies the delta of a rollback never restarts — it just swaps its view.
func (c *Consumer) ApplyDelta(d *Delta, post *State) {
	if c.State == nil || post == nil {
		return
	}
	c.State = post
}

// ApplyDiff is the one-call form used by consumers that poll the anchor.
func (c *Consumer) ApplyDiff(post *State) {
	c.ApplyDelta(c.Diff(post), post)
}
