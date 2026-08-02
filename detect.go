package trustorchestrator

import "math"

// CUSUM is the W1/W5 change-point detector core (architecture §6.2):
//
//	S = max(0, S + (x - mu0) - delta); alarm when S >= h.
//
// mu0 is the calibrated baseline mean; delta the minimal detectable shift;
// h the decision bound. All three come from TrustOps calibration, never by
// hand (N3).
type CUSUM struct {
	mu0, delta, h, S float64
}

func NewCUSUM(mu0, delta, h float64) *CUSUM { return &CUSUM{mu0: mu0, delta: delta, h: h} }

// Observe feeds one sample; returns true when the alarm bound is crossed.
func (c *CUSUM) Observe(x float64) bool {
	c.S = math.Max(0, c.S+(x-c.mu0)-c.delta)
	return c.S >= c.h
}

// Alarmed reports whether the accumulated drift has crossed the bound.
func (c *CUSUM) Alarmed() bool { return c.S >= c.h }
