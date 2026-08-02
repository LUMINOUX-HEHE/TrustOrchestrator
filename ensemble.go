package trustorchestrator

// Score is one watchdog's 30s output over mTLS (architecture §7.1).
type Score struct {
	NodeID   string
	Score    float64
	PValue   float64
	Evidence []byte
}

// Detect applies the fusion rule: DETECTED iff >= quorum watchdogs score
// below the calibrated threshold (FR2.3, P4). With n=5, quorum=3, one
// Byzantine watchdog can neither trigger nor block DETECTED.
func Detect(scores []Score, threshold float64, quorum int) bool {
	n := 0
	for _, s := range scores {
		if s.Score < threshold {
			n++
		}
	}
	return n >= quorum
}
