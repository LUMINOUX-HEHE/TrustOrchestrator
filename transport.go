package trustorchestrator

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
)

// Wire: the fleet transport (FR2.2 loopback → real sockets). Each watchdog
// dials the orchestrator and streams (score, p, evidence) frames as
// length-prefixed JSON over mutual TLS.
// Monitors/fan-in: FleetServer (fleet.go) serves all peers concurrently —
// the historical "sequential Accept" limit is lifted there.
type WireMsg struct {
	NodeID   string   `json:"node_id"`
	Score    float64  `json:"score"`
	PValue   float64  `json:"p_value"`
	Kind     string   `json:"kind"`
	BadIdx   int      `json:"bad_idx,omitempty"`
	Evidence []byte   `json:"evidence,omitempty"`
}

// DialWire opens an mTLS client connection to an orchestrator gateway.
func DialWire(addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.Dial("tcp", addr, cfg)
}

// WriteWire encodes msg as one length-prefixed JSON frame.
func WriteWire(conn net.Conn, msg WireMsg) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// ServeWire reads frames from one accepted mTLS peer into handler.
func ServeWire(conn net.Conn, handler func(WireMsg) error) error {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > 1<<20 {
			return errors.New("wire: frame too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		var m WireMsg
		if err := json.Unmarshal(buf, &m); err != nil {
			return err
		}
		if err := handler(m); err != nil {
			return err
		}
	}
}

// WireMsgFromScore converts a watchdog Score into a wire frame.
func WireMsgFromScore(s Score, kind string) WireMsg {
	msg := WireMsg{NodeID: s.NodeID, Score: s.Score, PValue: s.PValue,
		Kind: kind, Evidence: s.Evidence}
	if len(s.Evidence) > 0 {
		var ev struct {
			BadIndex int `json:"bad_index"`
		}
		if json.Unmarshal(s.Evidence, &ev) == nil {
			msg.BadIdx = ev.BadIndex
		}
	}
	return msg
}