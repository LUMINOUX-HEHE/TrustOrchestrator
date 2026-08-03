package main

import (
	"net"
	"testing"
)

// fakeServer answers one real UDP DNS query with a minimal TXT reply
// (RFC 1035): echo the question name, one TXT answer "hello". Run in its own
// goroutine; the client probe will block on read until the reply lands.
func fakeServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		req := buf[:n]
		resp := []byte{req[0], req[1], 0x81, 0x80, req[4], req[5], 0, 1, 0, 0, 0, 0}
		qEnd := 12
		for qEnd < len(req) && req[qEnd] != 0 {
			qEnd += int(req[qEnd]) + 1
		}
		if qEnd >= len(req) {
			panic("bad question")
		}
		qEnd += 1 + 4 // root octet + QTYPE + QCLASS
		question := req[12:qEnd]
		// answer: owner = same name again (real servers use a 0xC00C pointer;
		// a full echo is equally valid wire), then TXT record.
		ansName := question[:len(question)-4]
		answer := append([]byte{}, ansName...)
		answer = append(answer, 0, 16, 0, 1, 0, 0, 0, 60, 0, 6) // TXT class IN ttl 60 rlen 6
		answer = append(answer, 5, 'h', 'e', 'l', 'l', 'o')      // "hello"
		pc.WriteTo(append(append([]byte{}, resp...), append(question, answer...)...), peer)
	}()
	return pc.LocalAddr().String()
}

// TestProbeTXT drives the full real socket exchange: probe() builds a DNS
// query, fakeserver answers over UDP, and the decoder must surface the TXT.
// This is the smallest check that dies if encoder, transport, or decoder
// drift — the three pieces that make the consumer "real".
func TestProbeTXT(t *testing.T) {
	addr := fakeServer(t)
	err := probe([]string{"--server", addr, "--name", "example.test", "--type", "TXT"})
	if err != nil {
		t.Fatal(err)
	}
}

// TestParseAnswer checks the wire decoder in isolation against a hand-built
// NXDOMAIN (rcode 3) so the status path is covered offline.
func TestParseNXDOMAIN(t *testing.T) {
	msg, _ := makeQuery("nope.test", 16)
	reply := append([]byte{}, msg...)
	reply[3] = 3 // rcode NXDOMAIN in the low 4 bits of byte 3
	reply[7] = 0 // no answers
	ans, rcode, err := parseAnswer(reply, "nope.test")
	if err != nil {
		t.Fatal(err)
	}
	if rcode != 3 || len(ans) != 0 {
		t.Fatalf("got answers=%v rcode=%d", ans, rcode)
	}
}