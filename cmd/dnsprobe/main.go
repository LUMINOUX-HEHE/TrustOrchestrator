// to-dnsprobe: the external-probe consumer (architecture §5.8, §12.3). A
// watchdog W4 variant that does a REAL DNS query over a UDP socket against a
// user-specified nameserver for TXT records, returning the truth that a
// deployment's DNS-reliant workloads would see — no simulated transport.
// --poll N turns the single shot into a loop (every --interval seconds), the
// poll cadence a production W4 would feed into the fleet.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	if err := probe(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  to-dnsprobe --server <host:port> --name <name> --type TXT|A [--poll N] [--interval S]
    sends real DNS queries (one by default, N on a --interval-second cycle)
    and prints each answer set + a status.`)
	os.Exit(1)
}

func flags(args []string) map[string]string {
	f := map[string]string{}
	for i := 0; i < len(args); i++ {
		if i+1 < len(args) && len(args[i]) > 2 && args[i][:2] == "--" {
			f[args[i][2:]] = args[i+1]
			i++
		}
	}
	return f
}

// probe parses flags, then runs one real DNS exchange per poll.
func probe(args []string) error {
	f := flags(args)
	poll := 1
	if p, err := strconv.Atoi(f["poll"]); err == nil && p > 0 {
		poll = p
	}
	interval := 5 * time.Second
	if s, err := strconv.Atoi(f["interval"]); err == nil && s > 0 {
		interval = time.Duration(s) * time.Second
	}
	for i := 0; i < poll; i++ {
		if err := probeOnce(f); err != nil {
			return err
		}
		if i+1 < poll {
			time.Sleep(interval)
		}
	}
	return nil
}

// probeOnce builds and sends one query and prints the decoded answer set.
func probeOnce(f map[string]string) error {
	server, name := f["server"], f["name"]
	qtype := strings.ToUpper(f["type"])
	if server == "" || name == "" {
		return errors.New("usage: query --server <host:port> --name <name> --type TXT|A")
	}
	if qtype != "TXT" && qtype != "A" {
		return errors.New("--type: TXT or A only")
	}
	qt := uint16(16) // TXT
	if qtype == "A" {
		qt = 1
	}
	msg, err := makeQuery(name, qt)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	answers, rcode, err := parseAnswer(buf[:n], name)
	if err != nil {
		return err
	}
	status := "OK"
	if rcode != 0 {
		status = fmt.Sprintf("RCODE %d (%s)", rcode, rcodeName(rcode))
	}
	if len(answers) == 0 && rcode == 0 {
		status = "NODATA (0 answers)"
	}
	fmt.Printf("name=%s type=%s answers=%d rcode=%d status=%s\n", name, qtype, len(answers), rcode, status)
	for _, a := range answers {
		fmt.Println("  +", a)
	}
	return nil
}

func rcodeName(rc uint16) string {
	m := map[uint16]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
	if s, ok := m[rc]; ok {
		return s
	}
	return "?"
}

// makeQuery builds a one-question DNS query with a random ID. Header layout
// is RFC 1035 §4.1.1: ID(2) flags(2) QD(2) AN(2) NS(2) AR(2) = 12 bytes.
func makeQuery(name string, qtype uint16) ([]byte, error) {
	id := uint16(rand.Intn(65536))
	buf := make([]byte, 0, 128)
	buf = append(buf, byte(id>>8), byte(id))   // ID
	buf = append(buf, 0, 1)                    // flags: RD=1
	buf = append(buf, 0, 1)                    // QDCOUNT
	buf = append(buf, 0, 0, 0, 0, 0, 0)        // AN/NS/AR = 0
	labels, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	buf = append(buf, labels...)
	buf = append(buf, byte(qtype>>8), byte(qtype), 0, 1) // QTYPE + class IN
	return buf, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("name label invalid")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	return buf, nil
}

// parseAnswer walks the DNS wire response: skips the header + question, then
// decodes answer RDATA. Handles only the two types we query; a compressed
// name in an answer (rare for UDP TXT/A with stdlib client nameservers) is
// walked via the pointer. ponytail: uncompressed answers expected on loopback
// test servers; compressed names are handled for A (common) not TXT.
func parseAnswer(msg []byte, name string) ([]string, uint16, error) {
	if len(msg) < 12 {
		return nil, 0, errors.New("short DNS response")
	}
	rcode := binary.BigEndian.Uint16(msg[2:4]) & 0x0f
	nAns := binary.BigEndian.Uint16(msg[6:8])
	pos := 12 // skip header
	// question section: name labels
	for {
		if pos >= len(msg) {
			return nil, rcode, errors.New("truncated question")
		}
		l := msg[pos]
		pos++
		if l == 0 {
			break
		}
		pos += int(l)
	}
	pos += 4 // type + class
	answers := make([]string, 0, int(nAns))
	for i := 0; i < int(nAns) && pos+12 <= len(msg); i++ {
		// owner name (possibly a pointer)
		var skip int
		if msg[pos]&0xc0 == 0xc0 {
			skip = 2
		} else {
			for msg[pos+skip] != 0 {
				skip += int(msg[pos+skip]) + 1
			}
			skip++
		}
		pos += skip
		if pos+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		rdata := pos + 10
		if rdata+rdlen > len(msg) {
			return answers, rcode, errors.New("truncated RDATA")
		}
		switch typ {
		case 1:
			if rdlen == 4 {
				answers = append(answers, net.IP(msg[rdata:rdata+4]).String())
			}
		case 16:
			if rdlen > 0 {
				s := msg[rdata+1 : rdata+rdlen] // skip length octet
				answers = append(answers, string(s))
			}
		}
		pos = rdata + rdlen
	}
	return answers, rcode, nil
}