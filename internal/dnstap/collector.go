package dnstap

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/golang/protobuf/proto"
)

// DNSCache interface for updating DNS mappings
type DNSCache interface {
	Set(ip, hostname string)
}

// Collector listens for DNSTap data and updates the DNS cache
type Collector struct {
	listener net.Listener
	cache    DNSCache
	addr     string
}

// NewCollector creates a new DNSTap collector
func NewCollector(addr string, cache DNSCache) (*Collector, error) {
	slog.Debug("Initializing DNSTap collector", "addr", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	slog.Debug("DNSTap listener created successfully")

	c := &Collector{
		listener: listener,
		cache:    cache,
		addr:     addr,
	}

	slog.Info("DNSTap collector listening", "addr", addr)
	slog.Debug("DNSTap collector successfully initialized")
	return c, nil
}

// Start starts accepting DNSTap connections
func (c *Collector) Start() {
	slog.Debug("Starting DNSTap collector", "addr", c.addr)
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			slog.Error("DNSTap accept error", "error", err)
			continue
		}

		slog.Debug("DNSTap connection accepted", "remote", conn.RemoteAddr())
		go c.handleConnection(conn)
	}
}

// handleConnection processes a single DNSTap connection
func (c *Collector) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Create framestream decoder
	dec, err := framestream.NewDecoder(conn, &framestream.DecoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: true,
	})
	if err != nil {
		slog.Error("DNSTap framestream decoder error", "error", err)
		return
	}

	// Process frames
	for {
		buf, err := dec.Decode()
		if err != nil {
			if err != io.EOF {
				slog.Error("DNSTap decode error", "error", err)
			}
			return
		}

		// Parse DNSTap message
		var dt dnstap.Dnstap
		if err := proto.Unmarshal(buf, &dt); err != nil {
			slog.Error("DNSTap unmarshal error", "error", err)
			continue
		}

		c.processDNSTap(&dt)
	}
}

// processDNSTap extracts DNS query/response information and updates cache
func (c *Collector) processDNSTap(dt *dnstap.Dnstap) {
	if dt.Message == nil {
		return
	}

	msg := dt.Message

	// We're interested in responses that contain answers
	if msg.GetType() != dnstap.Message_CLIENT_RESPONSE &&
		msg.GetType() != dnstap.Message_RESOLVER_RESPONSE {
		return
	}

	// Get query address (client IP)
	var queryIP string
	if msg.QueryAddress != nil {
		queryIP = net.IP(msg.QueryAddress).String()
	}

	// Parse DNS response message to extract question and answers
	responseMsg := msg.GetResponseMessage()
	if responseMsg == nil || len(responseMsg) == 0 {
		return
	}

	// Parse DNS message (simplified - just extract A/AAAA records)
	answers := parseDNSMessage(responseMsg)

	for hostname, ips := range answers {
		for _, ip := range ips {
			c.cache.Set(ip, hostname)
			slog.Debug("DNSTap resolution",
				"hostname", hostname,
				"ip", ip,
				"queryIP", queryIP,
			)
		}
	}
}

// parseDNSMessage extracts hostname -> IP mappings from DNS response
// This is a simplified parser that extracts A and AAAA records
func parseDNSMessage(data []byte) map[string][]string {
	results := make(map[string][]string)

	if len(data) < 12 {
		return results
	}

	// Skip DNS header (12 bytes)
	offset := 12

	// Read question count
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])

	// Skip questions
	for i := uint16(0); i < qdcount && offset < len(data); i++ {
		// Skip QNAME
		for offset < len(data) {
			length := int(data[offset])
			offset++
			if length == 0 {
				break
			}
			offset += length
		}
		// Skip QTYPE and QCLASS (4 bytes)
		offset += 4
	}

	// Parse answers
	for i := uint16(0); i < ancount && offset < len(data); i++ {
		// Parse NAME (may be compressed)
		hostname, newOffset := parseDNSName(data, offset)
		offset = newOffset

		if offset+10 > len(data) {
			break
		}

		// Read TYPE, CLASS, TTL, RDLENGTH
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		// Skip CLASS (2 bytes)
		offset += 2
		// Skip TTL (4 bytes)
		offset += 4
		rdLength := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if offset+int(rdLength) > len(data) {
			break
		}

		// Extract IP addresses from A (type 1) and AAAA (type 28) records
		if rrType == 1 && rdLength == 4 {
			// A record (IPv4)
			ip := net.IP(data[offset : offset+4]).String()
			results[hostname] = append(results[hostname], ip)
		} else if rrType == 28 && rdLength == 16 {
			// AAAA record (IPv6)
			ip := net.IP(data[offset : offset+16]).String()
			results[hostname] = append(results[hostname], ip)
		}

		offset += int(rdLength)
	}

	return results
}

// parseDNSName parses a DNS name from the message, handling compression
func parseDNSName(data []byte, offset int) (string, int) {
	var name string
	jumped := false
	jumpOffset := 0

	for offset < len(data) {
		length := int(data[offset])

		// Check for compression pointer (top 2 bits set)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			// Compression pointer
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				jumpOffset = offset + 2
				jumped = true
			}
			offset = pointer
			continue
		}

		offset++
		if length == 0 {
			break
		}

		if offset+length > len(data) {
			break
		}

		if name != "" {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}

	if jumped {
		return name, jumpOffset
	}
	return name, offset
}

// Close closes the DNSTap collector
func (c *Collector) Close() error {
	return c.listener.Close()
}
