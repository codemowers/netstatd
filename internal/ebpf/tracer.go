package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"netstatd/internal/types"
)

// Tracer manages eBPF programs and ring buffer
type Tracer struct {
	objs       *tracerObjects
	ringbuf    *ringbuf.Reader
	events     chan types.ConnEvent
	links      []link.Link
	disableTCP bool
	disableUDP bool
}

func NewTracer(disableTCP, disableUDP bool) (*Tracer, error) {
	// Validate that at least one protocol is enabled
	if disableTCP && disableUDP {
		return nil, fmt.Errorf("cannot disable both TCP and UDP monitoring")
	}

	slog.Info("Initializing eBPF tracer", "disableTCP", disableTCP, "disableUDP", disableUDP)
	slog.Debug("Loading eBPF objects")

	spec, err := loadTracer()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF spec: %w", err)
	}

	var objs tracerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	var links []link.Link

	// Attach TCP tracepoint if TCP is enabled
	if !disableTCP {
		slog.Debug("Attaching TCP tracepoint")
		tp, err := link.AttachTracing(link.TracingOptions{
			Program: objs.TraceInetSockSetState,
		})
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("attaching TCP tracepoint: %w", err)
		}
		links = append(links, tp)
		slog.Info("TCP monitoring enabled")
	} else {
		slog.Info("TCP monitoring disabled")
	}

	// Attach UDP kprobes if UDP is enabled
	if !disableUDP {
		slog.Debug("Attaching UDP kprobes")
		kprobeSend, err := link.Kprobe("udp_sendmsg", objs.TraceUdpSendmsg, nil)
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
		}
		links = append(links, kprobeSend)

		kprobeRecv, err := link.Kprobe("udp_recvmsg", objs.TraceUdpRecvmsg, nil)
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attaching udp_recvmsg kprobe: %w", err)
		}
		links = append(links, kprobeRecv)
		slog.Info("UDP monitoring enabled")
	} else {
		slog.Info("UDP monitoring disabled")
	}

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	t := &Tracer{
		objs:       &objs,
		ringbuf:    rb,
		events:     make(chan types.ConnEvent, 100),
		links:      links,
		disableTCP: disableTCP,
		disableUDP: disableUDP,
	}

	go t.readEvents()

	slog.Info("eBPF tracer started successfully")
	return t, nil
}

// readEvents reads from ring buffer and converts to ConnEvent
func (t *Tracer) readEvents() {
	for {
		record, err := t.ringbuf.Read()
		if err != nil {
			slog.Error("Error reading ring buffer")
			return
		}

		// Parse the raw event
		event, err := parseConnEvent(record.RawSample)
		if err != nil {
			slog.Error("Fatal error parsing event - invalid data from eBPF",
				"error", err,
				"raw_bytes", fmt.Sprintf("%x", record.RawSample),
			)
			// Exit the program on invalid eBPF data
			panic(fmt.Sprintf("Invalid eBPF event data: %v", err))
		}

		// Log at TRACE level with full eBPF event details
		slog.Log(nil, slog.Level(-8), "eBPF event received",
			"pid", event.PID,
			"tgid", event.TGID,
			"family", familyToString(event.Family),
			"sport", event.Sport,
			"dport", event.Dport,
			"state", stateToString(event.State, event.Protocol),
			"protocol", event.Protocol,
			"sockCookie", fmt.Sprintf("0x%x", event.SockCookie),
		)

		// Send to channel
		select {
		case t.events <- *event:
		default:
			slog.Warn("Events channel full, dropping event")
		}
	}
}

// parseConnEvent parses raw bytes from eBPF to ConnEvent
func parseConnEvent(data []byte) (*types.ConnEvent, error) {
	// The struct in C is:
	// struct conn_event {
	//     __u32 pid;
	//     __u32 tgid;
	//     __u16 family;
	//     __u16 sport;
	//     __u16 dport;
	//     __u16 _pad1;      // padding to align state to 4 bytes
	//     __u32 state;
	//     __u8 protocol;
	//     __u8 _pad2[3];    // padding to align sock_cookie to 8 bytes (next field after union)
	//     __u64 sock_cookie;
	//     union {
	//         struct {
	//             __u32 saddr;
	//             __u32 daddr;
	//         } ipv4;
	//         struct {
	//             __u8 saddr[16];
	//             __u8 daddr[16];
	//         } ipv6;
	//     };
	// };
	// Actual layout: 4 + 4 + 2 + 2 + 2 + 2 + 4 + 1 + 3 + 8 + 32 = 64 bytes
	// But the sock_cookie comes AFTER the union in memory due to struct packing

	if len(data) < 64 {
		return nil, fmt.Errorf("data too short: %d bytes, need at least 64", len(data))
	}

	var event types.ConnEvent
	buf := bytes.NewReader(data)

	// Track offset for debugging
	startLen := len(data)

	// Read PID (4 bytes) - offset 0
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, fmt.Errorf("reading PID at offset 0: %w (data len: %d)", err, startLen)
	}

	// Read TGID (4 bytes) - offset 4
	if err := binary.Read(buf, binary.LittleEndian, &event.TGID); err != nil {
		return nil, fmt.Errorf("reading TGID at offset 4: %w (data len: %d)", err, startLen)
	}

	// Read family (2 bytes) - offset 8
	if err := binary.Read(buf, binary.LittleEndian, &event.Family); err != nil {
		return nil, fmt.Errorf("reading family at offset 8: %w (data len: %d)", err, startLen)
	}

	// Validate family is non-zero
	if event.Family == 0 {
		return nil, fmt.Errorf("invalid family: got 0, expected non-zero (AF_INET=2 or AF_INET6=10). Data len: %d", startLen)
	}

	// Read sport (2 bytes) - offset 10
	if err := binary.Read(buf, binary.LittleEndian, &event.Sport); err != nil {
		return nil, fmt.Errorf("reading sport at offset 10: %w (data len: %d)", err, startLen)
	}

	// Read dport (2 bytes) - offset 12
	if err := binary.Read(buf, binary.LittleEndian, &event.Dport); err != nil {
		return nil, fmt.Errorf("reading dport at offset 12: %w (data len: %d)", err, startLen)
	}

	// Note: We'll validate dport after reading protocol and state
	// because TCP CLOSE events can have sport=0 and dport=0

	// Skip 2 bytes of padding - offset 14
	var padding1 [2]uint8
	if err := binary.Read(buf, binary.LittleEndian, &padding1); err != nil {
		return nil, fmt.Errorf("reading padding1 at offset 14: %w (data len: %d)", err, startLen)
	}

	// Read state (4 bytes) - offset 16
	if err := binary.Read(buf, binary.LittleEndian, &event.State); err != nil {
		return nil, fmt.Errorf("reading state at offset 16: %w (data len: %d)", err, startLen)
	}

	// Validate sport: can only be 0 if state is CLOSE (7) for TCP
	if event.Sport == 0 {
		// For TCP (protocol 6), sport can only be 0 if state is CLOSE (7)
		// For UDP (protocol 17), we'll read protocol first before validating
		// So we'll validate this after reading protocol
	}

	// Read protocol (1 byte) - offset 20
	if err := binary.Read(buf, binary.LittleEndian, &event.Protocol); err != nil {
		return nil, fmt.Errorf("reading protocol at offset 20: %w (data len: %d)", err, startLen)
	}

	// Validate protocol is non-zero
	if event.Protocol == 0 {
		return nil, fmt.Errorf("invalid protocol: got 0, expected non-zero (TCP=6, UDP=17, etc). Data len: %d", startLen)
	}

	// Validate sport based on protocol and state
	if event.Sport == 0 {
		// For TCP, sport can only be 0 if state is CLOSE (7)
		if event.Protocol == 6 && event.State != 7 {
			return nil, fmt.Errorf("invalid sport: got 0 for TCP with state %d (expected sport > 0 unless state is CLOSE/7). Parsed values: PID=%d, TGID=%d, Family=%d, Sport=%d, Dport=%d, State=%d, Protocol=%d, Data len: %d",
				event.State, event.PID, event.TGID, event.Family, event.Sport, event.Dport, event.State, event.Protocol, startLen)
		}
		// For UDP, sport can be 0 in some edge cases
		// UDP is connectionless, so we'll allow it
	}

	// Note: PID can be 0 for TCP connections processed in softirq/kernel context
	// This is normal for incoming connections or kernel-initiated state changes
	// We rely on socket cookie for tracking TCP connections when PID is unavailable

	// Skip 3 bytes of padding after protocol - offset 21
	var padding2 [3]uint8
	if err := binary.Read(buf, binary.LittleEndian, &padding2); err != nil {
		return nil, fmt.Errorf("reading padding2 at offset 21: %w (data len: %d)", err, startLen)
	}

	// Read socket cookie (8 bytes) - offset 24
	if err := binary.Read(buf, binary.LittleEndian, &event.SockCookie); err != nil {
		return nil, fmt.Errorf("reading sock_cookie at offset 24: %w (data len: %d)", err, startLen)
	}

	// Validate dport is non-zero, except for:
	// 1. TCP CLOSE events where both sport and dport can be 0 (protocol=6, state=7)
	// 2. UDP events where dport can be 0 (protocol=17)
	if event.Dport == 0 {
		// For TCP CLOSE events (protocol=6, state=7), sport and dport can both be 0
		// For UDP (protocol=17), dport can be 0
		if !(event.Protocol == 6 && event.State == 7) && !(event.Protocol == 17) {
			// Try to get IP addresses for better debugging
			var srcIP, dstIP string
			// Save current position to read IPs
			currentPos := len(data) - buf.Len()
			if event.Family == 2 && currentPos+8 <= len(data) {
				// IPv4 addresses are 4 bytes each, starting at current position
				srcIP = fmt.Sprintf("%d.%d.%d.%d",
					data[currentPos],
					data[currentPos+1],
					data[currentPos+2],
					data[currentPos+3])
				dstIP = fmt.Sprintf("%d.%d.%d.%d",
					data[currentPos+4],
					data[currentPos+5],
					data[currentPos+6],
					data[currentPos+7])
			} else if event.Family == 10 && currentPos+32 <= len(data) {
				// IPv6 addresses are 16 bytes each
				srcIP = net.IP(data[currentPos : currentPos+16]).String()
				dstIP = net.IP(data[currentPos+16 : currentPos+32]).String()
			}
			return nil, fmt.Errorf("invalid dport: got 0, expected non-zero. Parsed values: PID=%d, TGID=%d, Family=%d, Sport=%d, Dport=%d, State=%d, Protocol=%d, SockCookie=0x%x, SrcIP=%s, DstIP=%s, Data len: %d",
				event.PID, event.TGID, event.Family, event.Sport, event.Dport, event.State, event.Protocol, event.SockCookie, srcIP, dstIP, startLen)
		}
	}

	// Now read addresses based on family - offset 32
	if event.Family == 2 { // AF_INET
		// Read IPv4 addresses (4 bytes each)
		if err := binary.Read(buf, binary.LittleEndian, &event.SaddrV4); err != nil {
			return nil, fmt.Errorf("reading saddr_v4 at offset 32: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
		}
		if err := binary.Read(buf, binary.LittleEndian, &event.DaddrV4); err != nil {
			return nil, fmt.Errorf("reading daddr_v4 at offset 36: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
		}
		// Clear IPv6 fields
		event.SaddrV6 = [16]uint8{}
		event.DaddrV6 = [16]uint8{}
	} else if event.Family == 10 { // AF_INET6
		// Read IPv6 addresses (16 bytes each)
		if err := binary.Read(buf, binary.LittleEndian, &event.SaddrV6); err != nil {
			return nil, fmt.Errorf("reading saddr_v6 at offset 32: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
		}
		if err := binary.Read(buf, binary.LittleEndian, &event.DaddrV6); err != nil {
			return nil, fmt.Errorf("reading daddr_v6 at offset 48: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
		}
		// Clear IPv4 fields
		event.SaddrV4 = 0
		event.DaddrV4 = 0
	} else {
		return nil, fmt.Errorf("unsupported address family: %d (data len: %d)", event.Family, startLen)
	}

	return &event, nil
}

// Events returns a channel for receiving connection events
func (t *Tracer) Events() <-chan types.ConnEvent {
	return t.events
}

// Close cleans up eBPF resources
func (t *Tracer) Close() error {
	// Close ring buffer first
	if t.ringbuf != nil {
		t.ringbuf.Close()
	}

	// Close all links
	for _, l := range t.links {
		l.Close()
	}

	// Close eBPF objects
	if t.objs != nil {
		t.objs.Close()
	}

	// Close events channel
	close(t.events)

	slog.Info("eBPF tracer closed")
	return nil
}

// Helper functions
func intToIP(ip uint32) string {
	// IP addresses in the kernel are stored in network byte order (big-endian)
	// but we read them as little-endian uint32, so we need to reverse the bytes
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}

func stateToString(state uint32, protocol uint8) string {
	if protocol == types.ProtocolUDP {
		return "ESTABLISHED"
	}

	// TCP states
	if name, ok := types.TCPStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("%d", state)
}

func familyToString(family uint16) string {
	if name, ok := types.FamilyNames[family]; ok {
		return name
	}
	return fmt.Sprintf("%d", family)
}
