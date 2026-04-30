package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"netstatd/internal/types"
)

// Config flags bitmap
const (
	ConfigDisableTCP uint32 = 1 << 0 // 0x1
	ConfigDisableUDP uint32 = 1 << 1 // 0x2
)

// Tracer manages eBPF programs and ring buffer
type Tracer struct {
	objs        *tracerObjects
	ringbuf     *ringbuf.Reader
	events      chan types.ConnEvent
	links       []link.Link
	configFlags uint32
}

func NewTracer(configFlags uint32) (*Tracer, error) {
	disableTCP := (configFlags & ConfigDisableTCP) != 0
	disableUDP := (configFlags & ConfigDisableUDP) != 0

	// Validate that at least one protocol is enabled
	if disableTCP && disableUDP {
		return nil, fmt.Errorf("cannot disable both TCP and UDP monitoring")
	}

	slog.Info("Initializing eBPF tracer",
		"configFlags", fmt.Sprintf("0x%x", configFlags),
		"configFlagsBinary", fmt.Sprintf("0b%08b", configFlags),
		"disableTCP", disableTCP,
		"disableUDP", disableUDP)
	slog.Debug("Loading eBPF objects")

	spec, err := loadTracer()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF spec: %w", err)
	}

	var objs tracerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Set config flags in eBPF map
	key := uint32(0)
	if err := objs.Config.Put(&key, &configFlags); err != nil {
		objs.Close()
		return nil, fmt.Errorf("setting config flags: %w", err)
	}
	slog.Debug("eBPF config flags set", "flags", configFlags)

	var links []link.Link

	// Attach TCP BTF tracepoint if TCP is enabled
	if !disableTCP {
		slog.Debug("Attaching TCP BTF tracepoint")
		tp, err := link.AttachTracing(link.TracingOptions{
			Program:    objs.TraceInetSockSetState,
			AttachType: cebpf.AttachTraceRawTp,
		})
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("attaching TCP BTF tracepoint: %w", err)
		}
		links = append(links, tp)

		listenTP, err := link.Tracepoint("syscalls", "sys_exit_listen", objs.TraceSysExitListen, nil)
		if err != nil {
			slog.Warn("listen syscall tracepoint unavailable; listening ports will rely on initial and metadata-triggered scans", "error", err)
		} else {
			links = append(links, listenTP)
		}

		acceptRet, err := link.Kretprobe("inet_csk_accept", objs.TraceInetCskAcceptRet, nil)
		if err != nil {
			slog.Warn("inet_csk_accept kretprobe unavailable; accepted inbound TCP PID metadata will be missing", "error", err)
		} else {
			links = append(links, acceptRet)
		}
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
		objs:        &objs,
		ringbuf:     rb,
		events:      make(chan types.ConnEvent, 100),
		links:       links,
		configFlags: configFlags,
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
			//panic(fmt.Sprintf("Invalid eBPF event data: %v", err))
			continue
		}

		// Note: Loopback filtering is now done in eBPF kernel space
		// No need to filter here in userspace

		// Log at TRACE level with full eBPF event details
		slog.Log(nil, slog.Level(-8), "eBPF event received",
			"pid", event.PID,
			"eventType", event.EventType,
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
	// The struct in C is (reordered for minimal padding):
	// struct conn_event {
	//     __u64 sock_cookie;  // 8 bytes, offset 0
	//     __u32 pid;          // 4 bytes, offset 8
	//     __u32 _pad;         // 4 bytes, offset 12
	//     __u32 state;        // 4 bytes, offset 16
	//     __u16 family;       // 2 bytes, offset 20
	//     __u16 sport;        // 2 bytes, offset 22
	//     __u16 dport;        // 2 bytes, offset 24
	//     __u8 protocol;      // 1 byte,  offset 26
	//     __u8 event_type;    // 1 byte,  offset 27
	//     __u8 saddr[16];     // 16 bytes, offset 28
	//     __u8 daddr[16];     // 16 bytes, offset 44
	// };
	// Total size: 8 + 4 + 4 + 4 + 2 + 2 + 2 + 1 + 1 + 16 + 16 = 60 bytes

	if len(data) < 60 {
		return nil, fmt.Errorf("data too short: %d bytes, need at least 60", len(data))
	}

	var event types.ConnEvent
	buf := bytes.NewReader(data)

	// Track offset for debugging
	startLen := len(data)

	// Read socket cookie (8 bytes) - offset 0
	if err := binary.Read(buf, binary.LittleEndian, &event.SockCookie); err != nil {
		return nil, fmt.Errorf("reading sock_cookie at offset 0: %w (data len: %d)", err, startLen)
	}

	// Read PID (4 bytes) - offset 8
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, fmt.Errorf("reading PID at offset 8: %w (data len: %d)", err, startLen)
	}

	// Skip explicit padding (4 bytes) - offset 12
	var padding uint32
	if err := binary.Read(buf, binary.LittleEndian, &padding); err != nil {
		return nil, fmt.Errorf("reading padding at offset 12: %w (data len: %d)", err, startLen)
	}

	// Read state (4 bytes) - offset 16
	if err := binary.Read(buf, binary.LittleEndian, &event.State); err != nil {
		return nil, fmt.Errorf("reading state at offset 16: %w (data len: %d)", err, startLen)
	}

	// Read family (2 bytes) - offset 20
	if err := binary.Read(buf, binary.LittleEndian, &event.Family); err != nil {
		return nil, fmt.Errorf("reading family at offset 20: %w (data len: %d)", err, startLen)
	}

	// Validate family is non-zero
	if event.Family == 0 {
		return nil, fmt.Errorf("invalid family: got 0, expected non-zero (AF_INET=2 or AF_INET6=10). Data len: %d", startLen)
	}

	// Read sport (2 bytes) - offset 22
	if err := binary.Read(buf, binary.LittleEndian, &event.Sport); err != nil {
		return nil, fmt.Errorf("reading sport at offset 22: %w (data len: %d)", err, startLen)
	}

	// Read dport (2 bytes) - offset 24
	if err := binary.Read(buf, binary.LittleEndian, &event.Dport); err != nil {
		return nil, fmt.Errorf("reading dport at offset 24: %w (data len: %d)", err, startLen)
	}

	// Read protocol (1 byte) - offset 26
	if err := binary.Read(buf, binary.LittleEndian, &event.Protocol); err != nil {
		return nil, fmt.Errorf("reading protocol at offset 26: %w (data len: %d)", err, startLen)
	}

	// Validate protocol is non-zero
	if event.Protocol == 0 {
		return nil, fmt.Errorf("invalid protocol: got 0, expected non-zero (TCP=6, UDP=17, etc). Data len: %d", startLen)
	}

	// Read raw event type (1 byte) - offset 27
	if err := binary.Read(buf, binary.LittleEndian, &event.EventType); err != nil {
		return nil, fmt.Errorf("reading event_type at offset 27: %w (data len: %d)", err, startLen)
	}

	// Note: sport can be 0 for various TCP states (SYN_SENT, CLOSE, FIN_WAIT2, etc.)
	// This is normal kernel behavior, so we don't validate sport here

	// Note: TCP state events intentionally carry PID 0. PID-bearing accepted
	// inbound connections are emitted separately by inet_csk_accept.

	// Note: dport can be 0 for various TCP states (LISTEN, CLOSE, etc.)
	// This is normal kernel behavior, so we don't validate dport here

	// Read addresses (always 16 bytes each, IPv4-mapped IPv6 format) - offset 28
	if err := binary.Read(buf, binary.LittleEndian, &event.SaddrV6); err != nil {
		return nil, fmt.Errorf("reading saddr_v6 at offset 28: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
	}

	// Read destination address - offset 44
	if err := binary.Read(buf, binary.LittleEndian, &event.DaddrV6); err != nil {
		return nil, fmt.Errorf("reading daddr_v6 at offset 44: %w (data len: %d, remaining: %d)", err, startLen, buf.Len())
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
