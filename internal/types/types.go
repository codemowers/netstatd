package types

import (
	"net"
	"time"
)

// ConnectionEntry represents a single connection tracking entry
type ConnectionEntry struct {
	Protocol   uint8  `json:"protocol"` // Raw protocol number (6=TCP, 17=UDP, etc)
	SourceIP   string `json:"sourceIP"`
	SourcePort uint16 `json:"sourcePort"`
	DestIP     string `json:"destIP"`
	DestPort   uint16 `json:"destPort"`
	State      string `json:"state"`
}

// ConnEvent represents a raw event from eBPF
type ConnEvent struct {
	PID        uint32 `json:"pid"`
	TGID       uint32 `json:"tgid"`   // Thread group ID (task ID)
	Family     uint16 `json:"family"` // AF_INET=2, AF_INET6=10
	Sport      uint16 `json:"sport"`
	Dport      uint16 `json:"dport"`
	State      uint32 `json:"state"`
	Protocol   uint8  `json:"protocol"`   // 6=TCP, 17=UDP
	SockCookie uint64 `json:"sockCookie"` // Socket cookie for connection tracking
	// For IPv4
	SaddrV4 uint32 `json:"saddrV4"`
	DaddrV4 uint32 `json:"daddrV4"`
	// For IPv6
	SaddrV6 [16]uint8 `json:"saddrV6"`
	DaddrV6 [16]uint8 `json:"daddrV6"`
}

// ToConnectionEntry converts a ConnEvent to a ConnectionEntry
func (ce *ConnEvent) ToConnectionEntry() *ConnectionEntry {
	entry := &ConnectionEntry{
		Protocol:   ce.Protocol,
		SourcePort: ce.Sport,
		DestPort:   ce.Dport,
		State:      ce.StateToString(),
	}

	// Set IP addresses based on family
	if ce.Family == 2 { // IPv4
		entry.SourceIP = intToIP(ce.SaddrV4).String()
		entry.DestIP = intToIP(ce.DaddrV4).String()
	} else if ce.Family == 10 { // IPv6
		// For IPv6, create a proper net.IP from the 16-byte array
		// Make a copy to avoid referencing the original array
		srcIP := make(net.IP, 16)
		dstIP := make(net.IP, 16)
		copy(srcIP, ce.SaddrV6[:])
		copy(dstIP, ce.DaddrV6[:])
		entry.SourceIP = srcIP.String()
		entry.DestIP = dstIP.String()
	}

	return entry
}

// StateToString converts state to string representation
func (ce *ConnEvent) StateToString() string {
	if ce.Protocol == ProtocolUDP {
		return "ESTABLISHED"
	}

	// TCP states
	if name, ok := TCPStateNames[ce.State]; ok {
		return name
	}
	// Return empty string for unknown states (will be rendered as "-" in UI)
	return ""
}

// StateToInt returns the numeric state value
func (ce *ConnEvent) StateToInt() uint32 {
	return ce.State
}

// IntToIP converts uint32 to net.IP (exported for use in other packages)
func IntToIP(ip uint32) net.IP {
	// IP addresses in the kernel are stored in network byte order (big-endian)
	// but we read them as little-endian uint32, so we need to reverse the bytes
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}

// Helper function to convert uint32 to net.IP
func intToIP(ip uint32) net.IP {
	return IntToIP(ip)
}

// KubeMetadata contains Kubernetes metadata extracted from containerd labels
type KubeMetadata struct {
	PodName       string            `json:"podName"`
	Namespace     string            `json:"namespace"`
	PodUID        string            `json:"podUID"`
	ContainerName string            `json:"containerName"`
	Labels        map[string]string `json:"labels,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// ContainerInfo represents a container with its metadata
type ContainerInfo struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Namespace       string        `json:"namespace"`                 // Containerd namespace
	PID             uint32        `json:"pid"`                       // Root process PID
	PodIPs          []string      `json:"podIPs,omitempty"`          // All pod IPs (IPv4, IPv6, etc) - empty for host network pods
	UsesHostNetwork bool          `json:"usesHostNetwork,omitempty"` // True if pod uses host networking
	KubeMetadata    *KubeMetadata `json:"kubernetes,omitempty"`
}

// WebSocketEvent is the envelope for all WebSocket messages
type WebSocketEvent struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	NodeName  string      `json:"nodeName,omitempty"`
	Data      interface{} `json:"data"`
}

// ContainerAddedEvent is emitted when a new container starts
type ContainerAddedEvent struct {
	ContainerID  string        `json:"containerId"`
	Name         string        `json:"name"`
	Namespace    string        `json:"namespace"` // Containerd namespace
	PID          uint32        `json:"pid"`
	KubeMetadata *KubeMetadata `json:"kubernetes,omitempty"`
}

// ContainerDeletedEvent is emitted when a container stops
type ContainerDeletedEvent struct {
	ContainerUID string `json:"containerUID"`
}

// ContainerListResponse is the response for GET /api/containers
type ContainerListResponse struct {
	Timestamp  string          `json:"timestamp"`
	Containers []ContainerInfo `json:"containers"`
}

// ListeningPort represents a listening socket
type ListeningPort struct {
	Protocol uint8  `json:"protocol"` // 6 for TCP, 17 for UDP
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	PID      uint32 `json:"pid"`
	Process  string `json:"process,omitempty"`
	NetNS    uint64 `json:"netns,omitempty"` // Network namespace inode number
}

// Event represents an internal event in the system
type Event struct {
	Type      string
	Timestamp time.Time
	Container *ContainerInfo
}
