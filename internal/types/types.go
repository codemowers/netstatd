package types

import "net"

// ConnEvent represents a raw event from eBPF
// Fields are ordered to match eBPF struct (minimal padding)
// IPv4 addresses are encoded as IPv4-mapped IPv6 (::ffff:0:0/96)
type ConnEvent struct {
	SockCookie uint64    `json:"sockCookie"` // Socket cookie for connection tracking
	PID        uint32    `json:"pid"`        // Process ID from bpf_get_current_pid_tgid()
	State      uint32    `json:"state"`      // Current TCP state
	Family     uint16    `json:"family"`     // AF_INET=2, AF_INET6=10
	Sport      uint16    `json:"sport"`
	Dport      uint16    `json:"dport"`
	Protocol   uint8     `json:"protocol"` // 6=TCP, 17=UDP
	EventType  uint8     `json:"eventType"`
	SaddrV6    [16]uint8 `json:"saddrV6"` // Source address (IPv6 or IPv4-mapped IPv6)
	DaddrV6    [16]uint8 `json:"daddrV6"` // Destination address (IPv6 or IPv4-mapped IPv6)
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

// LocalRemoteIPs returns the decoded local and remote IP addresses.
func (ce *ConnEvent) LocalRemoteIPs() (string, string) {
	isAllZero := func(b []uint8) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}

	// Addresses are always in IPv6 format (IPv4 uses IPv4-mapped IPv6).
	// Unspecified addresses are returned as empty strings so callers can
	// count them as missing instead of rendering "[::]" or "0.0.0.0".
	if ce.Family == 2 { // IPv4
		if isAllZero(ce.SaddrV6[12:16]) {
			if isAllZero(ce.DaddrV6[12:16]) {
				return "", ""
			}
			return "", net.IPv4(ce.DaddrV6[12], ce.DaddrV6[13], ce.DaddrV6[14], ce.DaddrV6[15]).String()
		}
		if isAllZero(ce.DaddrV6[12:16]) {
			return net.IPv4(ce.SaddrV6[12], ce.SaddrV6[13], ce.SaddrV6[14], ce.SaddrV6[15]).String(), ""
		}
		return net.IPv4(ce.SaddrV6[12], ce.SaddrV6[13], ce.SaddrV6[14], ce.SaddrV6[15]).String(),
			net.IPv4(ce.DaddrV6[12], ce.DaddrV6[13], ce.DaddrV6[14], ce.DaddrV6[15]).String()
	}
	if ce.Family == 10 { // IPv6
		if isAllZero(ce.SaddrV6[:]) {
			if isAllZero(ce.DaddrV6[:]) {
				return "", ""
			}
			return "", net.IP(ce.DaddrV6[:]).String()
		}
		if isAllZero(ce.DaddrV6[:]) {
			return net.IP(ce.SaddrV6[:]).String(), ""
		}
		localIP := make(net.IP, 16)
		remoteIP := make(net.IP, 16)
		copy(localIP, ce.SaddrV6[:])
		copy(remoteIP, ce.DaddrV6[:])
		return localIP.String(), remoteIP.String()
	}
	return "", ""
}

// ContainerInfo represents a container with its metadata
type ContainerInfo struct {
	ID                  string            `json:"containerUid"`
	Name                string            `json:"name"`
	ContainerdNamespace string            `json:"containerdNamespace,omitempty"` // Containerd namespace
	PodName             string            `json:"podName,omitempty"`
	PodNamespace        string            `json:"podNamespace,omitempty"` // Kubernetes namespace
	PodUID              string            `json:"podUid,omitempty"`
	ContainerName       string            `json:"containerName,omitempty"`
	Image               string            `json:"image,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
}
