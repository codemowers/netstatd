package types

import "net"

// ConnEvent represents a raw event from eBPF
// Fields are ordered to match eBPF struct (minimal padding)
// IPv4 addresses are encoded as IPv4-mapped IPv6 (::ffff:0:0/96)
type ConnEvent struct {
	SockCookie uint64    `json:"sockCookie"` // Socket cookie for connection tracking
	State      uint32    `json:"state"`      // Current TCP state
	PID        uint32    `json:"pid"`        // Process ID from bpf_get_current_pid_tgid()
	Family     uint16    `json:"family"`     // AF_INET=2, AF_INET6=10
	Sport      uint16    `json:"sport"`
	Dport      uint16    `json:"dport"`
	Protocol   uint8     `json:"protocol"` // 6=TCP, 17=UDP
	EventType  uint8     `json:"eventType"`
	SaddrV6    [16]uint8 `json:"saddrV6"` // Source address (IPv6 or IPv4-mapped IPv6)
	DaddrV6    [16]uint8 `json:"daddrV6"` // Destination address (IPv6 or IPv4-mapped IPv6)
}

type ByteEvent struct {
	ByteCount     uint64    `json:"byteCount"`
	PID           uint32    `json:"pid"`
	Family        uint16    `json:"family"`
	Sport         uint16    `json:"sport"`
	Dport         uint16    `json:"dport"`
	Protocol      uint8     `json:"protocol"`
	ByteDirection uint8     `json:"byteDirection"`
	SaddrV6       [16]uint8 `json:"saddrV6"`
	DaddrV6       [16]uint8 `json:"daddrV6"`
}

func ByteDirectionToString(direction uint8) string {
	switch direction {
	case ByteDirectionOut:
		return "out"
	case ByteDirectionIn:
		return "in"
	default:
		return ""
	}
}

func (be *ByteEvent) ByteDirectionString() string {
	return ByteDirectionToString(be.ByteDirection)
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

// LocalRemoteIPs returns the decoded local and remote IP addresses.
func (ce *ConnEvent) LocalRemoteIPs() (string, string) {
	return localRemoteIPs(ce.Family, ce.SaddrV6, ce.DaddrV6)
}

func (be *ByteEvent) LocalRemoteIPs() (string, string) {
	return localRemoteIPs(be.Family, be.SaddrV6, be.DaddrV6)
}

func localRemoteIPs(family uint16, saddrV6 [16]uint8, daddrV6 [16]uint8) (string, string) {
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
	if family == 2 { // IPv4
		if isAllZero(saddrV6[12:16]) {
			if isAllZero(daddrV6[12:16]) {
				return "", ""
			}
			return "", net.IPv4(daddrV6[12], daddrV6[13], daddrV6[14], daddrV6[15]).String()
		}
		if isAllZero(daddrV6[12:16]) {
			return net.IPv4(saddrV6[12], saddrV6[13], saddrV6[14], saddrV6[15]).String(), ""
		}
		return net.IPv4(saddrV6[12], saddrV6[13], saddrV6[14], saddrV6[15]).String(),
			net.IPv4(daddrV6[12], daddrV6[13], daddrV6[14], daddrV6[15]).String()
	}
	if family == 10 { // IPv6
		if isAllZero(saddrV6[:]) {
			if isAllZero(daddrV6[:]) {
				return "", ""
			}
			return "", net.IP(daddrV6[:]).String()
		}
		if isAllZero(daddrV6[:]) {
			return net.IP(saddrV6[:]).String(), ""
		}
		localIP := make(net.IP, 16)
		remoteIP := make(net.IP, 16)
		copy(localIP, saddrV6[:])
		copy(remoteIP, daddrV6[:])
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

// ImageMetainfo contains OCI image configuration metadata extracted from
// containerd content. It may include sensitive environment variables, so it is
// only emitted when explicitly enabled by the server.
type ImageMetainfo struct {
	Image                     string            `json:"image"`
	TargetDigest              string            `json:"targetDigest,omitempty"`
	TargetMediaType           string            `json:"targetMediaType,omitempty"`
	PlatformManifestDigest    string            `json:"platformManifestDigest,omitempty"`
	PlatformManifestMediaType string            `json:"platformManifestMediaType,omitempty"`
	ImageConfigDigest         string            `json:"imageConfigDigest,omitempty"`
	ImageConfigSize           int64             `json:"imageConfigSize,omitempty"`
	Size                      int64             `json:"size,omitempty"`
	Created                   string            `json:"created,omitempty"`
	Author                    string            `json:"author,omitempty"`
	Architecture              string            `json:"architecture,omitempty"`
	OS                        string            `json:"os,omitempty"`
	OSVersion                 string            `json:"osVersion,omitempty"`
	Variant                   string            `json:"variant,omitempty"`
	User                      string            `json:"user,omitempty"`
	Env                       []string          `json:"env,omitempty"`
	Entrypoint                []string          `json:"entrypoint,omitempty"`
	Cmd                       []string          `json:"cmd,omitempty"`
	WorkingDir                string            `json:"workingDir,omitempty"`
	ExposedPorts              []string          `json:"exposedPorts,omitempty"`
	Volumes                   []string          `json:"volumes,omitempty"`
	Labels                    map[string]string `json:"labels,omitempty"`
	StopSignal                string            `json:"stopSignal,omitempty"`
	RootFSType                string            `json:"rootfsType,omitempty"`
	RootFSDiffIDs             []string          `json:"rootfsDiffIds,omitempty"`
	History                   []ImageHistory    `json:"history,omitempty"`
}

type ImageHistory struct {
	Created    string `json:"created,omitempty"`
	CreatedBy  string `json:"createdBy,omitempty"`
	Author     string `json:"author,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"emptyLayer,omitempty"`
}
