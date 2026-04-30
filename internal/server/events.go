package server

import (
	"time"
)

// Event represents a WebSocket event
type Event interface {
	Type() string
}

// ConnectionEvent represents a connection.event. It intentionally does not
// carry PID; PID-bearing accepted TCP connections use ConnectionAcceptedEvent.
type ConnectionEvent struct {
	EventType  string `json:"type"`
	Timestamp  string `json:"timestamp"`
	NodeName   string `json:"nodeName,omitempty"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	SockCookie uint64 `json:"sockCookie"`
	LocalIP    string `json:"localIP"`
	RemoteIP   string `json:"remoteIP"`
	LocalPort  uint16 `json:"localPort,omitempty"`
	RemotePort uint16 `json:"remotePort,omitempty"`
}

func (e ConnectionEvent) Type() string {
	return e.EventType
}

// ConnectionAcceptedEvent represents a connection.accepted event.
type ConnectionAcceptedEvent struct {
	ConnectionEvent
	PID uint32 `json:"pid"`
}

func (e ConnectionAcceptedEvent) Type() string {
	return e.EventType
}

// ContainerMetainfoEvent represents a container.metainfo event.
// It carries container-scoped metadata plus flattened Kubernetes pod fields.
type ContainerMetainfoEvent struct {
	EventType     string            `json:"type"`
	Timestamp     string            `json:"timestamp"`
	NodeName      string            `json:"nodeName,omitempty"`
	ContainerUID  string            `json:"containerUid"`
	PodName       string            `json:"podName,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	PodUID        string            `json:"podUid,omitempty"`
	ContainerName string            `json:"containerName,omitempty"`
	Image         string            `json:"image,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

func (e ContainerMetainfoEvent) Type() string {
	return e.EventType
}

// ProcessMetainfoEvent represents a process.metainfo event
type ProcessMetainfoEvent struct {
	EventType    string `json:"type"`
	Timestamp    string `json:"timestamp"`
	NodeName     string `json:"nodeName"`
	PID          uint32 `json:"pid"`
	Exe          string `json:"exe,omitempty"`
	NetNS        uint64 `json:"netns"`
	IsHostNetNS  bool   `json:"isHostNetNS"`
	CgroupSlice  string `json:"cgroupSlice"`
	ContainerUID string `json:"containerUid,omitempty"`
}

func (e ProcessMetainfoEvent) Type() string {
	return e.EventType
}

// HostInfoEvent represents a host.info event
type HostInfoEvent struct {
	EventType string   `json:"type"`
	Timestamp string   `json:"timestamp"`
	NodeName  string   `json:"nodeName,omitempty"`
	HostIPs   []string `json:"hostIPs"`
	HostNetNS uint64   `json:"hostNetNS"`
	ImageHash string   `json:"imageHash,omitempty"`
}

func (e HostInfoEvent) Type() string {
	return e.EventType
}

// ContainerAddedEvent represents a container.added event
type ContainerAddedEvent struct {
	EventType     string            `json:"type"`
	Timestamp     string            `json:"timestamp"`
	NodeName      string            `json:"nodeName,omitempty"`
	ContainerUID  string            `json:"containerUid"`
	Name          string            `json:"name"`
	PodName       string            `json:"podName,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	PodUID        string            `json:"podUid,omitempty"`
	ContainerName string            `json:"containerName,omitempty"`
	Image         string            `json:"image,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

func (e ContainerAddedEvent) Type() string {
	return e.EventType
}

// PortListeningEvent represents a port.listening event
type PortListeningEvent struct {
	EventType   string `json:"type"`
	Timestamp   string `json:"timestamp"`
	NodeName    string `json:"nodeName,omitempty"`
	Protocol    string `json:"protocol"`
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
	NetNS       uint64 `json:"netns"`
	IsHostNetNS bool   `json:"isHostNetNS"`
}

func (e PortListeningEvent) Type() string {
	return e.EventType
}

// Helper function to create timestamp
func timestamp() string {
	return time.Now().Format(time.RFC3339)
}
