package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"netstatd/internal/containerd"
	"netstatd/internal/ebpf"
	"netstatd/internal/types"
)

var hostNetNS string
var hostNetNSInt uint64

const procPath = "/proc"
const clientEventBufferSize = 100000

var buildSourceHash string

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// initialStateMarker is a special event to trigger initial state sending
type initialStateMarker struct{}

func (initialStateMarker) Type() string {
	return "initialStateMarker"
}

type clientWriter struct {
	conn *websocket.Conn
	ch   chan Event
	done chan struct{}

	// State tracking for this client
	// These maps are only accessed from clientWriterLoop goroutine
	scannedNetNS     map[uint64]bool
	broadcastedPorts map[string]bool
	sentProcessPID   map[uint32]bool
	sentContainerUID map[string]bool
}

// JSONEvent is a wrapper for raw JSON that implements Event
type JSONEvent struct {
	Data []byte
}

func (j JSONEvent) Type() string {
	// Extract type from JSON
	var m map[string]interface{}
	if err := json.Unmarshal(j.Data, &m); err != nil {
		return "unknown"
	}
	if typ, ok := m["type"].(string); ok {
		return typ
	}
	return "unknown"
}

type listeningSocket struct {
	IP   string
	Port uint16
}

type Server struct {
	ctrdClient    *containerd.Client
	tracer        *ebpf.Tracer
	httpServer    *http.Server
	nodeName      string
	hostIPs       []string
	imageHash     string
	fanoutService string

	containers map[string]*types.ContainerInfo // keyed by container UID
	mu         sync.RWMutex

	clients   map[*websocket.Conn]*clientWriter
	clientsMu sync.RWMutex

	broadcast chan Event

	eventCounters       map[string]*atomic.Uint64
	wsEventCounters     map[string]*atomic.Uint64 // Tracks WebSocket events by type
	missingAddrCounters map[string]*atomic.Uint64
	resolutionFailures  map[string]*atomic.Uint64
	loopbackCounter     *atomic.Uint64
	acceptMissingPID    *atomic.Uint64
	clientDropCounter   *atomic.Uint64
	metricsMu           sync.RWMutex
}

func NewServer(ctrdClient *containerd.Client, tracer *ebpf.Tracer, fanoutService string) *Server {

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostnameBytes, err := os.ReadFile("/etc/hostname")
		if err == nil {
			nodeName = strings.TrimSpace(string(hostnameBytes))
		} else {
			nodeName = "unknown"
		}
	}

	hostIPs, err := getHostIPs()
	if err != nil {
		slog.Error("Failed to detect host IPs", "error", err)
		hostIPs = []string{}
	} else {
		slog.Info("Detected host IPs", "ips", hostIPs)
	}

	imageHash := computeImageHash()

	// Read host network namespace once at startup
	netns, err := os.Readlink(fmt.Sprintf("%s/1/ns/net", procPath))
	if err != nil {
		slog.Error("Failed to read host network namespace", "error", err)
		os.Exit(1)
	} else {
		hostNetNS = netns
		hostNetNSInt = parseNetNSIdentifier(netns)
		slog.Info("Host network namespace detected", "netns", hostNetNS, "netns_int", hostNetNSInt)
	}

	s := &Server{
		ctrdClient:          ctrdClient,
		tracer:              tracer,
		nodeName:            nodeName,
		hostIPs:             hostIPs,
		imageHash:           imageHash,
		fanoutService:       fanoutService,
		containers:          make(map[string]*types.ContainerInfo),
		clients:             make(map[*websocket.Conn]*clientWriter),
		broadcast:           make(chan Event, 1000),
		eventCounters:       make(map[string]*atomic.Uint64),
		wsEventCounters:     make(map[string]*atomic.Uint64),
		missingAddrCounters: make(map[string]*atomic.Uint64),
		resolutionFailures:  make(map[string]*atomic.Uint64),
		loopbackCounter:     &atomic.Uint64{},
		acceptMissingPID:    &atomic.Uint64{},
		clientDropCounter:   &atomic.Uint64{},
	}

	go s.preloadContainers()
	go s.processEBPFEvents()
	go s.handleBroadcast()

	return s
}

func computeImageHash() string {
	return buildSourceHash
}

func (s *Server) preloadContainers() {
	all, err := s.ctrdClient.ListAllContainers()
	if err != nil {
		slog.Error("Failed to preload containers from containerd", "error", err)
		return
	}

	s.mu.Lock()
	for _, ci := range all {
		// Use container ID as the key
		s.containers[ci.ID] = ci
	}
	s.mu.Unlock()

	slog.Info("Preloaded containers from containerd", "count", len(all))
}

func (s *Server) singlePodHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/conntrack", s.handleWebSocket)
	mux.HandleFunc("/metrics", s.handleMetrics)

	return mux
}

func (s *Server) StartWithListener(listener net.Listener) error {
	s.httpServer = &http.Server{
		Handler: s.singlePodHandler(),
	}

	slog.Info("Starting single-pod HTTP server on listener", "addr", listener.Addr())
	return s.httpServer.Serve(listener)
}

func (s *Server) muxHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/conntrack", s.handleFanoutWebSocket)

	return mux
}

func (s *Server) StartMuxWithListener(listener net.Listener) error {
	muxServer := &http.Server{
		Handler: s.muxHandler(),
	}

	slog.Info("Starting multiplexer HTTP server on listener", "addr", listener.Addr())
	return muxServer.Serve(listener)
}

func getExeFromPID(pid uint32) string {
	exe, _ := getExeFromPIDWithError(pid)
	return exe
}

func getExeFromPIDWithError(pid uint32) (string, error) {
	if pid == 0 {
		return "", nil
	}

	statusPath := fmt.Sprintf("%s/%d/status", procPath, pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "", err
	}

	return parseProcessNameFromStatus(data, statusPath)
}

func parseProcessNameFromStatus(data []byte, source string) (string, error) {
	firstLine, _, _ := strings.Cut(string(data), "\n")
	name, ok := strings.CutPrefix(firstLine, "Name:")
	if !ok {
		return "", fmt.Errorf("missing Name field in %s", source)
	}

	processName := strings.TrimSpace(name)
	if processName == "" {
		return "", fmt.Errorf("empty Name field in %s", source)
	}

	return processName, nil
}

func getNetNS(pid uint32) uint64 {
	if pid == 0 {
		return 0
	}

	netnsPath := fmt.Sprintf("%s/%d/ns/net", procPath, pid)
	target, err := os.Readlink(netnsPath)
	if err != nil {
		return 0
	}

	return parseNetNSIdentifier(target)
}

func parseNetNSIdentifier(netns string) uint64 {
	if netns == "" {
		return 0
	}

	start := strings.Index(netns, "[")
	if start == -1 {
		return 0
	}
	start++

	end := strings.Index(netns[start:], "]")
	if end == -1 {
		return 0
	}

	id, err := strconv.ParseUint(netns[start:start+end], 10, 64)
	if err != nil {
		return 0
	}

	return id
}

func getCgroupSlice(pid uint32) string {
	cgroupSlice, _ := getCgroupSliceWithError(pid)
	return cgroupSlice
}

func getCgroupSliceWithError(pid uint32) (string, error) {
	if pid == 0 {
		return "", nil
	}

	cgroupPath := fmt.Sprintf("%s/%d/cgroup", procPath, pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "", err
	}

	return parseCgroupSlice(data, cgroupPath)
}

func parseCgroupSlice(data []byte, source string) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 0 {
		if lines[0] != "" {
			return lines[0], nil
		}
	}
	return "", fmt.Errorf("empty cgroup file %s", source)
}

func (s *Server) getExeFromPID(pid uint32) string {
	exe := getExeFromPID(pid)
	if pid != 0 && exe == "" {
		s.incResolutionFailure("exe")
	}
	return exe
}

func (s *Server) getNetNS(pid uint32) uint64 {
	netns := getNetNS(pid)
	if pid != 0 && netns == 0 {
		s.incResolutionFailure("netns")
	}
	return netns
}

func (s *Server) getCgroupSlice(pid uint32) string {
	cgroupSlice, cgroupErr := getCgroupSliceWithError(pid)
	if pid != 0 && cgroupSlice == "" {
		s.incResolutionFailure("cgroup")
		processName, statusErr := getExeFromPIDWithError(pid)
		slog.Warn("Failed to resolve cgroup slice",
			"path", fmt.Sprintf("%s/%d/cgroup", procPath, pid),
			"pid", pid,
			"processName", processName,
			"cgroupError", cgroupErr,
			"statusPath", fmt.Sprintf("%s/%d/status", procPath, pid),
			"statusError", statusErr,
			"node", s.nodeName,
		)
	}
	return cgroupSlice
}

func isLoopbackIP(ip string) bool {
	if ip == "" {
		return false
	}
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	if ip == "::1" {
		return true
	}
	return false
}

func familyToString(family uint16) string {
	if name, ok := types.FamilyNames[family]; ok {
		return name
	}
	return fmt.Sprintf("%d", family)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}

func getHostIPs() ([]string, error) {
	var ips []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			if ip.To4() != nil {
				ips = append(ips, ip.String())
			} else if ip.To16() != nil {
				ips = append(ips, ip.String())
			}
		}
	}

	return ips, nil
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	slog.Debug("New WebSocket connection request", "remote", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		return
	}

	// Send host.info directly before starting writer goroutine
	hostInfoEvent := &HostInfoEvent{
		EventType: "host.info",
		Timestamp: time.Now().Format(time.RFC3339),
		NodeName:  s.nodeName,
		HostIPs:   s.hostIPs,
		HostNetNS: hostNetNSInt,
		ImageHash: s.imageHash,
	}
	if err := conn.WriteJSON(hostInfoEvent); err != nil {
		slog.Error("Failed to send host.info event", "error", err)
		conn.Close()
		return
	}

	// Create client writer
	cw := &clientWriter{
		conn:             conn,
		ch:               make(chan Event, clientEventBufferSize),
		done:             make(chan struct{}),
		scannedNetNS:     make(map[uint64]bool),
		broadcastedPorts: make(map[string]bool),
		sentProcessPID:   make(map[uint32]bool),
		sentContainerUID: make(map[string]bool),
	}

	// Register client
	s.clientsMu.Lock()
	s.clients[conn] = cw
	s.clientsMu.Unlock()

	// Start writer goroutine
	go s.clientWriterLoop(cw)

	// Send initial state through the channel to ensure sequential processing
	go func() {
		// We need to send initial state in order, so we'll send it through cw.ch
		// But we can't block, so we use a select with a timeout
		select {
		case cw.ch <- &initialStateMarker{}:
			// Initial state marker sent
		case <-cw.done:
			// Client disconnected before initial state could be queued
		case <-time.After(100 * time.Millisecond):
			slog.Warn("Timeout sending initial state marker")
		}
	}()

	// Read loop (just to detect disconnects)
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			slog.Debug("WebSocket read error, closing connection", "error", err, "remote", r.RemoteAddr)
			break
		}
	}

	// Unregister client
	s.clientsMu.Lock()
	delete(s.clients, conn)
	s.clientsMu.Unlock()

	// Signal writer goroutine to stop. cw.ch is intentionally left open so
	// concurrent broadcast snapshots cannot panic by sending to a closed channel.
	close(cw.done)
	cw.conn.Close()
}

// containerToEvent converts a ContainerInfo to a container.added WebSocket event.
// Only sends fields that containerd reliably provides: kube metadata.
// PID, cgroupSlice, and pod IPs are NOT included — they are not reliably available from
// containerd and are instead resolved from /proc when PID-bearing events are handled.
func (s *Server) containerToEvent(container *types.ContainerInfo) *ContainerAddedEvent {
	event := &ContainerAddedEvent{
		EventType:    "container.added",
		Timestamp:    time.Now().Format(time.RFC3339),
		NodeName:     s.nodeName,
		ContainerUID: container.ID,
		Name:         container.Name,
	}

	// Add flattened Kubernetes metadata
	if container.PodName != "" {
		event.PodName = container.PodName
	}
	if container.PodNamespace != "" {
		event.Namespace = container.PodNamespace
	}
	if container.PodUID != "" {
		event.PodUID = container.PodUID
	}
	// Use container name from pod metadata if available, otherwise use containerd container name
	if container.ContainerName != "" {
		event.ContainerName = container.ContainerName
	} else {
		event.ContainerName = container.Name
	}
	if container.Image != "" {
		event.Image = container.Image
	}
	// Only include labels if they are not empty
	if len(container.Labels) > 0 {
		event.Labels = container.Labels
	}

	return event
}

func (s *Server) sendInitialState(conn *websocket.Conn, cw *clientWriter) {
	slog.Debug("sendInitialState called", "nodeName", s.nodeName, "hostIPs", s.hostIPs)

	// host.info is already sent directly in handleWebSocket, skip here

	s.mu.RLock()
	containers := make([]*types.ContainerInfo, 0, len(s.containers))
	for _, c := range s.containers {
		containers = append(containers, c)
	}
	s.mu.RUnlock()

	for _, container := range containers {
		event := s.containerToEvent(container)
		if err := s.writeEventToClient(cw, event); err != nil {
			slog.Debug("Failed to send initial container event", "remote", conn.RemoteAddr(), "error", err)
			return
		}
	}

	slog.Debug("Sent initial containers", "count", len(containers))

	// Scan all PIDs in /proc to find all network namespaces
	seenNetNS := make(map[uint64]bool)
	var toScan []struct {
		pid   uint32
		netns uint64
	}

	// Read all numeric directories in /proc
	procDir, err := os.Open("/proc")
	if err != nil {
		slog.Error("Failed to open /proc", "error", err)
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		slog.Error("Failed to read /proc entries", "error", err)
		return
	}

	for _, entry := range entries {
		// Check if entry is a numeric PID
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}
		pid32 := uint32(pid)

		// Get network namespace for this PID
		netns := s.getNetNS(pid32)
		if netns == 0 {
			continue
		}

		// Skip if we've already seen this network namespace
		if seenNetNS[netns] {
			continue
		}
		seenNetNS[netns] = true

		toScan = append(toScan, struct {
			pid   uint32
			netns uint64
		}{
			pid:   pid32,
			netns: netns,
		})
	}

	slog.Debug("Scanning listening ports for initial state", "namespaceCount", len(toScan))

	for _, entry := range toScan {
		if !s.sendListeningPortsToClient(conn, cw, entry.pid, entry.netns) {
			return
		}
	}

	slog.Debug("Initial state sent", "remote", conn.RemoteAddr())
}

func (s *Server) sendListeningPortsToClient(conn *websocket.Conn, cw *clientWriter, pid uint32, netns uint64) bool {
	for _, netType := range []string{"tcp", "tcp6", "udp", "udp6"} {
		var protocol uint8
		if strings.HasPrefix(netType, "tcp") {
			protocol = types.ProtocolTCP
		} else {
			protocol = types.ProtocolUDP
		}

		ports := s.scanProcNetFile(pid, netType)
		for _, port := range ports {

			wsEvent := &PortListeningEvent{
				EventType:   "port.listening",
				Timestamp:   time.Now().Format(time.RFC3339),
				NodeName:    s.nodeName,
				Protocol:    types.ProtocolNames[protocol],
				IP:          port.IP,
				Port:        port.Port,
				NetNS:       netns,
				IsHostNetNS: netns == hostNetNSInt,
			}

			portKey := fmt.Sprintf("%s:%s:%s:%d:%d",
				wsEvent.NodeName, wsEvent.Protocol, wsEvent.IP, wsEvent.Port, wsEvent.NetNS)
			if cw.broadcastedPorts[portKey] {
				continue
			}
			if err := s.writeEventToClient(cw, wsEvent); err != nil {
				slog.Debug("Failed to send initial port.listening event", "remote", conn.RemoteAddr(), "error", err)
				return false
			}
			cw.broadcastedPorts[portKey] = true
		}
	}
	return true
}

func (s *Server) processEBPFEvents() {
	for event := range s.tracer.Events() {
		protocolName, _ := types.ProtocolNames[event.Protocol]
		localIP, remoteIP := event.LocalRemoteIPs()

		slog.Debug("Received eBPF connection event",
			"pid", event.PID,
			"protocol", protocolName,
			"family", familyToString(event.Family),
			"sport", event.Sport,
			"dport", event.Dport,
			"state", event.StateToString(),
			"src", localIP,
			"dst", remoteIP,
			"sockCookie", fmt.Sprintf("0x%x", event.SockCookie),
		)

		s.handleConnectionEvent(event)
	}
}

func (s *Server) incEventCounter(labels ...string) {
	key := strings.Join(labels, "::")
	s.metricsMu.Lock()
	counter, exists := s.eventCounters[key]
	if !exists {
		counter = &atomic.Uint64{}
		s.eventCounters[key] = counter
	}
	s.metricsMu.Unlock()
	counter.Add(1)
}

func (s *Server) incWSEventCounter(eventType string) {
	s.metricsMu.Lock()
	counter, exists := s.wsEventCounters[eventType]
	if !exists {
		counter = &atomic.Uint64{}
		s.wsEventCounters[eventType] = counter
	}
	s.metricsMu.Unlock()
	counter.Add(1)
}

func (s *Server) incResolutionFailure(field string) {
	s.metricsMu.Lock()
	counter, exists := s.resolutionFailures[field]
	if !exists {
		counter = &atomic.Uint64{}
		s.resolutionFailures[field] = counter
	}
	s.metricsMu.Unlock()
	counter.Add(1)
}

func (s *Server) incMissingAddr(side string) {
	s.metricsMu.Lock()
	counter, exists := s.missingAddrCounters[side]
	if !exists {
		counter = &atomic.Uint64{}
		s.missingAddrCounters[side] = counter
	}
	s.metricsMu.Unlock()
	counter.Add(1)
}

func (s *Server) scanListeningPortsForNetNS(pid uint32, netns uint64, containerUID string) {
	if pid == 0 || netns == 0 {
		return
	}

	slog.Debug("Scanning listening ports for network namespace", "netns", netns, "pid", pid)

	var container *types.ContainerInfo
	if containerUID != "" {
		s.mu.RLock()
		container = s.containers[containerUID]
		s.mu.RUnlock()

		if container == nil {
			// First try to get by container UID
			info, err := s.ctrdClient.GetContainerInfoByContainerID(containerUID)
			if err != nil {
				// If not found, try pod UID
				info, err = s.ctrdClient.GetContainerInfoByPodUID(containerUID)
			}
			if err == nil {
				s.mu.Lock()
				s.containers[info.ID] = info
				s.mu.Unlock()
				container = info
				s.broadcastContainerAdded(info)
			}
		}
	}

	for _, netType := range []string{"tcp", "tcp6", "udp", "udp6"} {
		var protocol uint8
		if strings.HasPrefix(netType, "tcp") {
			protocol = types.ProtocolTCP
		} else {
			protocol = types.ProtocolUDP
		}

		ports := s.scanProcNetFile(pid, netType)
		for _, port := range ports {
			portContainerUID := containerUID
			var portContainer *types.ContainerInfo
			if containerUID != "" {
				portContainer = container
			}

			portEvent := &PortListeningEvent{
				EventType:   "port.listening",
				Timestamp:   time.Now().Format(time.RFC3339),
				NodeName:    s.nodeName,
				Protocol:    types.ProtocolNames[protocol],
				IP:          port.IP,
				Port:        port.Port,
				NetNS:       netns,
				IsHostNetNS: netns == hostNetNSInt,
			}
			s.broadcastListeningPort(portEvent, portContainerUID, portContainer)
		}
	}
}

func (s *Server) scanProcNetFile(pid uint32, netType string) []listeningSocket {
	var ports []listeningSocket

	filePath := fmt.Sprintf("%s/%d/net/%s", procPath, pid, netType)
	file, err := os.Open(filePath)
	if err != nil {
		slog.Debug("Failed to open proc net file", "path", filePath, "error", err)
		return ports
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return ports
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]
		state := fields[3]

		if netType == "tcp" || netType == "tcp6" {
			if state != "0A" {
				continue
			}
		}

		remoteParts := strings.Split(remoteAddr, ":")
		if len(remoteParts) != 2 {
			continue
		}

		remoteHexIP := remoteParts[0]
		remoteHexPort := remoteParts[1]

		isListening := false
		if netType == "tcp6" || netType == "udp6" {
			if remoteHexIP == "00000000000000000000000000000000" && remoteHexPort == "0000" {
				isListening = true
			}
		} else {
			if remoteHexIP == "00000000" && remoteHexPort == "0000" {
				isListening = true
			}
		}

		if !isListening {
			continue
		}

		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		hexIP := parts[0]
		hexPort := parts[1]

		portNum, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}

		var ip string
		if netType == "tcp6" || netType == "udp6" {
			ip, err = parseHexIPv6(hexIP)
			if err != nil {
				continue
			}
		} else {
			ip, err = parseHexIPv4(hexIP)
			if err != nil {
				continue
			}
		}

		if isLoopbackIP(ip) {
			continue
		}

		ports = append(ports, listeningSocket{
			IP:   ip,
			Port: uint16(portNum),
		})
	}

	return ports
}

func parseHexIPv4(hexIP string) (string, error) {
	if len(hexIP) != 8 {
		return "", fmt.Errorf("invalid hex IP length: %d", len(hexIP))
	}

	val, err := strconv.ParseUint(hexIP, 16, 32)
	if err != nil {
		return "", err
	}

	ip := net.IPv4(byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
	return ip.String(), nil
}

func parseHexIPv6(hexIP string) (string, error) {
	if len(hexIP) != 32 {
		return "", fmt.Errorf("invalid hex IPv6 length: %d", len(hexIP))
	}

	var b [16]byte
	for i := 0; i < 4; i++ {
		word := hexIP[i*8 : (i+1)*8]
		val, err := strconv.ParseUint(word, 16, 32)
		if err != nil {
			return "", err
		}
		b[i*4] = byte(val)
		b[i*4+1] = byte(val >> 8)
		b[i*4+2] = byte(val >> 16)
		b[i*4+3] = byte(val >> 24)
	}

	return net.IP(b[:]).String(), nil
}

func (s *Server) broadcastContainerAdded(container *types.ContainerInfo) {
	select {
	case s.broadcast <- s.containerToEvent(container):
		// Counter will be incremented in handleBroadcast when event is sent
	default:
		slog.Warn("Broadcast channel full, dropping container.added event")
	}
}

func (s *Server) handleConnectionEvent(event types.ConnEvent) {
	localIP, remoteIP := event.LocalRemoteIPs()

	if event.Protocol == types.ProtocolTCP && event.State == types.TCPListen {
		s.handleListenStateEvent(event)
		return
	}

	if localIP == "" {
		s.incMissingAddr("local")
	}
	if remoteIP == "" {
		s.incMissingAddr("remote")
	}

	if isLoopbackIP(localIP) || isLoopbackIP(remoteIP) {
		s.loopbackCounter.Add(1)
		return
	}

	protocol := event.Protocol
	family := event.Family
	state := event.StateToString()

	s.incEventCounter("total", strconv.FormatUint(uint64(protocol), 10), strconv.FormatUint(uint64(family), 10))
	s.incEventCounter("state", strconv.FormatUint(uint64(protocol), 10), strconv.FormatUint(uint64(family), 10), state)

	// Note: container.metainfo and process.metainfo events are sent by the
	// WebSocket goroutine before PID-bearing connection.accepted events.

	baseEvent := ConnectionEvent{
		EventType:  "connection.event",
		Timestamp:  time.Now().Format(time.RFC3339),
		NodeName:   s.nodeName,
		Protocol:   types.ProtocolNames[event.Protocol],
		State:      state,
		SockCookie: event.SockCookie,
		LocalIP:    localIP,
		RemoteIP:   remoteIP,
	}
	if event.Sport != 0 {
		baseEvent.LocalPort = event.Sport
	}
	if event.Dport != 0 {
		baseEvent.RemotePort = event.Dport
	}

	var wsEvent Event = &baseEvent
	if event.EventType == types.ConnEventTCPAccept {
		if event.PID == 0 {
			s.acceptMissingPID.Add(1)
			slog.Warn("Dropping TCP accept event without PID",
				"nodeName", s.nodeName,
				"localIP", localIP,
				"remoteIP", remoteIP,
				"localPort", event.Sport,
				"remotePort", event.Dport,
				"sockCookie", fmt.Sprintf("0x%x", event.SockCookie),
			)
			return
		}
		baseEvent.EventType = "connection.accepted"
		wsEvent = &ConnectionAcceptedEvent{
			ConnectionEvent: baseEvent,
			PID:             event.PID,
		}
	}

	select {
	case s.broadcast <- wsEvent:
		slog.Debug("handleConnectionEvent: broadcast websocket event", "type", wsEvent.Type())
	default:
		slog.Warn("Broadcast channel full, dropping connection event")
	}
}

func (s *Server) createContainerMetainfoEvent(containerUID string) *ContainerMetainfoEvent {
	if containerUID == "" {
		return nil
	}

	s.mu.RLock()
	containerInfo := s.containers[containerUID]
	s.mu.RUnlock()

	if containerInfo == nil {
		return nil
	}

	event := &ContainerMetainfoEvent{
		EventType:    "container.metainfo",
		Timestamp:    time.Now().Format(time.RFC3339),
		NodeName:     s.nodeName,
		ContainerUID: containerInfo.ID,
	}

	if containerInfo.PodName != "" {
		event.PodName = containerInfo.PodName
	}
	if containerInfo.PodNamespace != "" {
		event.Namespace = containerInfo.PodNamespace
	}
	if containerInfo.PodUID != "" {
		event.PodUID = containerInfo.PodUID
	}
	if containerInfo.ContainerName != "" {
		event.ContainerName = containerInfo.ContainerName
	}
	if containerInfo.Image != "" {
		event.Image = containerInfo.Image
	}
	if len(containerInfo.Labels) > 0 {
		event.Labels = containerInfo.Labels
	}

	return event
}

func (s *Server) createProcessMetainfoEvent(pid uint32) *ProcessMetainfoEvent {
	if pid == 0 {
		slog.Debug("createProcessMetainfoEvent: pid is 0")
		return nil
	}

	exe := s.getExeFromPID(pid)

	netns := s.getNetNS(pid)
	cgroupSlice := s.getCgroupSlice(pid)
	return s.createProcessMetainfoEventFromResolved(pid, exe, netns, cgroupSlice)
}

func (s *Server) createProcessMetainfoEventFromResolved(pid uint32, exe string, netns uint64, cgroupSlice string) *ProcessMetainfoEvent {
	if pid == 0 {
		slog.Debug("createProcessMetainfoEvent: pid is 0")
		return nil
	}

	slog.Debug("createProcessMetainfoEvent",
		"pid", pid,
		"exe", exe,
		"netns", netns,
		"cgroupSlice", cgroupSlice)

	// Container UID is optional: not every cgroup path resolves to a containerd ID.
	containerUID := containerd.ExtractContainerUIDFromCgroup(cgroupSlice)
	if containerUID != "" && netns == 0 {
		slog.Warn("Dropping container process metadata without network namespace",
			"pid", pid,
			"exe", exe,
			"containerUID", containerUID,
			"cgroupSlice", cgroupSlice,
		)
		return nil
	}

	// Build process.metainfo event - only include core fields
	event := &ProcessMetainfoEvent{
		EventType:    "process.metainfo",
		Timestamp:    time.Now().Format(time.RFC3339),
		NodeName:     s.nodeName,
		PID:          pid,
		Exe:          exe,
		NetNS:        netns,
		IsHostNetNS:  netns != 0 && netns == hostNetNSInt,
		CgroupSlice:  cgroupSlice,
		ContainerUID: containerUID,
	}

	slog.Debug("Created process.metainfo event", "pid", pid, "exe", exe, "netns", netns, "cgroupSlice", cgroupSlice)
	return event
}

func (s *Server) fetchAndSendContainerMetainfo(containerUID, podUID string, pid uint32, cgroupSlice string) {
	// Try to get container info by container UID first
	var containerInfo *types.ContainerInfo
	var err error

	if containerUID != "" {
		containerInfo, err = s.ctrdClient.GetContainerInfoByContainerID(containerUID)
		if err != nil {
			containerInfo = nil
		}
	}

	// If not found, try pod UID
	if containerInfo == nil && podUID != "" {
		containerInfo, err = s.ctrdClient.GetContainerInfoByPodUID(podUID)
		if err != nil {
			return
		}
	}

	if containerInfo == nil {
		return
	}

	// Store in cache
	s.mu.Lock()
	s.containers[containerInfo.ID] = containerInfo
	s.mu.Unlock()

	wsEvent := &ContainerMetainfoEvent{
		EventType:     "container.metainfo",
		Timestamp:     time.Now().Format(time.RFC3339),
		NodeName:      s.nodeName,
		ContainerUID:  containerInfo.ID,
		PodName:       containerInfo.PodName,
		Namespace:     containerInfo.PodNamespace,
		PodUID:        containerInfo.PodUID,
		ContainerName: containerInfo.ContainerName,
		Image:         containerInfo.Image,
		Labels:        containerInfo.Labels,
	}

	select {
	case s.broadcast <- wsEvent:
		// Counter will be incremented in handleBroadcast when event is sent
	default:
		slog.Warn("Broadcast channel full, dropping container.metainfo event")
	}
}

func (s *Server) handleListenStateEvent(event types.ConnEvent) {
	netns := s.getNetNS(event.PID)
	if netns == 0 {
		return
	}

	if event.Sport == 0 {
		cgroupSlice := s.getCgroupSlice(event.PID)
		containerUID := containerd.ExtractContainerUIDFromCgroup(cgroupSlice)
		if containerUID == "" {
			containerUID = containerd.ExtractPodUIDFromCgroup(cgroupSlice)
		}
		slog.Debug("listen syscall observed; rescanning listening ports for process network namespace",
			"pid", event.PID,
			"netns", netns,
			"containerUID", containerUID,
		)
		go s.scanListeningPortsForNetNS(event.PID, netns, containerUID)
		return
	}

	localIP, _ := event.LocalRemoteIPs()

	cgroupSlice := s.getCgroupSlice(event.PID)
	var containerUID string
	var containerInfo *types.ContainerInfo

	if cgroupSlice != "" {
		containerUID = containerd.ExtractPodUIDFromCgroup(cgroupSlice)
		if containerUID != "" {
			s.mu.RLock()
			containerInfo = s.containers[containerUID]
			s.mu.RUnlock()

			if containerInfo == nil {
				info, err := s.ctrdClient.GetContainerInfoByPodUID(containerUID)
				if err == nil {
					s.mu.Lock()
					s.containers[containerUID] = info
					s.mu.Unlock()
					containerInfo = info
					s.broadcastContainerAdded(info)
				}
			}
		}
	}

	portEvent := &PortListeningEvent{
		EventType:   "port.listening",
		Timestamp:   time.Now().Format(time.RFC3339),
		NodeName:    s.nodeName,
		Protocol:    types.ProtocolNames[types.ProtocolTCP],
		IP:          localIP,
		Port:        event.Sport,
		NetNS:       netns,
		IsHostNetNS: netns == hostNetNSInt,
	}
	s.broadcastListeningPort(portEvent, containerUID, containerInfo)
}

func (s *Server) broadcastListeningPort(port *PortListeningEvent, containerUID string, container *types.ContainerInfo) {
	if isLoopbackIP(port.IP) {
		return
	}

	// Don't include cgroupSlice in initial port events
	// It will be updated from connection events later
	// Use containerUID directly, don't extract from cgroupSlice

	var containerInfo *types.ContainerInfo
	if containerUID != "" {
		if container != nil {
			containerInfo = container
		} else {
			s.mu.RLock()
			containerInfo = s.containers[containerUID]
			s.mu.RUnlock()

			if containerInfo == nil {
				info, err := s.ctrdClient.GetContainerInfoByPodUID(containerUID)
				if err == nil {
					s.mu.Lock()
					s.containers[containerUID] = info
					s.mu.Unlock()
					containerInfo = info
					s.broadcastContainerAdded(info)
				}
			}
		}
	}

	// UsesHostNetwork is now determined on the client side based on hostNetNS from host.info event

	// Log the port listening event being broadcasted
	logFields := []interface{}{
		"node", s.nodeName,
		"protocol", port.Protocol,
		"ip", port.IP,
		"port", port.Port,
		"netns", port.NetNS,
	}
	if containerInfo != nil {
		logFields = append(logFields, "containerUID", containerInfo.ID)
	}
	slog.Info("Broadcasting port.listening event", logFields...)

	select {
	case s.broadcast <- port:
		// Counter will be incremented in handleBroadcast when event is sent
	default:
		slog.Warn("Broadcast channel full, dropping port.listening event")
	}
}

func toUint64(v interface{}) (uint64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return uint64(f), true
}

func toUint32(v interface{}) (uint32, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return uint32(f), true
}

func toUint16(v interface{}) (uint16, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return uint16(f), true
}

func (s *Server) clientWriterLoop(cw *clientWriter) {
	defer cw.conn.Close()

	for {
		select {
		case <-cw.done:
			return
		case event := <-cw.ch:
			if event == nil {
				continue
			}
			// Handle different event types using type switch
			switch e := event.(type) {
			case *ConnectionEvent:
				s.writeEventToClient(cw, e)
			case *ConnectionAcceptedEvent:
				s.handleConnectionAcceptedEventForClient(cw, e)
			case *ContainerMetainfoEvent:
				s.writeEventToClient(cw, e)
			case *ProcessMetainfoEvent:
				s.writeEventToClient(cw, e)
				cw.sentProcessPID[e.PID] = true
			case *PortListeningEvent:
				// Check if we've already sent this port
				portKey := fmt.Sprintf("%s:%s:%s:%d:%d",
					e.NodeName, e.Protocol, e.IP, e.Port, e.NetNS)
				if !cw.broadcastedPorts[portKey] {
					s.writeEventToClient(cw, e)
					cw.broadcastedPorts[portKey] = true
				}
			case JSONEvent:
				// For JSON events from fanout, just write them directly
				s.writeEventToClient(cw, e)
			case *initialStateMarker:
				slog.Debug("clientWriterLoop: received initialStateMarker, calling sendInitialState")
				// Send initial state
				s.sendInitialState(cw.conn, cw)
			default:
				// For other events (host.info, container.added, etc.)
				s.writeEventToClient(cw, event)
			}
		}
	}
}

func (s *Server) handleConnectionAcceptedEventForClient(cw *clientWriter, event *ConnectionAcceptedEvent) {
	pid := event.PID
	var resolvedExe string
	var resolvedNetNS uint64
	var resolvedCgroupSlice string

	// Send container.metainfo first if needed
	if pid > 0 && !cw.sentProcessPID[pid] {
		resolvedExe = s.getExeFromPID(pid)
		resolvedNetNS = s.getNetNS(pid)
		resolvedCgroupSlice = s.getCgroupSlice(pid)

		// Extract container UID
		var containerUID string
		if resolvedCgroupSlice != "" {
			containerUID = containerd.ExtractContainerUIDFromCgroup(resolvedCgroupSlice)
		}

		// Send container.metainfo if we have container UID and haven't sent it yet
		if containerUID != "" && !cw.sentContainerUID[containerUID] {
			// Get container info
			s.mu.RLock()
			containerInfo := s.containers[containerUID]
			s.mu.RUnlock()

			// If not in cache, try to fetch it
			if containerInfo == nil {
				info, err := s.ctrdClient.GetContainerInfoByContainerID(containerUID)
				if err == nil {
					s.mu.Lock()
					s.containers[containerUID] = info
					s.mu.Unlock()
					containerInfo = info
				}
			}

			// Send container.metainfo event if we have container info
			if containerInfo != nil {
				containerEvent := s.createContainerMetainfoEvent(containerUID)
				if containerEvent != nil {
					s.writeEventToClient(cw, containerEvent)
					cw.sentContainerUID[containerUID] = true
				}
			}
		}

		processEvent := s.createProcessMetainfoEventFromResolved(
			pid,
			resolvedExe,
			resolvedNetNS,
			resolvedCgroupSlice,
		)
		if processEvent != nil {
			s.writeEventToClient(cw, processEvent)
			cw.sentProcessPID[pid] = true
		}
	}

	// Handle network namespace scanning
	netns := resolvedNetNS
	if netns == 0 && pid > 0 && !cw.sentProcessPID[pid] {
		netns = s.getNetNS(pid)
	}
	if netns != 0 {
		if !cw.scannedNetNS[netns] {
			cw.scannedNetNS[netns] = true

			// Try to extract podUID from cgroupSlice if available
			var podUID string
			if resolvedCgroupSlice != "" {
				podUID = containerd.ExtractPodUIDFromCgroup(resolvedCgroupSlice)
			}
			go s.scanListeningPortsForNetNS(pid, netns, podUID)
		}
	}

	s.writeEventToClient(cw, event)
}

func (s *Server) writeEventToClient(cw *clientWriter, event Event) error {
	// Extract event type for metrics
	// All events have a Type() method
	s.incWSEventCounter(event.Type())

	// Handle JSONEvent specially
	if je, ok := event.(JSONEvent); ok {
		return cw.conn.WriteMessage(websocket.TextMessage, je.Data)
	}
	return cw.conn.WriteJSON(event)
}

func enqueueClientEvent(cw *clientWriter, event Event) bool {
	select {
	case <-cw.done:
		return false
	default:
	}

	select {
	case <-cw.done:
		return false
	case cw.ch <- event:
		return true
	default:
		return false
	}
}

func (s *Server) handleBroadcast() {
	for event := range s.broadcast {
		s.clientsMu.RLock()
		clients := make([]*clientWriter, 0, len(s.clients))
		for _, cw := range s.clients {
			clients = append(clients, cw)
		}
		s.clientsMu.RUnlock()

		for _, cw := range clients {
			if !enqueueClientEvent(cw, event) {
				s.clientDropCounter.Add(1)
			}
		}
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	s.metricsMu.RLock()
	eventCounters := make(map[string]uint64)
	for key, counter := range s.eventCounters {
		eventCounters[key] = counter.Load()
	}
	wsEventCounters := make(map[string]uint64)
	for key, counter := range s.wsEventCounters {
		wsEventCounters[key] = counter.Load()
	}
	missingAddrCounters := make(map[string]uint64)
	for key, counter := range s.missingAddrCounters {
		missingAddrCounters[key] = counter.Load()
	}
	resolutionFailures := make(map[string]uint64)
	for key, counter := range s.resolutionFailures {
		resolutionFailures[key] = counter.Load()
	}
	s.metricsMu.RUnlock()

	fmt.Fprintf(w, "netstatd_loopback_events_total %d\n", s.loopbackCounter.Load())
	fmt.Fprintf(w, "netstatd_missing_pid_accept_events_total %d\n", s.acceptMissingPID.Load())
	fmt.Fprintf(w, "netstatd_client_dropped_events_total %d\n", s.clientDropCounter.Load())
	for side, value := range missingAddrCounters {
		fmt.Fprintf(w, "netstatd_missing_connection_ip_total{side=\"%s\"} %d\n", side, value)
	}

	// Output eBPF event counters
	for key, value := range eventCounters {
		parts := strings.Split(key, "::")
		if len(parts) < 3 {
			continue
		}
		prefix := parts[0]
		protocol := parts[1]
		family := parts[2]

		var metricName, labels string

		if prefix == "total" {
			metricName = "netstatd_events_total"
			labels = fmt.Sprintf(`protocol="%s",family="%s"`, protocol, family)
		} else if prefix == "state" && len(parts) >= 4 {
			metricName = "netstatd_events_by_state"
			state := strings.Join(parts[3:], "::")
			labels = fmt.Sprintf(`protocol="%s",family="%s",state="%s"`, protocol, family, state)
		} else {
			continue
		}

		fmt.Fprintf(w, "%s{%s} %d\n", metricName, labels, value)
	}

	// Output WebSocket event counters
	for eventType, value := range wsEventCounters {
		fmt.Fprintf(w, "netstatd_ws_events_total{type=\"%s\"} %d\n", eventType, value)
	}

	for field, value := range resolutionFailures {
		fmt.Fprintf(w, "netstatd_resolution_failures_total{field=\"%s\"} %d\n", field, value)
	}
}

func (s *Server) handleFanoutWebSocket(w http.ResponseWriter, r *http.Request) {
	slog.Debug("New fanout WebSocket connection request", "remote", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		return
	}
	defer conn.Close()

	if s.fanoutService == "" {
		conn.WriteJSON(map[string]string{"error": "Fanout service not configured"})
		return
	}

	podIPs, err := s.resolvePodIPs(s.fanoutService)
	if err != nil {
		conn.WriteJSON(map[string]string{"error": fmt.Sprintf("Failed to resolve pods: %v", err)})
		return
	}

	slog.Info("Fanout: discovered pod IPs", "count", len(podIPs), "ips", podIPs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aggregatedEvents := make(chan Event, 1000)

	var wg sync.WaitGroup
	podCancels := make(map[string]context.CancelFunc)
	startPodWorker := func(podIP string) {
		if _, exists := podCancels[podIP]; exists {
			return
		}
		podCtx, podCancel := context.WithCancel(ctx)
		podCancels[podIP] = podCancel
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			s.connectToPod(podCtx, ip, "5280", aggregatedEvents)
		}(podIP)
	}

	for _, podIP := range podIPs {
		startPodWorker(podIP)
	}

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				for _, podCancel := range podCancels {
					podCancel()
				}
				wg.Wait()
				close(aggregatedEvents)
				return
			case <-ticker.C:
				nextPodIPs, err := s.resolvePodIPs(s.fanoutService)
				if err != nil {
					slog.Warn("Fanout: failed to refresh pod IPs", "service", s.fanoutService, "error", err)
					continue
				}

				next := make(map[string]bool, len(nextPodIPs))
				for _, podIP := range nextPodIPs {
					next[podIP] = true
					startPodWorker(podIP)
				}

				for podIP, podCancel := range podCancels {
					if !next[podIP] {
						slog.Info("Fanout: stopping removed pod worker", "podIP", podIP)
						podCancel()
						delete(podCancels, podIP)
					}
				}
			}
		}
	}()

	writeMutex := &sync.Mutex{}
	go func() {
		for event := range aggregatedEvents {
			writeMutex.Lock()
			var err error
			// Handle JSONEvent specially - write raw bytes
			if je, ok := event.(JSONEvent); ok {
				// Log for debugging
				slog.Debug("Fanout: writing JSONEvent", "data_length", len(je.Data))
				err = conn.WriteMessage(websocket.TextMessage, je.Data)
			} else {
				slog.Debug("Fanout: writing regular event", "type", event.Type())
				err = conn.WriteJSON(event)
			}
			writeMutex.Unlock()
			if err != nil {
				slog.Error("Fanout write error", "error", err)
				cancel()
				conn.Close()
				return
			}
		}
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			cancel()
			break
		}
	}
}

func (s *Server) resolvePodIPs(serviceName string) ([]string, error) {
	ips, err := net.LookupIP(serviceName)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", serviceName, err)
	}

	var podIPs []string
	for _, ip := range ips {
		podIPs = append(podIPs, ip.String())
	}

	if len(podIPs) == 0 {
		return nil, fmt.Errorf("no pod IPs found for service %s", serviceName)
	}

	return podIPs, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fanoutReconnectDelay(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	if failures > 5 {
		failures = 5
	}
	delay := time.Second << failures
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func (s *Server) connectToPod(ctx context.Context, podIP string, port string, events chan<- Event) {
	failures := 0
	for {
		connected, err := s.streamPodEvents(ctx, podIP, port, events)
		if ctx.Err() != nil {
			return
		}
		if connected {
			failures = 0
		}

		delay := fanoutReconnectDelay(failures)
		failures++
		if err != nil {
			slog.Warn("Fanout: pod stream disconnected, reconnecting",
				"podIP", podIP,
				"delay", delay,
				"error", err)
		} else {
			slog.Warn("Fanout: pod stream ended, reconnecting",
				"podIP", podIP,
				"delay", delay)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *Server) streamPodEvents(ctx context.Context, podIP string, port string, events chan<- Event) (bool, error) {
	host := podIP
	if net.ParseIP(podIP).To4() == nil {
		host = fmt.Sprintf("[%s]", podIP)
	}
	wsURL := fmt.Sprintf("ws://%s:%s/conntrack", host, port)

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return false, fmt.Errorf("dial pod websocket: %w", err)
	}
	defer conn.Close()

	slog.Debug("Fanout: connected to pod", "podIP", podIP)

	// Channel for incoming events
	eventChan := make(chan Event, 10)

	// Read goroutine
	go func() {
		defer close(eventChan)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Read raw message
				_, msg, err := conn.ReadMessage()
				if err != nil {
					slog.Debug("Fanout: pod read stopped", "podIP", podIP, "error", err)
					return
				}
				// Log the raw message for debugging
				slog.Debug("Fanout: received message from pod",
					"podIP", podIP,
					"length", len(msg),
					"first_100_bytes", string(msg[:min(100, len(msg))]))
				// Create JSONEvent wrapper
				event := JSONEvent{Data: msg}
				select {
				case eventChan <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Monitor context cancellation to close connection
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return true, nil
		case event, ok := <-eventChan:
			if !ok {
				// Channel closed, read goroutine exited
				return true, fmt.Errorf("pod websocket reader stopped")
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return true, nil
			}
		}
	}
}
