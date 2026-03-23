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
	"path/filepath"
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

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in this example
	},
}

// Server handles HTTP and WebSocket requests
type Server struct {
	ctrdClient *containerd.Client
	tracer     *ebpf.Tracer
	httpServer *http.Server
	nodeName   string
	hostIPs    []string  // Host IP addresses
	dnsCache   *DNSCache // IP to hostname mapping cache

	// Container cache indexed by pod UID
	containers map[string]*types.ContainerInfo
	mu         sync.RWMutex

	// PID to container UID mapping for fast lookup
	pidToContainerUID map[uint32]string
	pidMu             sync.RWMutex

	// PID to executable name cache
	pidToExe   map[uint32]string
	pidToExeMu sync.RWMutex

	// Track which network namespaces we've scanned for listening ports
	scannedNetNS   map[uint64]bool
	scannedNetNSMu sync.RWMutex

	// Track which listening ports we've already broadcast
	// Key format: "nodeName:protocol:ip:port:netns"
	broadcastedPorts   map[string]bool
	broadcastedPortsMu sync.RWMutex

	// Local address:port to container mapping
	localAddrPortToContainer map[string]string // "tcp:127.0.0.1:8080" -> containerUID
	localAddrPortMu          sync.RWMutex

	// WebSocket clients
	clients   map[*websocket.Conn]bool
	clientsMu sync.RWMutex

	// Event broadcast channel
	broadcast chan interface{}

	// Mutex for each WebSocket connection to prevent concurrent writes
	connMutexes   map[*websocket.Conn]*sync.Mutex
	connMutexesMu sync.Mutex

	// Metrics
	eventCounters map[string]*atomic.Uint64 // key: "protocol_family" or "protocol_family_state"
	metricsMu     sync.RWMutex
}

// NewServer creates a new server
func NewServer(ctrdClient *containerd.Client, tracer *ebpf.Tracer) *Server {
	slog.Debug("Initializing server")
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		// Try to read from /etc/hostname
		hostnameBytes, err := os.ReadFile("/etc/hostname")
		if err == nil {
			nodeName = strings.TrimSpace(string(hostnameBytes))
			slog.Debug("Read node name from /etc/hostname", "nodeName", nodeName)
		} else {
			nodeName = "unknown"
			slog.Debug("Failed to read /etc/hostname, using 'unknown'", "error", err)
		}
	}
	slog.Debug("Node name", "nodeName", nodeName)

	// Detect host IPs
	slog.Debug("Detecting host IP addresses")
	hostIPs, err := getHostIPs()
	if err != nil {
		slog.Error("Failed to detect host IPs", "error", err)
		hostIPs = []string{}
	} else {
		slog.Info("Detected host IPs", "ips", hostIPs)
	}

	s := &Server{
		ctrdClient:               ctrdClient,
		tracer:                   tracer,
		nodeName:                 nodeName,
		hostIPs:                  hostIPs,
		dnsCache:                 NewDNSCache(3600 * time.Second), // 3600s TTL
		containers:               make(map[string]*types.ContainerInfo),
		pidToContainerUID:        make(map[uint32]string),
		pidToExe:                 make(map[uint32]string),
		scannedNetNS:             make(map[uint64]bool),
		broadcastedPorts:         make(map[string]bool),
		localAddrPortToContainer: make(map[string]string),
		clients:                  make(map[*websocket.Conn]bool),
		broadcast:                make(chan interface{}, 100),
		connMutexes:              make(map[*websocket.Conn]*sync.Mutex),
		eventCounters:            make(map[string]*atomic.Uint64),
	}

	slog.Debug("Starting event processor")
	// Start event processor
	go s.processEvents()
	slog.Debug("Event processor started")

	slog.Debug("Starting broadcast handler")
	// Start broadcast handler
	go s.handleBroadcast()
	slog.Debug("Broadcast handler started")

	slog.Info("Server successfully initialized")
	return s
}

// Start starts the HTTP server on the single-pod port
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	// Serve static files from web/static at /static/
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/containers", s.handleContainers)
	mux.HandleFunc("/netstat", s.handleWebSocket)
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s.httpServer.ListenAndServe()
}

// StartWithListener starts the HTTP server using a pre-created listener
func (s *Server) StartWithListener(listener net.Listener) error {
	mux := http.NewServeMux()
	// Serve static files from web/static at /static/
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/netstat", s.handleWebSocket)
	mux.HandleFunc("/netstat/fanout", s.handleFanoutRedirect)
	mux.HandleFunc("/api/pid-exe", s.handlePidExe)
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	slog.Info("Starting single-pod HTTP server on listener", "addr", listener.Addr())
	return s.httpServer.Serve(listener)
}

// StartMux starts the HTTP server on the multiplexer port with fanout endpoints
func (s *Server) StartMux(addr string) error {
	mux := http.NewServeMux()
	// Serve static files from web/static at /static/
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/containers", s.handleContainers)
	mux.HandleFunc("/netstat", s.handleFanoutWebSocket)
	mux.HandleFunc("/metrics", s.handleMetrics)

	muxServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	slog.Info("Starting multiplexer HTTP server", "addr", addr)
	return muxServer.ListenAndServe()
}

// StartMuxWithListener starts the multiplexer HTTP server using a pre-created listener
func (s *Server) StartMuxWithListener(listener net.Listener) error {
	mux := http.NewServeMux()
	// Serve static files from web/static at /static/
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/netstat", s.handleFanoutWebSocket)
	mux.HandleFunc("/api/pid-exe", s.handlePidExe)
	mux.HandleFunc("/metrics", s.handleMetrics)

	muxServer := &http.Server{
		Handler: mux,
	}

	slog.Info("Starting multiplexer HTTP server on listener", "addr", listener.Addr())
	return muxServer.Serve(listener)
}

// handlePidExe resolves a PID to its executable path
func (s *Server) handlePidExe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pidStr := r.URL.Query().Get("pid")
	if pidStr == "" {
		http.Error(w, "Missing pid parameter", http.StatusBadRequest)
		return
	}

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid pid parameter", http.StatusBadRequest)
		return
	}

	exe := s.getOrResolveExe(uint32(pid))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"pid": pidStr,
		"exe": exe,
	})
}

// getOrResolveExe gets executable name from cache or resolves it
func (s *Server) getOrResolveExe(pid uint32) string {
	if pid == 0 {
		return ""
	}

	// Check cache first
	s.pidToExeMu.RLock()
	exe, exists := s.pidToExe[pid]
	s.pidToExeMu.RUnlock()

	if exists {
		return exe
	}

	// Resolve and cache
	exe = getExeFromPID(pid)

	s.pidToExeMu.Lock()
	s.pidToExe[pid] = exe
	s.pidToExeMu.Unlock()

	return exe
}

// getExeFromPID resolves a PID to its executable path
func getExeFromPID(pid uint32) string {
	if pid == 0 {
		return ""
	}

	// Read /proc/<pid>/exe symlink
	exePath := fmt.Sprintf("/host/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		// If we can't read the exe link, try to read cmdline
		cmdlinePath := fmt.Sprintf("/host/proc/%d/cmdline", pid)
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			return ""
		}
		// cmdline is null-separated, first element is the command
		if len(data) > 0 {
			// Find first null byte
			end := 0
			for i, b := range data {
				if b == 0 {
					end = i
					break
				}
			}
			if end == 0 {
				end = len(data)
			}
			cmdline := string(data[:end])
			// Extract just the basename
			return filepath.Base(cmdline)
		}
		return ""
	}

	// Extract just the basename from the full path
	// Also handle deleted executables (marked with " (deleted)")
	target = strings.TrimSuffix(target, " (deleted)")
	return filepath.Base(target)
}

// getNetNS returns the network namespace inode number for a PID
func getNetNS(pid uint32) uint64 {
	if pid == 0 {
		return 0
	}

	// Read /proc/<pid>/ns/net symlink
	netnsPath := fmt.Sprintf("/host/proc/%d/ns/net", pid)
	target, err := os.Readlink(netnsPath)
	if err != nil {
		return 0
	}

	// The symlink looks like "net:[4026531840]"
	// Parse the inode number from the string
	return parseNetNSInode(target)
}

// parseNetNSInode extracts the inode number from a network namespace string
// Input format: "net:[4026531840]"
// Returns: 4026531840
func parseNetNSInode(netns string) uint64 {
	if netns == "" {
		return 0
	}

	// Find the opening bracket
	start := strings.Index(netns, "[")
	if start == -1 {
		return 0
	}
	start++ // Move past the bracket

	// Find the closing bracket
	end := strings.Index(netns[start:], "]")
	if end == -1 {
		return 0
	}

	// Extract the number string
	inodeStr := netns[start : start+end]

	// Parse as uint64
	inode, err := strconv.ParseUint(inodeStr, 10, 64)
	if err != nil {
		return 0
	}

	return inode
}

// getCgroupSlice returns the cgroup slice string for a PID
func getCgroupSlice(pid uint32) string {
	if pid == 0 {
		return ""
	}

	// Read /proc/<pid>/cgroup
	cgroupPath := fmt.Sprintf("/host/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	// Return the first line (there's usually only one line in cgroup v2)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// extractContainerUIDFromCgroup extracts containerd container UID from cgroup slice string
func extractContainerUIDFromCgroup(cgroupSlice string) string {
	// Example: 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podc47f9237_a57c_431c_9daf_c94cbd4cc19b.slice/cri-containerd-507a61ff10abff45ff22f7c78d85b02c6b3e178c7c697b081ab619ae919306cb.scope
	// We want to extract the container UID after "cri-containerd-"

	// Split by "/"
	parts := strings.Split(cgroupSlice, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "cri-containerd-") {
			// Remove "cri-containerd-" prefix and ".scope" suffix
			uid := strings.TrimPrefix(part, "cri-containerd-")
			uid = strings.TrimSuffix(uid, ".scope")
			return uid
		}
	}
	return ""
}

// getSocketInodeForConnection tries to find the socket inode for a connection
// by scanning /proc/<pid>/fd/* for socket file descriptors
func getSocketInodeForConnection(pid uint32, srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol uint8) uint64 {
	if pid == 0 {
		return 0
	}

	// Scan /proc/<pid>/fd/ for socket file descriptors
	fdDir := fmt.Sprintf("/host/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}

	for _, fd := range fds {
		fdPath := filepath.Join(fdDir, fd.Name())
		target, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// Check if it's a socket
		if !strings.HasPrefix(target, "socket:[") {
			continue
		}

		// Extract inode from "socket:[12345]"
		inodeStr := strings.TrimPrefix(target, "socket:[")
		inodeStr = strings.TrimSuffix(inodeStr, "]")
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}

		// We found a socket inode, but we can't easily verify it matches this specific connection
		// without parsing /proc/net/{tcp,udp} files and matching by inode
		// For now, just return the first socket inode we find for this PID
		// This is a best-effort approach
		return inode
	}

	return 0
}

// familyToString converts address family number to string
func familyToString(family uint16) string {
	if name, ok := types.FamilyNames[family]; ok {
		return name
	}
	return fmt.Sprintf("%d", family)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// GetDNSCache returns the server's DNS cache for DNSTap integration
func (s *Server) GetDNSCache() *DNSCache {
	return s.dnsCache
}

// handleIndex serves the main UI
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}

// getHostIPs gets all non-loopback IP addresses from network interfaces
func getHostIPs() ([]string, error) {
	var ips []string

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			slog.Debug("Failed to get addresses for interface", "interface", iface.Name, "error", err)
			continue
		}

		for _, addr := range addrs {
			// Parse IP address from CIDR notation
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			// Skip link-local addresses
			if ip.IsLinkLocalUnicast() {
				continue
			}

			// Add both IPv4 and IPv6 addresses
			if ip.To4() != nil {
				// IPv4
				ips = append(ips, ip.String())
			} else if ip.To16() != nil {
				// IPv6
				ips = append(ips, ip.String())
			}
		}
	}

	return ips, nil
}

// handleContainers handles GET /api/containers
func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	containers := make([]types.ContainerInfo, 0, len(s.containers))
	for _, c := range s.containers {
		containers = append(containers, *c)
	}
	s.mu.RUnlock()

	// Apply filters
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("podName")

	if namespace != "" || podName != "" {
		filtered := make([]types.ContainerInfo, 0)
		for _, c := range containers {
			if c.KubeMetadata == nil {
				continue
			}
			if namespace != "" && c.KubeMetadata.Namespace != namespace {
				continue
			}
			if podName != "" && c.KubeMetadata.PodName != podName {
				continue
			}
			filtered = append(filtered, c)
		}
		containers = filtered
	}

	response := types.ContainerListResponse{
		Timestamp:  time.Now().Format(time.RFC3339),
		Containers: containers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleWebSocket handles WebSocket connections for netstat data
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	slog.Debug("New WebSocket connection request", "remote", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		return
	}
	defer conn.Close()
	slog.Debug("WebSocket connection established", "remote", r.RemoteAddr)

	// Register client
	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()
	slog.Debug("Client registered", "totalClients", len(s.clients))

	// Create mutex for this connection
	s.connMutexesMu.Lock()
	s.connMutexes[conn] = &sync.Mutex{}
	s.connMutexesMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		slog.Debug("Client unregistered", "totalClients", len(s.clients))

		s.connMutexesMu.Lock()
		delete(s.connMutexes, conn)
		s.connMutexesMu.Unlock()
		slog.Debug("WebSocket connection closed", "remote", r.RemoteAddr)
	}()

	// Send current state
	slog.Debug("Sending current state to new client")
	s.sendCurrentState(conn)
	slog.Debug("Current state sent successfully")

	// Keep connection alive and handle client messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			slog.Debug("WebSocket read error, closing connection", "error", err, "remote", r.RemoteAddr)
			break
		}
	}
}

// sendCurrentState sends the current state to a newly connected client
func (s *Server) sendCurrentState(conn *websocket.Conn) {
	s.mu.RLock()
	containers := make([]*types.ContainerInfo, 0, len(s.containers))
	for _, c := range s.containers {
		containers = append(containers, c)
	}
	s.mu.RUnlock()

	// Get mutex for this connection
	s.connMutexesMu.Lock()
	connMutex := s.connMutexes[conn]
	s.connMutexesMu.Unlock()

	if connMutex == nil {
		return
	}

	// Send host information first
	hostEvent := map[string]interface{}{
		"type":      "host.info",
		"timestamp": time.Now().Format(time.RFC3339),
		"nodeName":  s.nodeName,
		"hostIPs":   s.hostIPs,
	}

	slog.Debug("Sending host info to new client",
		"type", "host.info",
		"nodeName", s.nodeName,
		"hostIPCount", len(s.hostIPs),
	)

	connMutex.Lock()
	conn.WriteJSON(hostEvent)
	connMutex.Unlock()

	// Send all containers
	for _, container := range containers {
		event := map[string]interface{}{
			"type":            "container.added",
			"timestamp":       time.Now().Format(time.RFC3339),
			"nodeName":        s.nodeName,
			"containerId":     container.ID,
			"name":            container.Name,
			"pid":             container.PID, // Root process PID
			"podIPs":          container.PodIPs,
			"usesHostNetwork": container.UsesHostNetwork,
		}

		// Unnest kubernetes metadata
		if container.KubeMetadata != nil {
			event["podName"] = container.KubeMetadata.PodName
			event["namespace"] = container.KubeMetadata.Namespace
			event["podUID"] = container.KubeMetadata.PodUID
			event["containerName"] = container.KubeMetadata.ContainerName
			event["labels"] = container.KubeMetadata.Labels
			event["annotations"] = container.KubeMetadata.Annotations
		}

		slog.Debug("Sending container to new client",
			"type", "container.added",
			"podName", container.KubeMetadata.PodName,
			"namespace", container.KubeMetadata.Namespace,
		)

		connMutex.Lock()
		conn.WriteJSON(event)
		connMutex.Unlock()
	}

	slog.Debug("Finished sending current state to new client",
		"containerCount", len(containers),
	)

	// Trigger listening ports scan for all containers
	slog.Debug("Starting listening ports scan for all containers")
	go s.scanAllListeningPorts(conn, connMutex)

	// Note: eBPF doesn't provide a snapshot of existing connections
	// We'll only send new events as they occur
}

// processEvents processes events from containerd and eBPF tracer
func (s *Server) processEvents() {
	// Process containerd events
	go func() {
		for event := range s.ctrdClient.Events() {
			s.handleContainerdEvent(event)
		}
	}()

	// Process eBPF connection events (TCP and UDP)
	go func() {
		for event := range s.tracer.Events() {
			// Get protocol name (empty if unknown)
			protocolName, _ := types.ProtocolNames[event.Protocol]

			// Convert event to entry to get state string and IPs
			entry := (&event).ToConnectionEntry()

			// Get socket inode for logging (only if PID > 0)
			logAttrs := []any{
				"pid", event.PID,
				"tgid", event.TGID,
				"protocol", protocolName,
				"family", familyToString(event.Family),
				"sport", event.Sport,
				"dport", event.Dport,
				"state", entry.State,
				"src", entry.SourceIP,
				"dst", entry.DestIP,
				"sockCookie", fmt.Sprintf("0x%x", event.SockCookie),
			}

			if event.PID > 0 {
				socketInode := getSocketInodeForConnection(event.PID, entry.SourceIP, entry.SourcePort, entry.DestIP, entry.DestPort, event.Protocol)
				if socketInode > 0 {
					logAttrs = append(logAttrs, "inode", socketInode)
				}
			}

			slog.Info("Received eBPF connection event", logAttrs...)
			// Process the connection event
			s.handleConnectionEvent(event)
		}
	}()
}

// incEventCounter increments a counter for the given labels
func (s *Server) incEventCounter(labels ...string) {
	// Use a separator that won't appear in label values
	// State values may contain underscores, so we use "::"
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

// scanListeningPortsForNetNS reads /proc/net/tcp and /proc/net/udp to find listening sockets for a network namespace
func (s *Server) scanListeningPortsForNetNS(pid uint32, netns uint64, containerUID string) {
	if pid == 0 || netns == 0 {
		return
	}

	// Check if we've already scanned this network namespace
	s.scannedNetNSMu.RLock()
	alreadyScanned := s.scannedNetNS[netns]
	s.scannedNetNSMu.RUnlock()

	if alreadyScanned {
		slog.Debug("Network namespace already scanned for listening ports, skipping", "netns", netns, "pid", pid)
		return
	}

	slog.Debug("Scanning listening ports for network namespace", "netns", netns, "pid", pid, "containerUID", containerUID)

	// Mark as scanned before doing the work
	s.scannedNetNSMu.Lock()
	s.scannedNetNS[netns] = true
	s.scannedNetNSMu.Unlock()

	// Get container info (may be nil for host processes)
	s.mu.RLock()
	container := s.containers[containerUID]
	s.mu.RUnlock()

	if containerUID != "" && container == nil {
		slog.Debug("Container not found for UID", "containerUID", containerUID)
		return
	}

	// Scan TCP listening ports
	tcpPorts := s.scanProcNetFile(pid, "tcp")
	slog.Debug("Scanned TCP ports", "netns", netns, "pid", pid, "count", len(tcpPorts))
	for _, port := range tcpPorts {
		// Get executable name for this specific PID
		exe := s.getOrResolveExe(port.PID)
		s.broadcastListeningPort(&types.ListeningPort{
			Protocol: types.ProtocolTCP,
			IP:       port.IP,
			Port:     port.Port,
			PID:      port.PID,
			Process:  exe,
			NetNS:    netns,
		}, containerUID, container)
	}

	// Scan TCP6 listening ports
	tcp6Ports := s.scanProcNetFile(pid, "tcp6")
	slog.Debug("Scanned TCP6 ports", "netns", netns, "pid", pid, "count", len(tcp6Ports))
	for _, port := range tcp6Ports {
		// Get executable name for this specific PID
		exe := s.getOrResolveExe(port.PID)
		s.broadcastListeningPort(&types.ListeningPort{
			Protocol: types.ProtocolTCP,
			IP:       port.IP,
			Port:     port.Port,
			PID:      port.PID,
			Process:  exe,
			NetNS:    netns,
		}, containerUID, container)
	}

	// Scan UDP listening ports
	udpPorts := s.scanProcNetFile(pid, "udp")
	slog.Debug("Scanned UDP ports", "netns", netns, "pid", pid, "count", len(udpPorts))
	for _, port := range udpPorts {
		// Get executable name for this specific PID
		exe := s.getOrResolveExe(port.PID)
		s.broadcastListeningPort(&types.ListeningPort{
			Protocol: types.ProtocolUDP,
			IP:       port.IP,
			Port:     port.Port,
			PID:      port.PID,
			Process:  exe,
			NetNS:    netns,
		}, containerUID, container)
	}

	// Scan UDP6 listening ports
	udp6Ports := s.scanProcNetFile(pid, "udp6")
	slog.Debug("Scanned UDP6 ports", "netns", netns, "pid", pid, "count", len(udp6Ports))
	for _, port := range udp6Ports {
		// Get executable name for this specific PID
		exe := s.getOrResolveExe(port.PID)
		s.broadcastListeningPort(&types.ListeningPort{
			Protocol: types.ProtocolUDP,
			IP:       port.IP,
			Port:     port.Port,
			PID:      port.PID,
			Process:  exe,
			NetNS:    netns,
		}, containerUID, container)
	}
}

// scanProcNetFile parses /proc/<pid>/net/{tcp,tcp6,udp,udp6} for listening sockets
func (s *Server) scanProcNetFile(pid uint32, netType string) []types.ListeningPort {
	var ports []types.ListeningPort

	filePath := fmt.Sprintf("/host/proc/%d/net/%s", pid, netType)
	file, err := os.Open(filePath)
	if err != nil {
		slog.Debug("Failed to open proc net file", "path", filePath, "error", err)
		return ports
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if !scanner.Scan() {
		return ports
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Field 1 is local_address (hex IP:port)
		// Field 2 is rem_address (hex IP:port) - remote/peer address
		// Field 3 is st (state) - 0A = LISTEN for TCP
		// Field 7 is uid
		// Field 9 is inode
		localAddr := fields[1]
		remoteAddr := fields[2]
		state := fields[3]
		uidStr := fields[7]

		// For TCP, only include LISTEN state (0A = 10 decimal = TCPListen)
		// For UDP, all entries are "listening" (state 07)
		if netType == "tcp" || netType == "tcp6" {
			if state != "0A" { // 0A hex = 10 decimal = TCPListen
				continue
			}
		}

		// Parse remote address to check if it's 0.0.0.0:0 or :::0
		remoteParts := strings.Split(remoteAddr, ":")
		if len(remoteParts) != 2 {
			continue
		}

		remoteHexIP := remoteParts[0]
		remoteHexPort := remoteParts[1]

		// Only include entries where remote address is 0.0.0.0:0 or :::0
		// This indicates a listening socket (not an established connection)
		isListening := false
		if netType == "tcp6" || netType == "udp6" {
			// IPv6: check if remote is all zeros (32 zeros)
			if remoteHexIP == "00000000000000000000000000000000" && remoteHexPort == "0000" {
				isListening = true
			}
		} else {
			// IPv4: check if remote is 0.0.0.0:0
			if remoteHexIP == "00000000" && remoteHexPort == "0000" {
				isListening = true
			}
		}

		if !isListening {
			continue
		}

		// Parse local address
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		hexIP := parts[0]
		hexPort := parts[1]

		// Parse port
		portNum, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}

		// Parse IP address
		var ip string
		if netType == "tcp6" || netType == "udp6" {
			// IPv6 address (32 hex chars)
			ip, err = parseHexIPv6(hexIP)
			if err != nil {
				slog.Debug("Failed to parse IPv6 address", "hex", hexIP, "error", err)
				continue
			}
		} else {
			// IPv4 address (8 hex chars)
			ip, err = parseHexIPv4(hexIP)
			if err != nil {
				slog.Debug("Failed to parse IPv4 address", "hex", hexIP, "error", err)
				continue
			}
		}

		// Try to find the PID for this socket by matching inode
		// This is more accurate than using the scanning PID
		inode := fields[9]
		socketPID := s.findPIDForSocket(uidStr, inode)
		if socketPID == 0 {
			slog.Debug("Could not find PID for socket, using scanning PID",
				"inode", inode,
				"scanningPID", pid,
				"ip", ip,
				"port", portNum,
			)
			// Fall back to the scanning PID (container's root PID)
			// This is better than 0, though not perfect for multi-process containers
			socketPID = pid
		} else {
			slog.Debug("Found PID for socket",
				"inode", inode,
				"pid", socketPID,
				"ip", ip,
				"port", portNum,
			)
		}

		ports = append(ports, types.ListeningPort{
			IP:   ip,
			Port: uint16(portNum),
			PID:  socketPID,
		})
	}

	return ports
}

// scanAllListeningPorts scans listening ports for all running containers
// and sends port.listening events to the specified WebSocket connection
func (s *Server) scanAllListeningPorts(conn *websocket.Conn, connMutex *sync.Mutex) {
	s.mu.RLock()
	containers := make([]*types.ContainerInfo, 0, len(s.containers))
	containerUIDs := make([]string, 0, len(s.containers))
	for uid, c := range s.containers {
		containers = append(containers, c)
		containerUIDs = append(containerUIDs, uid)
	}
	s.mu.RUnlock()

	slog.Debug("Scanning listening ports for all containers", "count", len(containers))

	for i, container := range containers {
		if container.PID == 0 {
			continue
		}

		containerUID := containerUIDs[i]
		netns := getNetNS(container.PID)
		if netns == 0 {
			continue
		}

		// Scan TCP listening ports
		tcpPorts := s.scanProcNetFile(container.PID, "tcp")
		for _, port := range tcpPorts {
			exe := s.getOrResolveExe(port.PID)
			s.sendListeningPortToClient(conn, connMutex, &types.ListeningPort{
				Protocol: types.ProtocolTCP,
				IP:       port.IP,
				Port:     port.Port,
				PID:      port.PID,
				Process:  exe,
				NetNS:    netns,
			}, containerUID, container)
		}

		// Scan TCP6 listening ports
		tcp6Ports := s.scanProcNetFile(container.PID, "tcp6")
		for _, port := range tcp6Ports {
			exe := s.getOrResolveExe(port.PID)
			s.sendListeningPortToClient(conn, connMutex, &types.ListeningPort{
				Protocol: types.ProtocolTCP,
				IP:       port.IP,
				Port:     port.Port,
				PID:      port.PID,
				Process:  exe,
				NetNS:    netns,
			}, containerUID, container)
		}

		// Scan UDP listening ports
		udpPorts := s.scanProcNetFile(container.PID, "udp")
		for _, port := range udpPorts {
			exe := s.getOrResolveExe(port.PID)
			s.sendListeningPortToClient(conn, connMutex, &types.ListeningPort{
				Protocol: types.ProtocolUDP,
				IP:       port.IP,
				Port:     port.Port,
				PID:      port.PID,
				Process:  exe,
				NetNS:    netns,
			}, containerUID, container)
		}

		// Scan UDP6 listening ports
		udp6Ports := s.scanProcNetFile(container.PID, "udp6")
		for _, port := range udp6Ports {
			exe := s.getOrResolveExe(port.PID)
			s.sendListeningPortToClient(conn, connMutex, &types.ListeningPort{
				Protocol: types.ProtocolUDP,
				IP:       port.IP,
				Port:     port.Port,
				PID:      port.PID,
				Process:  exe,
				NetNS:    netns,
			}, containerUID, container)
		}
	}

	slog.Debug("Finished scanning listening ports for all containers")
}

// sendListeningPortToClient sends a listening port event to a specific WebSocket client
func (s *Server) sendListeningPortToClient(conn *websocket.Conn, connMutex *sync.Mutex, port *types.ListeningPort, containerUID string, container *types.ContainerInfo) {
	// Get cgroup slice for the PID
	cgroupSlice := getCgroupSlice(port.PID)

	// Try to extract container UID from cgroup if not provided
	extractedContainerUID := containerUID
	if extractedContainerUID == "" && cgroupSlice != "" {
		extractedContainerUID = extractContainerUIDFromCgroup(cgroupSlice)
	}

	// If we have a container UID but no container info, try to get it from containerd
	var containerInfo *types.ContainerInfo
	if extractedContainerUID != "" {
		if container != nil {
			containerInfo = container
		} else {
			// Try to get container info from containerd
			info, err := s.ctrdClient.GetContainerInfoByUID(extractedContainerUID)
			if err != nil {
				slog.Debug("Failed to get container info from containerd",
					"containerUID", extractedContainerUID,
					"error", err)
			} else {
				containerInfo = info
			}
		}
	}

	// Get protocol name string (empty if unknown)
	protocolStr, _ := types.ProtocolNames[port.Protocol]

	wsEvent := map[string]interface{}{
		"type":        "port.listening",
		"timestamp":   time.Now().Format(time.RFC3339),
		"nodeName":    s.nodeName,
		"protocol":    protocolStr, // String: "TCP", "UDP", or empty
		"ip":          port.IP,
		"port":        port.Port,
		"pid":         port.PID,
		"exe":         port.Process,
		"netns":       port.NetNS,
		"cgroupSlice": cgroupSlice,
	}

	if containerInfo != nil && containerInfo.KubeMetadata != nil {
		wsEvent["containerUID"] = extractedContainerUID
		wsEvent["podName"] = containerInfo.KubeMetadata.PodName
		wsEvent["namespace"] = containerInfo.KubeMetadata.Namespace
		wsEvent["containerName"] = containerInfo.KubeMetadata.ContainerName
	}

	connMutex.Lock()
	conn.WriteJSON(wsEvent)
	connMutex.Unlock()
}

// findPIDForSocket tries to find the PID that owns a socket by scanning /proc/*/fd/
// This is a best-effort approach and may not always succeed
func (s *Server) findPIDForSocket(uid string, inode string) uint32 {
	// Scan /proc for processes
	entries, err := os.ReadDir("/host/proc")
	if err != nil {
		return 0
	}

	targetSocket := fmt.Sprintf("socket:[%s]", inode)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a number (PID)
		pidStr := entry.Name()
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}

		// Scan this process's file descriptors
		fdDir := fmt.Sprintf("/host/proc/%s/fd", pidStr)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			fdPath := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}

			if target == targetSocket {
				return uint32(pid)
			}
		}
	}

	return 0
}

// parseHexIPv4 converts hex IPv4 address from /proc/net files (little-endian) to string
func parseHexIPv4(hexIP string) (string, error) {
	if len(hexIP) != 8 {
		return "", fmt.Errorf("invalid hex IP length: %d", len(hexIP))
	}

	val, err := strconv.ParseUint(hexIP, 16, 32)
	if err != nil {
		return "", err
	}

	// Convert little-endian to IP
	ip := net.IPv4(
		byte(val),
		byte(val>>8),
		byte(val>>16),
		byte(val>>24),
	)
	return ip.String(), nil
}

// parseHexIPv6 converts hex IPv6 address from /proc/net files to string
func parseHexIPv6(hexIP string) (string, error) {
	if len(hexIP) != 32 {
		return "", fmt.Errorf("invalid hex IPv6 length: %d", len(hexIP))
	}

	// Parse 4 32-bit words in little-endian format
	var bytes [16]byte
	for i := 0; i < 4; i++ {
		word := hexIP[i*8 : (i+1)*8]
		val, err := strconv.ParseUint(word, 16, 32)
		if err != nil {
			return "", err
		}
		// Convert little-endian word to bytes
		bytes[i*4] = byte(val)
		bytes[i*4+1] = byte(val >> 8)
		bytes[i*4+2] = byte(val >> 16)
		bytes[i*4+3] = byte(val >> 24)
	}

	ip := net.IP(bytes[:])
	return ip.String(), nil
}

// handleContainerdEvent processes containerd events
func (s *Server) handleContainerdEvent(event *types.Event) {
	switch event.Type {
	case "container.added":
		s.mu.Lock()
		var podUID string
		if event.Container.KubeMetadata != nil {
			podUID = event.Container.KubeMetadata.PodUID
			s.containers[podUID] = event.Container
		}
		s.mu.Unlock()

		// Update PID to container UID mapping
		if event.Container.PID > 0 && podUID != "" {
			s.pidMu.Lock()
			s.pidToContainerUID[event.Container.PID] = podUID
			s.pidMu.Unlock()
			slog.Debug("Added PID to container mapping",
				"pid", event.Container.PID,
				"containerUID", podUID,
				"podName", event.Container.KubeMetadata.PodName,
				"namespace", event.Container.KubeMetadata.Namespace,
			)
		}

		wsEvent := map[string]interface{}{
			"type":            "container.added",
			"timestamp":       time.Now().Format(time.RFC3339),
			"nodeName":        s.nodeName,
			"containerId":     event.Container.ID,
			"name":            event.Container.Name,
			"pid":             event.Container.PID, // Root process PID
			"podIPs":          event.Container.PodIPs,
			"usesHostNetwork": event.Container.UsesHostNetwork,
		}

		var podName, namespace string
		// Unnest kubernetes metadata
		if event.Container.KubeMetadata != nil {
			wsEvent["podName"] = event.Container.KubeMetadata.PodName
			wsEvent["namespace"] = event.Container.KubeMetadata.Namespace
			wsEvent["podUID"] = event.Container.KubeMetadata.PodUID
			wsEvent["containerName"] = event.Container.KubeMetadata.ContainerName
			wsEvent["labels"] = event.Container.KubeMetadata.Labels
			wsEvent["annotations"] = event.Container.KubeMetadata.Annotations
			podName = event.Container.KubeMetadata.PodName
			namespace = event.Container.KubeMetadata.Namespace
		}

		slog.Debug("Broadcasting container added",
			"type", "container.added",
			"podName", podName,
			"namespace", namespace,
			"pid", event.Container.PID,
			"podIPs", event.Container.PodIPs,
			"usesHostNetwork", event.Container.UsesHostNetwork,
		)

		// Non-blocking send to prevent deadlock
		select {
		case s.broadcast <- wsEvent:
		default:
			slog.Warn("Broadcast channel full, dropping container.added event")
		}

	case "container.deleted":
		s.mu.Lock()
		var podUID string
		var pid uint32
		for uid, c := range s.containers {
			if c.ID == event.Container.ID {
				podUID = uid
				pid = c.PID
				delete(s.containers, uid)
				break
			}
		}
		s.mu.Unlock()

		// Remove PID to container UID mapping and related caches
		if pid > 0 {
			s.pidMu.Lock()
			delete(s.pidToContainerUID, pid)
			s.pidMu.Unlock()

			s.pidToExeMu.Lock()
			delete(s.pidToExe, pid)
			s.pidToExeMu.Unlock()

			slog.Debug("Removed PID mappings and caches",
				"pid", pid,
				"containerUID", podUID,
			)
		}

		if podUID != "" {
			wsEvent := map[string]interface{}{
				"type":         "container.deleted",
				"timestamp":    time.Now().Format(time.RFC3339),
				"nodeName":     s.nodeName,
				"containerUID": podUID,
			}

			slog.Debug("Broadcasting container deleted",
				"type", "container.deleted",
				"containerUID", podUID,
			)

			// Non-blocking send to prevent deadlock
			select {
			case s.broadcast <- wsEvent:
			default:
				slog.Warn("Broadcast channel full, dropping container.deleted event")
			}
		}
	}
}

// handleConnectionEvent processes connection events from eBPF (both TCP and UDP)
func (s *Server) handleConnectionEvent(event types.ConnEvent) {
	entry := (&event).ToConnectionEntry()

	// Try to get socket inode for this connection
	socketInode := getSocketInodeForConnection(event.PID, entry.SourceIP, entry.SourcePort, entry.DestIP, entry.DestPort, event.Protocol)

	// Log at TRACE level with detailed connection info
	slog.Log(nil, slog.Level(-8), "Processing connection event",
		"pid", event.PID,
		"tgid", event.TGID,
		"protocol", event.Protocol,
		"family", familyToString(event.Family),
		"src", entry.SourceIP,
		"srcPort", entry.SourcePort,
		"dst", entry.DestIP,
		"dstPort", entry.DestPort,
		"state", entry.State,
		"socketInode", socketInode,
	)

	// Log warning if PID is 0 - this indicates kernel-initiated connection or softirq context
	if event.PID == 0 {
		slog.Debug("Connection event with PID=0 (kernel context or softirq)",
			"tgid", event.TGID,
			"protocol", event.Protocol,
			"src", entry.SourceIP,
			"srcPort", entry.SourcePort,
			"dst", entry.DestIP,
			"dstPort", entry.DestPort,
			"state", entry.State,
			"socketInode", socketInode,
		)
	}

	// Increment metrics using protocol and family constants
	protocol := entry.Protocol
	family := event.Family
	state := entry.State

	// Total events by protocol and family
	s.incEventCounter("total", strconv.FormatUint(uint64(protocol), 10), strconv.FormatUint(uint64(family), 10))

	// Events by state (for both TCP and UDP)
	s.incEventCounter("state", strconv.FormatUint(uint64(protocol), 10), strconv.FormatUint(uint64(family), 10), state)

	// Find container by PID using fast lookup map
	var containerUID string
	var containerInfo *types.ContainerInfo

	if event.PID > 0 {
		// Fast PID lookup
		s.pidMu.RLock()
		containerUID = s.pidToContainerUID[event.PID]
		s.pidMu.RUnlock()

		if containerUID != "" {
			// Get full container info
			s.mu.RLock()
			containerInfo = s.containers[containerUID]
			s.mu.RUnlock()

			if containerInfo != nil {
				slog.Log(nil, slog.Level(-8), "Matched connection to container via PID",
					"pid", event.PID,
					"containerUID", containerUID,
					"podName", containerInfo.KubeMetadata.PodName,
					"namespace", containerInfo.KubeMetadata.Namespace,
					"protocol", event.Protocol,
				)
			}
		} else {
			slog.Log(nil, slog.Level(-8), "Connection from host process (not in container)",
				"pid", event.PID,
				"protocol", event.Protocol,
			)
		}

		// Get network namespace and scan for listening ports if not already scanned
		netns := getNetNS(event.PID)
		if netns != 0 {
			go s.scanListeningPortsForNetNS(event.PID, netns, containerUID)
		}
	} else {
		// PID is 0 - this is a kernel-initiated connection or softirq context
		// We cannot determine the container from PID alone
		// The connection will still be visible in the UI but without container metadata
		slog.Log(nil, slog.Level(-8), "Cannot determine container for PID=0 connection",
			"protocol", event.Protocol,
			"family", familyToString(event.Family),
			"src", entry.SourceIP,
			"srcPort", entry.SourcePort,
			"dst", entry.DestIP,
			"dstPort", entry.DestPort,
		)
	}

	// Get protocol name string (empty if unknown)
	protocolStr, _ := types.ProtocolNames[event.Protocol]

	wsEvent := map[string]interface{}{
		"type":       "connection.event",
		"timestamp":  time.Now().Format(time.RFC3339),
		"nodeName":   s.nodeName,
		"protocol":   protocolStr, // String: "TCP", "UDP", or empty
		"sourceIP":   entry.SourceIP,
		"sourcePort": entry.SourcePort,
		"destIP":     entry.DestIP,
		"destPort":   entry.DestPort,
		"state":      entry.State,      // State name as string (ESTABLISHED, CLOSE, etc)
		"pid":        event.PID,        // uint32 PID
		"sockCookie": event.SockCookie, // uint64 socket cookie for connection tracking
	}

	slog.Debug("Prepared WebSocket event",
		"type", "connection.event",
		"protocol", event.Protocol,
		"sourceIP", entry.SourceIP,
		"sourcePort", entry.SourcePort,
		"destIP", entry.DestIP,
		"destPort", entry.DestPort,
		"state", event.State,
		"pid", event.PID,
		"clientCount", len(s.clients),
	)

	// Add executable name from cache if available
	if event.PID > 0 {
		exe := s.getOrResolveExe(event.PID)
		if exe != "" {
			wsEvent["exe"] = exe
		}
	}

	// Add container information if matched
	if containerUID != "" {
		wsEvent["containerUID"] = containerUID
		if containerInfo != nil && containerInfo.KubeMetadata != nil {
			wsEvent["podName"] = containerInfo.KubeMetadata.PodName
			wsEvent["namespace"] = containerInfo.KubeMetadata.Namespace
			wsEvent["podUID"] = containerInfo.KubeMetadata.PodUID
		}
	}

	// Non-blocking send to prevent deadlock
	select {
	case s.broadcast <- wsEvent:
		slog.Debug("Broadcasting connection event",
			"type", "connection.event",
			"protocol", entry.Protocol,
			"src", entry.SourceIP,
			"srcPort", entry.SourcePort,
			"dst", entry.DestIP,
			"dstPort", entry.DestPort,
			"state", entry.State,
			"pid", event.PID,
			"containerUID", containerUID,
			"broadcastChannelSize", len(s.broadcast),
		)
	default:
		slog.Warn("Broadcast channel full, dropping connection event",
			"channelCapacity", cap(s.broadcast),
			"protocol", entry.Protocol,
			"src", entry.SourceIP,
			"dst", entry.DestIP,
		)
	}
}

// broadcastListeningPort sends a listening port event
func (s *Server) broadcastListeningPort(port *types.ListeningPort, containerUID string, container *types.ContainerInfo) {
	// Create unique key for this listening port
	// Use node name, protocol, IP, port, and netns inode to uniquely identify
	portKey := fmt.Sprintf("%s:%d:%s:%d:%d", s.nodeName, port.Protocol, port.IP, port.Port, port.NetNS)

	// Check if we've already broadcast this port
	s.broadcastedPortsMu.RLock()
	alreadyBroadcast := s.broadcastedPorts[portKey]
	s.broadcastedPortsMu.RUnlock()

	if alreadyBroadcast {
		slog.Log(nil, slog.Level(-8), "Skipping already broadcast listening port",
			"protocol", port.Protocol,
			"ip", port.IP,
			"port", port.Port,
			"netns", port.NetNS,
		)
		return
	}

	// Mark as broadcast
	s.broadcastedPortsMu.Lock()
	s.broadcastedPorts[portKey] = true
	s.broadcastedPortsMu.Unlock()

	// Get cgroup slice for the PID
	cgroupSlice := getCgroupSlice(port.PID)

	// Try to extract container UID from cgroup if not provided
	extractedContainerUID := containerUID
	if extractedContainerUID == "" && cgroupSlice != "" {
		extractedContainerUID = extractContainerUIDFromCgroup(cgroupSlice)
	}

	// If we have a container UID but no container info, try to get it from containerd
	var containerInfo *types.ContainerInfo
	if extractedContainerUID != "" {
		if container != nil {
			containerInfo = container
		} else {
			// Try to get container info from containerd
			info, err := s.ctrdClient.GetContainerInfoByUID(extractedContainerUID)
			if err != nil {
				slog.Debug("Failed to get container info from containerd",
					"containerUID", extractedContainerUID,
					"error", err)
			} else {
				containerInfo = info
			}
		}
	}

	// Get protocol name string (empty if unknown)
	protocolName, _ := types.ProtocolNames[port.Protocol]

	wsEvent := map[string]interface{}{
		"type":        "port.listening",
		"timestamp":   time.Now().Format(time.RFC3339),
		"nodeName":    s.nodeName,
		"protocol":    protocolName, // String: "TCP", "UDP", or empty
		"ip":          port.IP,
		"port":        port.Port,
		"pid":         port.PID,
		"exe":         port.Process,
		"netns":       port.NetNS,
		"cgroupSlice": cgroupSlice,
	}

	var podName, namespace, containerName string
	if containerInfo != nil && containerInfo.KubeMetadata != nil {
		wsEvent["containerUID"] = extractedContainerUID
		wsEvent["podName"] = containerInfo.KubeMetadata.PodName
		wsEvent["namespace"] = containerInfo.KubeMetadata.Namespace
		wsEvent["containerName"] = containerInfo.KubeMetadata.ContainerName
		podName = containerInfo.KubeMetadata.PodName
		namespace = containerInfo.KubeMetadata.Namespace
		containerName = containerInfo.KubeMetadata.ContainerName
	}

	slog.Debug("Broadcasting listening port",
		"type", "port.listening",
		"protocol", port.Protocol,
		"ip", port.IP,
		"port", port.Port,
		"pid", port.PID,
		"exe", port.Process,
		"netns", port.NetNS,
		"cgroupSlice", cgroupSlice,
		"podName", podName,
		"namespace", namespace,
		"containerName", containerName,
		"containerUID", extractedContainerUID,
	)

	select {
	case s.broadcast <- wsEvent:
	default:
		slog.Warn("Broadcast channel full, dropping port.listening event")
	}
}

// handleBroadcast broadcasts events to all connected WebSocket clients
func (s *Server) handleBroadcast() {
	for event := range s.broadcast {
		s.clientsMu.RLock()
		clients := make([]*websocket.Conn, 0, len(s.clients))
		for client := range s.clients {
			clients = append(clients, client)
		}
		s.clientsMu.RUnlock()

		slog.Debug("Broadcasting event to clients",
			"eventType", event.(map[string]interface{})["type"],
			"clientCount", len(clients),
		)

		for _, client := range clients {
			// Get mutex for this connection
			s.connMutexesMu.Lock()
			connMutex := s.connMutexes[client]
			s.connMutexesMu.Unlock()

			if connMutex == nil {
				continue
			}

			// Try to send with a timeout to prevent blocking
			go func(c *websocket.Conn, m *sync.Mutex, ev interface{}) {
				m.Lock()
				defer m.Unlock()

				// Use a channel with timeout for write
				writeDone := make(chan error, 1)
				go func() {
					writeDone <- c.WriteJSON(ev)
				}()

				select {
				case err := <-writeDone:
					if err != nil {
						slog.Error("WebSocket write error", "error", err)
						c.Close()
						s.clientsMu.Lock()
						delete(s.clients, c)
						s.clientsMu.Unlock()

						s.connMutexesMu.Lock()
						delete(s.connMutexes, c)
						s.connMutexesMu.Unlock()
					}
				case <-time.After(100 * time.Millisecond):
					slog.Debug("WebSocket write timeout, skipping")
				}
			}(client, connMutex, event)
		}
	}
}

// handleFanoutRedirect redirects to the multiplexer port for fanout connections
func (s *Server) handleFanoutRedirect(w http.ResponseWriter, r *http.Request) {
	// Get the current host and port
	host := r.Host
	// Replace port 5280 with 6280
	// This is a simple approach - in production you might want to be more robust
	redirectHost := strings.Replace(host, ":5280", ":6280", 1)
	if redirectHost == host {
		// If port wasn't replaced, try to add :6280
		if !strings.Contains(host, ":") {
			redirectHost = host + ":6280"
		} else {
			// Replace the last part after : with 6280
			lastColon := strings.LastIndex(host, ":")
			redirectHost = host[:lastColon] + ":6280"
		}
	}

	// Redirect to the multiplexer port
	redirectURL := fmt.Sprintf("http://%s/conntrack", redirectHost)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// handleMetrics serves Prometheus metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()

	// Write all counters
	for key, counter := range s.eventCounters {
		// Parse key format: prefix::protocol::family or prefix::protocol::family::state
		parts := strings.Split(key, "::")
		if len(parts) < 3 {
			continue
		}
		prefix := parts[0]
		protocol := parts[1]
		family := parts[2]

		var metricName string
		var labels string

		if prefix == "total" {
			metricName = "netstatd_events_total"
			labels = fmt.Sprintf(`protocol="%s",family="%s"`, protocol, family)
		} else if prefix == "state" && len(parts) >= 4 {
			metricName = "netstatd_events_by_state"
			// The state is the remaining part
			state := strings.Join(parts[3:], "::")
			labels = fmt.Sprintf(`protocol="%s",family="%s",state="%s"`, protocol, family, state)
		} else {
			continue
		}

		value := counter.Load()
		fmt.Fprintf(w, "%s{%s} %d\n", metricName, labels, value)
	}
}

// handleFanoutWebSocket handles the fanout WebSocket endpoint that connects to all pods
func (s *Server) handleFanoutWebSocket(w http.ResponseWriter, r *http.Request) {
	slog.Debug("New fanout WebSocket connection request", "remote", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		return
	}
	defer conn.Close()
	slog.Debug("Fanout WebSocket connection established", "remote", r.RemoteAddr)

	// Get service name from environment
	serviceName := os.Getenv("FANOUT_SERVICE")
	if serviceName == "" {
		slog.Error("FANOUT_SERVICE environment variable not set")
		conn.WriteJSON(map[string]string{
			"error": "FANOUT_SERVICE environment variable not set",
		})
		return
	}
	slog.Debug("Using service name for fanout", "serviceName", serviceName)

	// Hardcoded fanout target port (single-pod port)
	const port = "5280"
	slog.Debug("Fanout target port", "port", port)

	// Resolve all pod IPs via headless service (assumes same namespace)
	slog.Debug("Resolving pod IPs via headless service")
	podIPs, err := s.resolvePodIPs(serviceName)
	if err != nil {
		slog.Error("Failed to resolve pod IPs", "error", err)
		conn.WriteJSON(map[string]string{
			"error": fmt.Sprintf("Failed to resolve pods: %v", err),
		})
		return
	}

	slog.Info("Fanout: discovered pod IPs", "count", len(podIPs), "ips", podIPs)

	// Create context for managing all pod connections
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to aggregate events from all pods
	aggregatedEvents := make(chan interface{}, 1000)
	slog.Debug("Created aggregated events channel")

	// Connect to each pod
	var wg sync.WaitGroup
	slog.Debug("Starting connections to individual pods", "podCount", len(podIPs))
	for _, podIP := range podIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			s.connectToPod(ctx, ip, port, aggregatedEvents)
		}(podIP)
	}
	slog.Debug("All pod connection goroutines started")

	// Close aggregated channel when all pod connections are done
	go func() {
		wg.Wait()
		close(aggregatedEvents)
		slog.Debug("All pod connections finished, aggregated channel closed")
	}()

	// Forward aggregated events to client with mutex protection
	writeMutex := &sync.Mutex{}
	go func() {
		slog.Debug("Starting aggregated events forwarding to client")
		for event := range aggregatedEvents {
			writeMutex.Lock()
			err := conn.WriteJSON(event)
			writeMutex.Unlock()

			if err != nil {
				slog.Error("Fanout write error", "error", err)
				cancel()
				return
			}
		}
		slog.Debug("Aggregated events forwarding finished")
	}()

	// Keep connection alive and handle client messages
	slog.Debug("Fanout WebSocket connection ready for client messages")
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			slog.Debug("Fanout WebSocket read error, closing connection", "error", err)
			cancel()
			break
		}
	}
}

// resolvePodIPs resolves all pod IPs for a headless service in the same namespace
func (s *Server) resolvePodIPs(serviceName string) ([]string, error) {
	// Construct the service name (assumes same namespace, so just use service name)
	// Kubernetes DNS will resolve this within the same namespace
	serviceDNS := serviceName

	// Perform DNS lookup to get all pod IPs
	slog.Debug("Fanout: resolving DNS for service", "service", serviceDNS)
	ips, err := net.LookupIP(serviceDNS)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", serviceDNS, err)
	}

	slog.Debug("Fanout: DNS lookup returned IPs", "count", len(ips))

	var podIPs []string
	for _, ip := range ips {
		// Include both IPv4 and IPv6 addresses (dual stack)
		podIPs = append(podIPs, ip.String())
	}

	if len(podIPs) == 0 {
		return nil, fmt.Errorf("no pod IPs found for service %s", serviceDNS)
	}

	slog.Debug("Fanout: resolved pod IPs", "ips", podIPs)
	return podIPs, nil
}

// connectToPod connects to a single pod's WebSocket endpoint
func (s *Server) connectToPod(ctx context.Context, podIP string, port string, events chan<- interface{}) {
	// Wrap IPv6 addresses in brackets
	host := podIP
	if net.ParseIP(podIP).To4() == nil {
		// This is an IPv6 address
		host = fmt.Sprintf("[%s]", podIP)
	}
	wsURL := fmt.Sprintf("ws://%s:%s/netstat", host, port)

	slog.Debug("Fanout: connecting to pod", "url", wsURL)

	// Create WebSocket dialer with timeout
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		slog.Error("Failed to connect to pod", "podIP", podIP, "error", err)
		return
	}
	defer conn.Close()

	slog.Debug("Fanout: connected to pod", "podIP", podIP)

	// Read messages from pod and forward to aggregated channel
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var event map[string]interface{}
			err := conn.ReadJSON(&event)
			if err != nil {
				slog.Error("Error reading from pod", "podIP", podIP, "error", err)
				return
			}

			// Add pod IP to event metadata
			event["podIP"] = podIP

			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}
