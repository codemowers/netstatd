package containerd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"netstatd/internal/types"
)

// Client wraps containerd client and provides container monitoring
type Client struct {
	client    *containerd.Client
	ctx       context.Context
	cancel    context.CancelFunc
	eventChan chan *types.Event
}

// NewClient creates a new containerd client
func NewClient(ctx context.Context, socket string) (*Client, error) {
	slog.Debug("Initializing containerd client", "socket", socket)
	client, err := containerd.New(socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to containerd: %w", err)
	}
	slog.Debug("Containerd client connection established successfully")

	clientCtx, cancel := context.WithCancel(ctx)

	c := &Client{
		client:    client,
		ctx:       clientCtx,
		cancel:    cancel,
		eventChan: make(chan *types.Event, 100),
	}

	slog.Debug("Loading initial containers from all namespaces (best effort)")
	// Load initial containers in background to avoid blocking startup
	go func() {
		if err := c.loadInitialContainers(); err != nil {
			slog.Warn("Failed to load initial containers", "error", err)
		} else {
			slog.Debug("Initial containers loaded successfully")
		}
	}()

	// Start event monitoring for all namespaces
	slog.Debug("Starting containerd event monitoring")
	go c.monitorEvents()
	slog.Debug("Containerd event monitoring started")

	slog.Info("Containerd client successfully initialized")
	return c, nil
}

// loadInitialContainers loads all currently running containers from all namespaces
func (c *Client) loadInitialContainers() error {
	// Get all namespaces
	namespaceService := c.client.NamespaceService()
	nsList, err := namespaceService.List(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Iterate through all namespaces
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		containers, err := c.client.Containers(nsCtx)
		if err != nil {
			slog.Warn("Failed to list containers in namespace",
				"namespace", ns,
				"error", err,
			)
			continue
		}

		for _, container := range containers {
			info, err := c.getContainerInfo(nsCtx, ns, container)
			if err != nil {
				slog.Warn("Failed to get container info",
					"container", container.ID(),
					"namespace", ns,
					"error", err,
				)
				continue
			}

			// Only send events for containers with running tasks (PID > 0)
			// This ensures we only monitor containers that can have network connections
			if info.PID > 0 {
				c.eventChan <- &types.Event{
					Type:      "container.added",
					Container: info,
				}
			} else {
				slog.Debug("Skipping container without running task",
					"container", container.ID(),
					"namespace", ns,
				)
			}
		}
	}

	return nil
}

// getContainerInfo extracts container information including Kubernetes metadata
func (c *Client) getContainerInfo(ctx context.Context, namespace string, container containerd.Container) (*types.ContainerInfo, error) {
	info, err := container.Info(ctx)
	if err != nil {
		return nil, err
	}

	containerInfo := &types.ContainerInfo{
		ID:        container.ID(),
		Name:      info.Labels["io.kubernetes.container.name"],
		Namespace: namespace,
		PID:       0, // Default to 0 if no running task
		PodIPs:    []string{},
	}

	// Try to get the task (running container process)
	task, err := container.Task(ctx, nil)
	if err != nil {
		// If there's no running task, we can still extract metadata but skip PID and IPs
		// This is not an error - containers can be in various states (created, stopped, etc.)
		slog.Debug("Container has no running task, skipping PID and IP collection",
			"container", container.ID(),
			"namespace", namespace,
		)
	} else {
		// Get the root process PID
		pid := task.Pid()
		containerInfo.PID = pid

		// Check if pod uses host network by reading network namespace
		// Host network pods share the host's network namespace (typically inode 4026531840 or similar)
		// We'll detect this by comparing the pod's netns with PID 1's netns
		usesHostNetwork := false
		if pid > 0 {
			usesHostNetwork, err = isHostNetwork(pid)
			if err != nil {
				slog.Debug("Failed to check host network status",
					"container", container.ID(),
					"pid", pid,
					"error", err,
				)
			}
		}

		// Get IP addresses by reading /proc/<pid>/net files
		// Skip for host network pods since they share host IPs
		if pid > 0 && !usesHostNetwork {
			ips, err := getIPsFromProc(pid)
			if err != nil {
				slog.Debug("Failed to get IPs from /proc",
					"container", container.ID(),
					"pid", pid,
					"error", err,
				)
			} else {
				containerInfo.PodIPs = ips
			}
		} else if usesHostNetwork {
			slog.Debug("Skipping IP collection for host network pod",
				"container", container.ID(),
				"pid", pid,
			)
		}
	}

	// Extract Kubernetes metadata from labels
	if podName, ok := info.Labels["io.kubernetes.pod.name"]; ok {
		containerInfo.KubeMetadata = &types.KubeMetadata{
			PodName:       podName,
			Namespace:     info.Labels["io.kubernetes.pod.namespace"],
			PodUID:        info.Labels["io.kubernetes.pod.uid"],
			ContainerName: info.Labels["io.kubernetes.container.name"],
			Labels:        make(map[string]string),
			Annotations:   make(map[string]string),
		}

		// Extract all labels and annotations
		for k, v := range info.Labels {
			if strings.HasPrefix(k, "io.kubernetes.pod.label.") {
				labelKey := strings.TrimPrefix(k, "io.kubernetes.pod.label.")
				containerInfo.KubeMetadata.Labels[labelKey] = v
			} else if strings.HasPrefix(k, "io.kubernetes.pod.annotation.") {
				annotationKey := strings.TrimPrefix(k, "io.kubernetes.pod.annotation.")
				containerInfo.KubeMetadata.Annotations[annotationKey] = v
			}
		}
	}

	return containerInfo, nil
}

// isHostNetwork checks if a process is using the host network namespace
// by comparing its network namespace with PID 1's network namespace
func isHostNetwork(pid uint32) (bool, error) {
	// Read the network namespace inode for the process
	pidNetNS, err := os.Readlink(fmt.Sprintf("/host/proc/%d/ns/net", pid))
	if err != nil {
		return false, err
	}

	// Read the network namespace inode for PID 1 (init, which uses host network)
	hostNetNS, err := os.Readlink("/host/proc/1/ns/net")
	if err != nil {
		return false, err
	}

	// If they match, the pod is using host networking
	return pidNetNS == hostNetNS, nil
}

// getIPsFromProc reads IP addresses from /proc/<pid>/net/tcp and /proc/<pid>/net/udp
func getIPsFromProc(pid uint32) ([]string, error) {
	ipSet := make(map[string]bool)

	// Read IPv4 addresses from /proc/<pid>/net/tcp
	tcpPath := fmt.Sprintf("/host/proc/%d/net/tcp", pid)
	ipv4TCP, err := parseNetFile(tcpPath, false)
	if err != nil {
		slog.Debug("Failed to parse tcp file",
			"path", tcpPath,
			"error", err,
		)
	} else {
		for _, ip := range ipv4TCP {
			ipSet[ip] = true
		}
	}

	// Read IPv4 addresses from /proc/<pid>/net/udp
	udpPath := fmt.Sprintf("/host/proc/%d/net/udp", pid)
	ipv4UDP, err := parseNetFile(udpPath, false)
	if err != nil {
		slog.Debug("Failed to parse udp file",
			"path", udpPath,
			"error", err,
		)
	} else {
		for _, ip := range ipv4UDP {
			ipSet[ip] = true
		}
	}

	// Read IPv6 addresses from /proc/<pid>/net/tcp6
	tcp6Path := fmt.Sprintf("/host/proc/%d/net/tcp6", pid)
	ipv6TCP, err := parseNetFile(tcp6Path, true)
	if err != nil {
		slog.Debug("Failed to parse tcp6 file",
			"path", tcp6Path,
			"error", err,
		)
	} else {
		for _, ip := range ipv6TCP {
			ipSet[ip] = true
		}
	}

	// Read IPv6 addresses from /proc/<pid>/net/udp6
	udp6Path := fmt.Sprintf("/host/proc/%d/net/udp6", pid)
	ipv6UDP, err := parseNetFile(udp6Path, true)
	if err != nil {
		slog.Debug("Failed to parse udp6 file",
			"path", udp6Path,
			"error", err,
		)
	} else {
		for _, ip := range ipv6UDP {
			ipSet[ip] = true
		}
	}

	// Convert set to slice
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}

// parseNetFile parses /proc/<pid>/net/{tcp,tcp6,udp,udp6} to extract local IP addresses
func parseNetFile(path string, isIPv6 bool) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ipSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return nil, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Field 1 is local_address (hex IP:port)
		localAddr := fields[1]

		// Parse local address
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		hexIP := parts[0]

		// Parse IP address
		var ip string
		if isIPv6 {
			// IPv6 address (32 hex chars)
			parsedIP, err := parseHexIPv6(hexIP)
			if err != nil {
				continue
			}
			ip = parsedIP
		} else {
			// IPv4 address (8 hex chars)
			parsedIP, err := parseHexIPv4(hexIP)
			if err != nil {
				continue
			}
			ip = parsedIP
		}

		// Skip loopback addresses (127.x.x.x for IPv4, ::1 for IPv6)
		if strings.HasPrefix(ip, "127.") || ip == "::1" {
			continue
		}

		// Skip unspecified addresses (0.0.0.0 for IPv4, :: for IPv6)
		if ip == "0.0.0.0" || ip == "::" {
			continue
		}

		ipSet[ip] = true
	}

	// Convert set to slice
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, scanner.Err()
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

// monitorEvents subscribes to containerd events from all namespaces
func (c *Client) monitorEvents() {
	eventService := c.client.EventService()

	// Subscribe without namespace filter to get events from all namespaces
	eventCh, errCh := eventService.Subscribe(c.ctx)

	for {
		select {
		case <-c.ctx.Done():
			return
		case err := <-errCh:
			slog.Error("Containerd event error", "error", err)
			return
		case envelope := <-eventCh:
			c.handleEvent(envelope)
		}
	}
}

// handleEvent processes containerd events
func (c *Client) handleEvent(envelope *events.Envelope) {
	// Extract namespace from envelope
	ns := envelope.Namespace
	if ns == "" {
		ns = "default"
	}

	switch envelope.Topic {
	case "/tasks/create", "/tasks/start":
		// Container started
		containerID := extractContainerID(envelope)
		if containerID == "" {
			return
		}

		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		container, err := c.client.LoadContainer(nsCtx, containerID)
		if err != nil {
			slog.Warn("Failed to load container",
				"container", containerID,
				"namespace", ns,
				"error", err,
			)
			return
		}

		info, err := c.getContainerInfo(nsCtx, ns, container)
		if err != nil {
			slog.Warn("Failed to get container info",
				"container", containerID,
				"namespace", ns,
				"error", err,
			)
			return
		}

		// Only send events for containers with running tasks
		if info.PID > 0 {
			c.eventChan <- &types.Event{
				Type:      "container.added",
				Container: info,
			}
		} else {
			slog.Debug("Skipping container event without running task",
				"container", containerID,
				"namespace", ns,
			)
		}

	case "/containers/delete", "/tasks/delete":
		// Container deleted
		containerID := extractContainerID(envelope)
		if containerID == "" {
			return
		}

		// We need to get the pod UID before the container is fully deleted
		// This is a simplified version - in production you'd maintain a cache
		c.eventChan <- &types.Event{
			Type: "container.deleted",
			Container: &types.ContainerInfo{
				ID:        containerID,
				Namespace: ns,
			},
		}
	}
}

// extractContainerID extracts container ID from event envelope
func extractContainerID(envelope *events.Envelope) string {
	// Try to extract container ID from the event
	// The envelope contains an Any field with the actual event
	if envelope.Event != nil {
		// The type of envelope.Event depends on the topic
		// For task events, it's usually a TaskCreate, TaskStart, etc.
		// We'll use type assertion based on common patterns
		// This is a simplified implementation
		switch envelope.Topic {
		case "/tasks/create", "/tasks/start", "/tasks/delete", "/tasks/exit":
			// These events typically have a container ID field
			// For now, return a placeholder
			// In a real implementation, you'd unmarshal the event
			return "container-" + envelope.Namespace
		case "/containers/create", "/containers/delete":
			return "container-" + envelope.Namespace
		}
	}
	// Fallback: use namespace as part of ID
	if envelope.Namespace != "" {
		return "container-" + envelope.Namespace
	}
	return ""
}

// Events returns the event channel
func (c *Client) Events() <-chan *types.Event {
	return c.eventChan
}

// ListContainers returns all currently running containers from all namespaces
func (c *Client) ListContainers() ([]*types.ContainerInfo, error) {
	// Get all namespaces
	namespaceService := c.client.NamespaceService()
	nsList, err := namespaceService.List(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	var result []*types.ContainerInfo
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		containers, err := c.client.Containers(nsCtx)
		if err != nil {
			slog.Warn("Failed to list containers in namespace",
				"namespace", ns,
				"error", err,
			)
			continue
		}

		for _, container := range containers {
			info, err := c.getContainerInfo(nsCtx, ns, container)
			if err != nil {
				slog.Warn("Failed to get container info",
					"container", container.ID(),
					"namespace", ns,
					"error", err,
				)
				continue
			}
			// Only include containers with running tasks
			if info.PID > 0 {
				result = append(result, info)
			}
		}
	}

	return result, nil
}

// GetContainerInfoByUID gets container information by container UID
func (c *Client) GetContainerInfoByUID(containerUID string) (*types.ContainerInfo, error) {
	// Get all namespaces
	namespaceService := c.client.NamespaceService()
	nsList, err := namespaceService.List(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Search through all namespaces
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		container, err := c.client.LoadContainer(nsCtx, containerUID)
		if err != nil {
			// Container not found in this namespace, continue
			continue
		}
		// Found the container
		return c.getContainerInfo(nsCtx, ns, container)
	}
	return nil, fmt.Errorf("container not found: %s", containerUID)
}

// Close closes the containerd client
func (c *Client) Close() error {
	return c.client.Close()
}
