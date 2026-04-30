package containerd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"netstatd/internal/types"
)

// procPath is the base path for /proc filesystem
// Set to /proc for normal operation, can be overridden for testing
const procPath = "/proc"

// hostNetNS is the host network namespace identifier (read from /proc/1/ns/net at startup)
var hostNetNS string
var hostNetNSInt uint64

// Client wraps containerd client and provides container metadata lookup
type Client struct {
	client *containerd.Client
	ctx    context.Context
	cancel context.CancelFunc
}

// Regex to extract pod UID from cgroup slice.
// Matches kubepods-pod<uid>.slice as well as QoS variants such as
// kubepods-burstable-pod<uid>.slice and kubepods-besteffort-pod<uid>.slice.
var podUIDRegex = regexp.MustCompile(`kubepods(?:-[^.\/]+)?-pod([a-f0-9_]+)\.slice`)

// Regex to extract container UID from cgroup slice
// Example: 0::/kubepods.slice/kubepods-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-ae5909341745bc298cc35a1aca9ca8290cffe61f241c558e6c196fc68ca3c08b.scope
// Captures: ae5909341745bc298cc35a1aca9ca8290cffe61f241c558e6c196fc68ca3c08b
var containerUIDRegex = regexp.MustCompile(`cri-containerd-([a-f0-9]+)\.scope`)

// NewClient creates a new containerd client
func NewClient(ctx context.Context, socket string) (*Client, error) {
	// Read host network namespace once at startup
	if hostNetNS == "" {
		netns, err := os.Readlink(fmt.Sprintf("%s/1/ns/net", procPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read host network namespace: %w", err)
		}
		hostNetNS = netns
		// Parse the inode number from net:[4026531840] format
		hostNetNSInt = parseNetNSIdentifier(netns)
		slog.Info("Host network namespace detected", "netns", hostNetNS, "netns_int", hostNetNSInt)
	}

	slog.Debug("Initializing containerd client", "socket", socket)
	client, err := containerd.New(socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to containerd: %w", err)
	}
	slog.Debug("Containerd client connection established successfully")

	clientCtx, cancel := context.WithCancel(ctx)

	c := &Client{
		client: client,
		ctx:    clientCtx,
		cancel: cancel,
	}

	slog.Info("Containerd client successfully initialized")
	return c, nil
}

// ExtractPodUIDFromCgroup extracts the pod UID from a cgroup slice path
// Example input: 0::/kubepods.slice/kubepods-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-ae5909341745bc298cc35a1aca9ca8290cffe61f241c558e6c196fc68ca3c08b.scope
// Returns: 1d2f838d-4a2e-4f27-be9e-ce7f8a4a466f
func ExtractPodUIDFromCgroup(cgroupSlice string) string {
	matches := podUIDRegex.FindStringSubmatch(cgroupSlice)
	if len(matches) < 2 {
		return ""
	}

	// Convert underscores to hyphens to get standard UUID format
	podUID := strings.ReplaceAll(matches[1], "_", "-")
	return podUID
}

// ExtractContainerUIDFromCgroup extracts the container UID from a cgroup slice path
// Example input: 0::/kubepods.slice/kubepods-pod1d2f838d_4a2e_4f27_be9e_ce7f8a4a466f.slice/cri-containerd-ae5909341745bc298cc35a1aca9ca8290cffe61f241c558e6c196fc68ca3c08b.scope
// Returns: ae5909341745bc298cc35a1aca9ca8290cffe61f241c558e6c196fc68ca3c08b
func ExtractContainerUIDFromCgroup(cgroupSlice string) string {
	matches := containerUIDRegex.FindStringSubmatch(cgroupSlice)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// GetContainerInfoByPodUID looks up container information by pod UID
// This searches all namespaces for a container with matching pod UID
func (c *Client) GetContainerInfoByPodUID(podUID string) (*types.ContainerInfo, error) {
	// Get all namespaces
	namespaceService := c.client.NamespaceService()
	nsList, err := namespaceService.List(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Search through all namespaces
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		containers, err := c.client.Containers(nsCtx)
		if err != nil {
			slog.Debug("Failed to list containers in namespace",
				"namespace", ns,
				"error", err,
			)
			continue
		}

		// Search for container with matching pod UID
		for _, container := range containers {
			info, err := container.Info(nsCtx)
			if err != nil {
				continue
			}

			// Check if this container's pod UID matches
			if info.Labels["io.kubernetes.pod.uid"] == podUID {
				return c.getContainerInfo(nsCtx, ns, container)
			}
		}
	}

	return nil, fmt.Errorf("container not found for pod UID: %s", podUID)
}

// GetContainerInfoByContainerID looks up container information by container ID
// This searches all namespaces for a container with matching container ID
func (c *Client) GetContainerInfoByContainerID(containerID string) (*types.ContainerInfo, error) {
	// Get all namespaces
	namespaceService := c.client.NamespaceService()
	nsList, err := namespaceService.List(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Search through all namespaces
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(c.ctx, ns)
		containers, err := c.client.Containers(nsCtx)
		if err != nil {
			slog.Debug("Failed to list containers in namespace",
				"namespace", ns,
				"error", err,
			)
			continue
		}

		// Search for container with matching container ID
		for _, container := range containers {
			if container.ID() == containerID {
				return c.getContainerInfo(nsCtx, ns, container)
			}
		}
	}

	return nil, fmt.Errorf("container not found for container ID: %s", containerID)
}

// ListAllContainers returns ContainerInfo for every container known to containerd,
// across all namespaces.  Containers without Kubernetes pod labels are skipped.
func (c *Client) ListAllContainers() ([]*types.ContainerInfo, error) {
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
			slog.Debug("Failed to list containers in namespace", "namespace", ns, "error", err)
			continue
		}

		for _, container := range containers {
			info, err := container.Info(nsCtx)
			if err != nil {
				continue
			}

			// Only include containers that have Kubernetes pod metadata
			if _, ok := info.Labels["io.kubernetes.pod.uid"]; !ok {
				continue
			}

			ci, err := c.getContainerInfo(nsCtx, ns, container)
			if err != nil {
				slog.Debug("Failed to get container info", "container", container.ID(), "error", err)
				continue
			}
			result = append(result, ci)
		}
	}

	return result, nil
}

// getContainerInfo extracts container information including Kubernetes metadata
func (c *Client) getContainerInfo(ctx context.Context, namespace string, container containerd.Container) (*types.ContainerInfo, error) {
	info, err := container.Info(ctx)
	if err != nil {
		return nil, err
	}

	containerInfo := &types.ContainerInfo{
		ID:                  container.ID(),
		Name:                info.Labels["io.kubernetes.container.name"],
		ContainerdNamespace: namespace,
		Image:               info.Image,
	}

	// Extract Kubernetes metadata from labels
	if podName, ok := info.Labels["io.kubernetes.pod.name"]; ok {
		containerInfo.PodName = podName
		containerInfo.PodNamespace = info.Labels["io.kubernetes.pod.namespace"]
		containerInfo.PodUID = info.Labels["io.kubernetes.pod.uid"]
		containerInfo.ContainerName = info.Labels["io.kubernetes.container.name"]

		containerInfo.Labels = extractContainerLabels(info.Labels)
	}

	return containerInfo, nil
}

func extractContainerLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}

	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// getCgroupSlice returns the cgroup slice string for a PID
func getCgroupSlice(pid uint32) string {
	if pid == 0 {
		return ""
	}

	// Read /proc/<pid>/cgroup
	cgroupPath := fmt.Sprintf("%s/%d/cgroup", procPath, pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	// Return the first line as-is, no parsing
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// parseNetNSIdentifier extracts the inode number from net:[4026531840] format
func parseNetNSIdentifier(netns string) uint64 {
	if netns == "" {
		return 0
	}
	// netns format is "net:[4026531840]"
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

		// For IPv4, make sure it's not a mapped IPv6 address (::ffff:)
		if !isIPv6 && strings.HasPrefix(ip, "::ffff:") {
			// Extract the IPv4 part
			ipv4 := strings.TrimPrefix(ip, "::ffff:")
			ipSet[ipv4] = true
		} else {
			ipSet[ip] = true
		}
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
	// The bytes in the hex string are in network byte order (big-endian) for each 32-bit word
	// But the entire 32-bit value is stored in little-endian format
	// So we need to reverse the bytes
	ip := net.IPv4(
		byte(val>>24),
		byte(val>>16),
		byte(val>>8),
		byte(val),
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

// Close closes the containerd client
func (c *Client) Close() error {
	return c.client.Close()
}
