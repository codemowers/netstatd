package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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

// GetImageMetainfo extracts OCI image configuration metadata for a container
// image reference from containerd. It first tries the exact container image
// reference and then falls back to the CRI image-name label when present.
func (c *Client) GetImageMetainfo(namespace, imageRef string, labels map[string]string) (*types.ImageMetainfo, error) {
	if imageRef == "" {
		return nil, fmt.Errorf("image reference is empty")
	}
	if namespace == "" {
		namespace = "k8s.io"
	}

	nsCtx := namespaces.WithNamespace(c.ctx, namespace)
	refs := []string{imageRef}
	if criImageName := labels["io.kubernetes.cri.image-name"]; criImageName != "" && criImageName != imageRef {
		refs = append(refs, criImageName)
	}

	var lastErr error
	for _, ref := range refs {
		image, err := c.client.GetImage(nsCtx, ref)
		if err != nil {
			lastErr = err
			continue
		}
		return extractImageMetainfo(nsCtx, image, imageRef)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("image not found: %s", imageRef)
}

func extractImageMetainfo(ctx context.Context, image containerd.Image, requestedRef string) (*types.ImageMetainfo, error) {
	spec, err := image.Spec(ctx)
	if err != nil {
		return nil, err
	}

	target := image.Target()
	configDesc, err := image.Config(ctx)
	if err != nil {
		return nil, err
	}
	platformManifestDesc, err := platformManifestDescriptor(ctx, image)
	if err != nil {
		platformManifestDesc = ocispec.Descriptor{}
	}

	size, err := image.Size(ctx)
	if err != nil {
		size = 0
	}

	meta := &types.ImageMetainfo{
		Image:             requestedRef,
		TargetDigest:      target.Digest.String(),
		TargetMediaType:   target.MediaType,
		ImageConfigDigest: configDesc.Digest.String(),
		ImageConfigSize:   configDesc.Size,
		Size:              size,
		Author:            spec.Author,
		Architecture:      spec.Architecture,
		OS:                spec.OS,
		OSVersion:         spec.OSVersion,
		Variant:           spec.Variant,
		User:              spec.Config.User,
		Env:               append([]string(nil), spec.Config.Env...),
		Entrypoint:        append([]string(nil), spec.Config.Entrypoint...),
		Cmd:               append([]string(nil), spec.Config.Cmd...),
		WorkingDir:        spec.Config.WorkingDir,
		ExposedPorts:      sortedSetKeys(spec.Config.ExposedPorts),
		Volumes:           sortedSetKeys(spec.Config.Volumes),
		Labels:            copyStringMap(spec.Config.Labels),
		StopSignal:        spec.Config.StopSignal,
		RootFSType:        spec.RootFS.Type,
	}
	if platformManifestDesc.Digest != "" {
		meta.PlatformManifestDigest = platformManifestDesc.Digest.String()
		meta.PlatformManifestMediaType = platformManifestDesc.MediaType
	}
	if spec.Created != nil {
		meta.Created = spec.Created.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	for _, diffID := range spec.RootFS.DiffIDs {
		meta.RootFSDiffIDs = append(meta.RootFSDiffIDs, diffID.String())
	}
	for _, entry := range spec.History {
		history := types.ImageHistory{
			CreatedBy:  entry.CreatedBy,
			Author:     entry.Author,
			Comment:    entry.Comment,
			EmptyLayer: entry.EmptyLayer,
		}
		if entry.Created != nil {
			history.Created = entry.Created.Format("2006-01-02T15:04:05.999999999Z07:00")
		}
		meta.History = append(meta.History, history)
	}

	return meta, nil
}

func platformManifestDescriptor(ctx context.Context, image containerd.Image) (ocispec.Descriptor, error) {
	target := image.Target()
	if images.IsManifestType(target.MediaType) {
		return target, nil
	}
	if !images.IsIndexType(target.MediaType) {
		return ocispec.Descriptor{}, fmt.Errorf("image target is not a manifest or index: %s", target.MediaType)
	}

	p, err := content.ReadBlob(ctx, image.ContentStore(), target)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	var idx ocispec.Index
	if err := json.Unmarshal(p, &idx); err != nil {
		return ocispec.Descriptor{}, err
	}

	platform := image.Platform()
	if platform == nil {
		platform = platforms.Default()
	}

	var matches []ocispec.Descriptor
	for _, desc := range idx.Manifests {
		if desc.Platform == nil || platform.Match(*desc.Platform) {
			matches = append(matches, desc)
		}
	}
	if len(matches) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("no platform manifest matches host platform")
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Platform == nil {
			return false
		}
		if matches[j].Platform == nil {
			return true
		}
		return platform.Less(*matches[i].Platform, *matches[j].Platform)
	})

	return matches[0], nil
}

func sortedSetKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
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

// Close closes the containerd client
func (c *Client) Close() error {
	return c.client.Close()
}
