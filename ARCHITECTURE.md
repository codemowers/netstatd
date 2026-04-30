# Architecture

## Overview

```
Linux Kernel (eBPF Tracer) ──────┐
                                 ├→ HTTP/WebSocket Server → Browser
Containerd Events ───────────────┤
                                 │
/proc Filesystem ────────────────┘
```

The system uses multiple data sources for comprehensive network monitoring:

- **eBPF**: Captures TCP/UDP connection events from kernel
- **Containerd**: Provides container metadata and lifecycle events
- **/proc**: Used for IP detection, listening port scanning, and executable resolution

**Architecture Design:** TCP state events are tracked by socket cookie and normally do not carry process identity. Accepted inbound TCP connections are emitted separately as `connection.accepted` events with a PID; the server resolves that PID through `/proc` to cgroup, container UID, executable, and network namespace metadata before the accepted event reaches the browser. The system also scans `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` to discover listening ports.

## Container Metadata Extraction

netstatd extracts container metadata from containerd using the containerd client API. The metadata includes:

### Container Information Structure

Each container is represented by a `ContainerInfo` struct with the following fields:

- **ID**: The container UID (e.g., `2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a`)
- **Name**: Container name from `io.kubernetes.container.name` label
- **Namespace**: Containerd namespace (e.g., `k8s.io`)
- **UsesHostNetwork**: Boolean indicating if pod uses host networking
- **PodName**: Pod name (e.g., `alloy-ltrr7`)
- **PodNamespace**: Kubernetes namespace (e.g., `monitoring`)
- **PodUID**: Pod UID (e.g., `d5647735-a7fe-4a8f-85a5-28a46ec08802`)
- **ContainerName**: Container name (e.g., `alloy`)
- **Labels**: Kubernetes pod labels (extracted from `io.kubernetes.pod.label.*` labels)

**Note**: PID, CgroupSlice, and PodIPs fields have been removed from the ContainerInfo struct. These fields are not reliably available from containerd and are instead resolved from `/proc` at connection event time.

### Containerd Container Info Example

Here's a full example of `ctr container info` output that netstatd processes:

```json
{
  "ID": "2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a",
  "Labels": {
    "io.cri-containerd.kind": "container",
    "io.kubernetes.container.name": "alloy",
    "io.kubernetes.pod.name": "alloy-ltrr7",
    "io.kubernetes.pod.namespace": "monitoring",
    "io.kubernetes.pod.uid": "d5647735-a7fe-4a8f-85a5-28a46ec08802",
    "org.opencontainers.image.ref.name": "ubuntu",
    "org.opencontainers.image.source": "https://github.com/grafana/alloy",
    "org.opencontainers.image.version": "24.04"
  },
  "Image": "docker.io/grafana/alloy:latest",
  "Spec": {
    "annotations": {
      "io.kubernetes.cri.container-name": "alloy",
      "io.kubernetes.cri.container-type": "container",
      "io.kubernetes.cri.image-name": "grafana/alloy:latest",
      "io.kubernetes.cri.sandbox-id": "80e27ec50fdd0d3a14948723a52f48680ed472f044cd78e1cb6755b5a74e16b2",
      "io.kubernetes.cri.sandbox-name": "alloy-ltrr7",
      "io.kubernetes.cri.sandbox-namespace": "monitoring",
      "io.kubernetes.cri.sandbox-uid": "d5647735-a7fe-4a8f-85a5-28a46ec08802"
    }
  }
}
```

From this output, netstatd extracts the following key metadata:

1. **Container ID**: `2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a` (64-character hex string)
2. **Kubernetes Labels**:
   - `io.kubernetes.container.name`: `"alloy"`
   - `io.kubernetes.pod.name`: `"alloy-ltrr7"`
   - `io.kubernetes.pod.namespace`: `"monitoring"`
   - `io.kubernetes.pod.uid`: `"d5647735-a7fe-4a8f-85a5-28a46ec08802"`
3. **Container Runtime Annotations** (from `Spec.annotations`):
   - `io.kubernetes.cri.container-name`: `"alloy"`
   - `io.kubernetes.cri.sandbox-name`: `"alloy-ltrr7"`
   - `io.kubernetes.cri.sandbox-namespace`: `"monitoring"`
   - `io.kubernetes.cri.sandbox-uid`: `"d5647735-a7fe-4a8f-85a5-28a46ec08802"`
   - `io.kubernetes.cri.sandbox-id`: `"80e27ec50fdd0d3a14948723a52f48680ed472f044cd78e1cb6755b5a74e16b2"`

**Note**: The `io.kubernetes.cri.sandbox-uid` annotation matches the `io.kubernetes.pod.uid` label, confirming the pod UID. The sandbox ID (`80e27ec50fdd0d3a14948723a52f48680ed472f044cd78e1cb6755b5a74e16b2`) is the pause/infra container ID, which is different from the application container ID (`2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a`).

### Metadata Extraction Limitations

netstatd currently extracts Kubernetes metadata primarily from container labels, not from the container spec annotations. This means:

1. **Extracted from labels**:
   - `io.kubernetes.pod.name`
   - `io.kubernetes.pod.namespace`
   - `io.kubernetes.pod.uid`
   - `io.kubernetes.container.name`
   - `io.kubernetes.pod.label.*` (custom pod labels)
   - `io.kubernetes.pod.annotation.*` (custom pod annotations)

2. **Not extracted (but available in spec)**:
   - `io.kubernetes.cri.sandbox-id` (pause container ID)
   - `io.kubernetes.cri.container-type`
   - `io.kubernetes.cri.image-name`
   - Other CRI-specific annotations

This is sufficient for netstatd's purposes, as the essential pod and container identification information is available in the labels. The sandbox ID (pause container) is not needed for connection tracking since all containers in a pod share the same network namespace and pod UID.

### Cgroup Path Parsing

The cgroup path contains both pod and container identifiers:

```
kubepods-besteffort-podd5647735_a7fe_4a8f_85a5_28a46ec08802.slice:cri-containerd:2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a
```

netstatd uses regex patterns to extract:

- **Pod UID**: `d5647735-a7fe-4a8f-85a5-28a46ec08802` (underscores converted to hyphens)
- **Container UID**: `2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a`

### IP Address Discovery

Pod IP addresses are not directly available from containerd metadata. Instead, netstatd discovers IP addresses through connection events:

1. **Initial Discovery**: When a connection event occurs, the source and destination IPs are examined
2. **Association**: IPs are associated with containers via:
   - PID from accepted TCP events and process metadata
   - Cgroup slice from `/proc/<pid>/cgroup`
   - Container UID extracted from cgroup path
3. **Browser-side Mapping**: The browser maintains mappings between IPs and pod metadata
   - When a connection event includes container metadata, the browser associates the IP with that container
   - Subsequent connections with the same IP can be resolved to the appropriate pod

This approach is necessary because:

- Containerd does not expose pod IPs in container metadata
- IP addresses are network namespace properties, not container properties
- Multiple containers in a pod share the same network namespace and IPs
- IPs can only be discovered when network activity occurs

**Note**: The `podIPs` field in `container.added` events is always empty and should be ignored.

### Host Network Detection

netstatd determines if a container uses host networking by comparing its network namespace with the host's network namespace (read from `/proc/1/ns/net` at startup).

### Container Lifecycle

1. **Preloading**: At startup, netstatd lists all containers from containerd and caches their metadata.
2. **Runtime Discovery**: When accepted connection and listen events expose a PID, netstatd looks up container metadata using:
   - Container UID from cgroup path (primary)
   - Pod UID from cgroup path (fallback)
3. **Dynamic Updates**: If a container is not found in cache, netstatd queries containerd for the container info and adds it to the cache.

### WebSocket Events

Container metadata is sent to browsers via `container.added` WebSocket events with the following structure:

```json
{
  "type": "container.added",
  "timestamp": "2026-03-11T14:24:35.548592376Z",
  "nodeName": "node-name",
  "containerUid": "2b7c7451d4f4915c4467d90db3adae670bc9a0ec0b0b612ef36f567189e4bf0a",
  "name": "alloy",
  "podName": "alloy-ltrr7",
  "namespace": "monitoring",
  "podUID": "d5647735-a7fe-4a8f-85a5-28a46ec08802",
  "containerName": "alloy"
}
```

**Note**: PID, CgroupSlice, and PodIPs fields are NOT included in WebSocket events — they are not reliably available from containerd and are instead resolved from `/proc` at connection event time. Empty `labels` fields are omitted from the WebSocket events to reduce payload size.

## Identifier Hierarchy

A running Kubernetes workload has **three distinct identifiers** that must not be conflated:

### Pod UID

The Kubernetes pod UID, e.g. `7447f388-0231-48f5-9b32-44a28560d0a3`.

- Assigned by the Kubernetes API server.
- Shared by **all containers in the pod** (including the `pause`/infra container).
- Extractable from the cgroup slice path: the `kubepods-<qos>-pod<uid>.slice` component.
- Retained for pod identity and same-pod comparisons.
- Present in containerd labels as `io.kubernetes.pod.uid`.

### Container UID (containerd container ID)

The containerd container ID, e.g. `ff430d3a65488e04911ac17d621c1f69d57edbd1c3405d7325c59f0dab98e118`.

- A 64-character hex string assigned by containerd.
- **Unique per container** within a pod. A pod with 3 containers has 3 container UIDs.
- Extractable from the cgroup slice path: the `cri-containerd-<uid>.scope` component.
- Sent as `containerUid` in `container.added` WebSocket events.
- Used as the primary key in the server and browser container caches.

### Example cgroup slice

```
0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod7447f388_0231_48f5_9b32_44a28560d0a3.slice/cri-containerd-ff430d3a65488e04911ac17d621c1f69d57edbd1c3405d7325c59f0dab98e118.scope
```

Parsed:

- Pod UID: `7447f388-0231-48f5-9b32-44a28560d0a3` (underscores → hyphens)
- Container UID: `ff430d3a65488e04911ac17d621c1f69d57edbd1c3405d7325c59f0dab98e118`

### Implication for the server container cache

The server indexes containers by **container UID**, so sidecars in the same pod remain distinct records. Pod UID is still retained and used to recognize that multiple container UIDs belong to one pod identity. When a cgroup slice is read from `/proc/<pid>/cgroup`, the container UID is the preferred lookup key; pod UID is only a fallback for cases where the exact container record is not yet cached.

## Operation Modes

### Mode 1: Self-Contained DaemonSet

Each pod runs independently on port 5280, serving only its local node's data:

- Single-pod WebSocket endpoint: `/conntrack`
- Headless service (`netstatd-headless`) for pod discovery

### Mode 2: DaemonSet + Multiplexer

Pods run both single-pod (5280) and multiplexer (6280) endpoints:

- **Port 5280**: Single-pod data
- **Port 6280**: Fanout endpoint that aggregates from all pods
  - WebSocket endpoint: `/conntrack` (connects to all pods' port 5280)
  - Provides cluster-wide view from single connection

**Fanout Architecture:** The multiplexer discovers all pods via the headless service DNS, connects to each pod's single-pod endpoint, and aggregates events.

## Concurrency and State Management

### Design Philosophy: Minimize Mutexes via Per-Connection State

**Primary optimization target is a single active WebSocket connection.** Multiple connections are supported but are not the primary performance concern. This shapes the entire state management strategy: move as much state as possible into per-connection structs so that the common case (one connection) requires zero mutex contention.

**Rule of thumb:**

- If state is only needed to track _what has been sent to a specific client_, it belongs in `clientWriter` (per-connection, no mutex needed).
- If state is shared across all clients (e.g., container metadata cache), it belongs in the `Server` struct and requires a mutex.

### Per-Connection State (`clientWriter`)

Each WebSocket connection owns a `clientWriter` with a buffered event channel. Per-client tracking maps are accessed from that client's writer goroutine, so they do not require their own mutex.

```go
type clientWriter struct {
    conn             *websocket.Conn
    ch               chan Event
    done             chan struct{}
    scannedNetNS     map[uint64]bool // Network namespaces already scanned for listening ports
    broadcastedPorts map[string]bool // Port keys already sent to this client
    sentProcessPID   map[uint32]bool // Process metadata already sent to this client
    sentContainerUID map[string]bool // Container metadata already sent to this client
}
```

**What is tracked per-connection:**

- `scannedNetNS` — Tracks which network namespace inodes have been scanned for listening ports. When a PID-bearing event resolves to a new `netns`, the scan is triggered once per connection. Each client independently triggers its own scan on first encounter, ensuring every client gets the full port list regardless of when it connects.
- `broadcastedPorts` — Tracks which `port.listening` events have already been sent to this client. Prevents duplicate port rows in the UI when the same port is discovered multiple times (e.g., from multiple connection events in the same netns).
- `sentProcessPID` — Tracks which `process.metainfo` events have already been sent to this client.
- `sentContainerUID` — Tracks which `container.metainfo` events have already been sent to this client.

**Lifecycle:** `clientWriter` is created when a client connects and deleted when it disconnects. Cleanup is automatic.

### Global Shared State (Requires Mutexes)

Only state that must be shared across all connections (or between the eBPF event goroutine and the broadcast goroutine) uses mutexes:

| Field           | Mutex                 | Access Pattern                                         | Rationale                                                      |
| --------------- | --------------------- | ------------------------------------------------------ | -------------------------------------------------------------- |
| `containers`    | `mu` (RWMutex)        | Many reads, rare writes                                | Container metadata cache; written only on container add/delete |
| `clients`       | `clientsMu` (RWMutex) | Read on every broadcast, write on connect/disconnect   | Registry of active WebSocket connections                       |
| `eventCounters` | `metricsMu` (RWMutex) | Written on every eBPF event, read on `/metrics` scrape | Prometheus counters                                            |

### Broadcast Flow (Single Connection Case)

In the common case of one WebSocket client, the broadcast handler:

1. Acquires `clientsMu.RLock()` to iterate active client writers.
2. Enqueues each event into the client's buffered channel.
3. The per-client writer goroutine performs metadata ordering, dedupe, and WebSocket writes.

This keeps the eBPF processing path from blocking on browser writes except when a client's channel is full, in which case the event is dropped for that client and counted.

## Components

### 1. eBPF Tracer (`internal/ebpf/`)

Monitors TCP and UDP connections using eBPF:

- **TCP**: Attaches to `inet_sock_set_state` tracepoint (tp_btf) for state changes
- **UDP**: Attaches kprobes to `udp_sendmsg` and `udp_recvmsg`
- Uses ring buffers for efficient userspace communication
- Supports both IPv4 and IPv6
- Minimal overhead

**Data Captured from eBPF:**

Currently captured per connection event:

- **PID** (`uint32`) - Process ID from `bpf_get_current_pid_tgid()` for PID-bearing event types, especially TCP accept; TCP state events set this to 0
- **Address Family** (`uint16`) - AF_INET (2) or AF_INET6 (10)
- **Source Port** (`uint16`) - Local port number (may be 0 for certain TCP states)
- **Destination Port** (`uint16`) - Remote port number (may be 0 for certain TCP states)
- **State** (`uint32`) - Current TCP state (1=ESTABLISHED, 7=CLOSE, 10=LISTEN) or 0 for UDP
- **Protocol** (`uint8`) - 6 for TCP, 17 for UDP
- **Socket Cookie** (`uint64`) - Unique TCP state identifier via `bpf_get_socket_cookie(sk)` where available; accept and UDP kprobe events may use 0
- **Source IP** - IPv4 (uint32) or IPv6 (16 bytes)
- **Destination IP** - IPv4 (uint32) or IPv6 (16 bytes)

**Additional Data Available from eBPF (Not Currently Captured):**

From `struct sock`:

- **UID/GID** (`uint32`) - User/group ID via `bpf_get_current_uid_gid()`
- **Comm** (`char[16]`) - Process name via `bpf_get_current_comm()`
- **Cgroup ID** (`uint64`) - Cgroup identifier via `bpf_get_current_cgroup_id()`
- **Socket Options** - SO_REUSEADDR, SO_KEEPALIVE, etc.
- **TCP Metrics** - RTT, congestion window, retransmits (from `struct tcp_sock`)
- **Socket Buffer Stats** - Send/receive buffer sizes, queued bytes

From tracepoint/kprobe context:

- **Timestamp** (`uint64`) - Event timestamp via `bpf_ktime_get_ns()`
- **CPU ID** (`uint32`) - CPU where event occurred via `bpf_get_smp_processor_id()`
- **Task Struct Fields** - Parent PID, thread group ID, etc.

**Why Some Data Isn't Captured:**

- **UID/GID**: Can be obtained from `/proc/<pid>/status` when needed
- **Comm**: Process name resolved via `/proc/<pid>/exe` for better accuracy (full path)
- **TCP Metrics**: Would add overhead and complexity; focus is on connection tracking
- **Timestamps**: Event ordering handled by ring buffer; absolute timestamps not needed
- **Cgroup ID**: Cgroup slice obtained via `/proc/<pid>/cgroup` for full path and pod UID extraction

**Trade-offs:**

The current implementation prioritizes:

1. **Minimal overhead** - Only essential data captured in eBPF
2. **Simplicity** - Complex data resolved in userspace where debugging is easier
3. **Flexibility** - `/proc` filesystem provides rich metadata without eBPF complexity
4. **Compatibility** - Fewer kernel version dependencies
5. **Reliable tracking** - Socket cookies provide stable connection tracking even when PID is unavailable

Socket cookies are used for TCP connection tracking because they remain stable across the connection lifetime and work even when PID is unavailable (kernel context, softirq).

### 2. Containerd Client (`internal/containerd/`)

Interfaces with containerd:

- Event-based monitoring via containerd events API
- Extracts container metadata, PID, and Kubernetes labels
- Detects host network pods by comparing network namespaces
- Reads pod IPs from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`
- Real-time updates without polling
- Monitors all containerd namespaces

### 3. HTTP/WebSocket Server (`internal/server/`)

Exposes data via multiple endpoints:

**WebSocket API:**

- `/conntrack` - Single pod events (port 5280)
- `/conntrack` - Cluster-wide fanout (port 6280)

## WebSocket Message Types

### 1. `host.info`

Sent when a client connects to provide host information.

**Required fields:**

- `type`: "host.info"
- `timestamp`: ISO 8601 timestamp
- `nodeName`: Node name
- `hostIPs`: Array of host IP addresses

**Optional fields:** None

### 2. `container.added`

Sent when a new container is discovered.

**Required fields:**

- `type`: "container.added"
- `timestamp`: ISO 8601 timestamp
- `nodeName`: Node name
- `containerUid`: Container UID (containerd container ID, 64-char hex)
- `name`: Container name from `io.kubernetes.container.name` label

- `podName`: Pod name (from `io.kubernetes.pod.name` label)
- `namespace`: Kubernetes namespace (from `io.kubernetes.pod.namespace` label)
- `podUID`: Pod UID (from `io.kubernetes.pod.uid` label)
- `containerName`: Container name (from `io.kubernetes.container.name` label)
- `image`: Container image
- `labels`: Map of pod labels (extracted from `io.kubernetes.pod.label.*` labels)

**Note:** PID, CgroupSlice, and PodIPs are NOT included — they are not reliably available from containerd and are resolved from `/proc` at connection event time.

### 3. `container.deleted`

Sent when a container stops.

**Required fields:**

- `type`: "container.deleted"
- `containerUid`: Container UID

**Optional fields:**

- `timestamp`: ISO 8601 timestamp
- `nodeName`: Node name

### 4. `connection.event`

Sent for TCP/UDP connection events from eBPF.

**Required fields:**

- `type`: "connection.event"
- `timestamp`: ISO 8601 timestamp
- `protocol`: Protocol name ("TCP" or "UDP")
- `state`: Connection state string
- `sockCookie`: Socket cookie for connection tracking
- `nodeName`: Node name
- `localIP`: Local IP address
- `remoteIP`: Remote IP address

**Optional fields:**

- `localPort`: Local port number (if non-zero)
- `remotePort`: Remote port number (if non-zero)

**Note:** `connection.event` intentionally does not carry PID or container metadata. TCP state transitions are keyed by socket cookie when the kernel exposes one. Closing states without an existing browser row are ignored by the frontend instead of creating stale rows.

### 5. `connection.accepted`

Sent for accepted inbound TCP connections. This is the PID-bearing companion event for passive accepts.

**Required fields:**

- `type`: "connection.accepted"
- `timestamp`: ISO 8601 timestamp
- `protocol`: "TCP"
- `state`: Connection state string
- `nodeName`: Node name
- `localIP`: Local IP address
- `remoteIP`: Remote IP address
- `pid`: Process ID

**Optional fields:**

- `localPort`: Local port number (if non-zero)
- `remotePort`: Remote port number (if non-zero)
- `sockCookie`: Socket cookie if available; accept kretprobe events may use 0

**Note:** The WebSocket writer sends `container.metainfo` and `process.metainfo` before `connection.accepted` when it has not already sent metadata for that PID. In the browser, this event enriches existing connection rows and listening port rows; it does not create a new connection row by itself.

### 6. `port.listening`

Sent when a listening port is discovered.

**Required fields:**

- `type`: "port.listening"
- `timestamp`: ISO 8601 timestamp
- `nodeName`: Node name
- `protocol`: Protocol name ("TCP" or "UDP")
- `ip`: IP address
- `port`: Port number
- `netns`: Network namespace identifier
- `isListening`: Boolean (always true)

**Optional fields:**

- `containerUid`: Container UID (if resolved)
- `podUID`: Pod UID (if resolved)
- `podName`: Pod name (if resolved)
- `namespace`: Kubernetes namespace (if resolved)
- `containerName`: Container name (if resolved)

**Note:** PID, exe, and cgroupSlice are not included in `port.listening` because the scanning PID may be a namespace representative rather than the process that owns every listening socket. The browser fills the Last PID and cgroup columns from `connection.accepted` plus `process.metainfo`, keyed by `nodeName/protocol/port/netns`.

### 7. `process.metainfo`

Sent to resolve PID to executable, cgroup slice, container UID, and netns information.

**Required fields:**

- `type`: "process.metainfo"
- `timestamp`: ISO 8601 timestamp
- `nodeName`: Node name
- `pid`: Process ID

**Optional fields:**

- `exe`: Executable name (resolved from `/proc/<pid>/exe`)
- `netns`: Network namespace identifier
- `cgroupSlice`: Cgroup slice path
- `containerUid`: Container UID (if resolved from cgroup)
- `podUID`: Pod UID (if resolved)
- `podName`: Pod name (if resolved)
- `namespace`: Kubernetes namespace (if resolved)
- `containerName`: Container name (if resolved)

**Note:** This event is sent before `connection.accepted` for PIDs that have not had their metadata sent to a client yet. Container process metadata with a container UID but no network namespace is logged and dropped server-side, because sending it would poison browser ownership caches.

## Event Processing Order

1. TCP state transitions arrive as `connection.event` and update rows by socket cookie, or by endpoint tuple when no cookie is available.
2. Accepted inbound TCP connections arrive as `connection.accepted` with PID.
3. Before a PID-bearing accepted event is written to a client, the server sends missing `container.metainfo` and `process.metainfo` for that PID.
4. The browser stores process metadata in `processMetadata` keyed by `nodeName/pid`.
5. `connection.accepted` enriches matching connection rows and listening port rows. Listening port PID metadata is keyed by `nodeName/protocol/port/netns`.

## Deduplication and State Tracking

- **Ports:** `port.listening` events are deduplicated per client using `broadcastedPorts` map (key: `nodeName:protocol:ip:port:netns`).
- **Connection Rows:** TCP state events use `sockCookie` as the preferred browser row key; when no cookie is available, the browser falls back to a node/protocol/sorted-endpoint tuple.
- **Process Metadata:** `process.metainfo` is sent once per PID per client using `sentProcessPID` map.
- **Network Namespace Scanning:** Network namespace scanning for listening ports is triggered once per netns per client using `scannedNetNS` map.

**PID-based Container Matching:**

When an accepted TCP or listen event exposes a PID:

1. Read `/proc/<pid>/cgroup` to get the full cgroup slice string.
2. Extract the **container UID** from the `cri-containerd-<uid>.scope` component.
3. Look up the container UID in `s.containers` to get exact container metadata.
4. Extract the **pod UID** from the `kubepods-<qos>-pod<uid>.slice` component as fallback metadata and for same-pod identity checks.

This keeps sidecars distinct while still treating multiple containers in one pod as the same pod owner for IP ambiguity checks.

**Listening Port Discovery:**
When a PID-bearing event resolves to a network namespace inode not yet seen by a given WebSocket client, the server scans `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` for that client. This scan is tracked in `clientWriter.scannedNetNS` and is **per-client**, so each new client independently triggers scans and receives the full port list. The `broadcastedPorts` set in `clientWriter` prevents duplicate `port.listening` events within a single client session.

**Executable Resolution:**
The server resolves PIDs to executable names by reading `/proc/<pid>/exe` symlinks (with fallback to `/proc/<pid>/cmdline`). Results are not globally cached — they are resolved on demand per event.

**Network Namespace Tracking:**
Each listening port includes its network namespace inode number (extracted from `/proc/<pid>/ns/net` symlink) to distinguish between ports in different namespaces (e.g., host vs. pod network).

**Loopback Filtering:**
Loopback connections (127.0.0.0/8 for IPv4 and ::1 for IPv6) are filtered both in eBPF kernel space and in userspace before events are sent to the browser.

**Protocol Filtering:**
TCP and UDP monitoring can be independently enabled/disabled via command-line flags:

- `--disable-tcp`: Disables TCP connection monitoring (eBPF tracepoint not attached)
- `--enable-udp`: Enables UDP connection monitoring (eBPF kprobes attached, disabled by default)

## Default Configuration

- Containerd socket: `/run/containerd/containerd.sock`
- Single-pod HTTP server: `[::]:5280`
- Multiplexer HTTP server: `[::]:6280`
- Headless service name: `netstatd-headless`

Environment variables:

- `CONTAINERD_SOCKET` - Override containerd socket path (default: `/run/containerd/containerd.sock`)
- `FANOUT_SERVICE` - Headless service name for fanout (required for multiplexer mode, default: `netstatd-headless`)
- `NODE_NAME` - Node name (injected by Kubernetes, falls back to `/etc/hostname`)

Command-line flags:

- `--log-level` - Set log level: trace, debug, info, warn, error (default: warn)
- `--http-port` - HTTP port for single-pod server (default: 5280)
- `--http-mux-port` - HTTP port for multiplexer server (default: 6280)
- `--disable-tcp` - Disable TCP connection monitoring
- `--enable-udp` - Enable UDP connection monitoring (disabled by default)

**Note:** Loopback connections (127.0.0.0/8 and ::1) are always filtered at the eBPF kernel level for performance.

## Data Lookup Mechanisms

### Network Namespace Tracking

Network namespaces are identified by their inode numbers (uint64) extracted from `/proc/<pid>/ns/net` symlinks. The format is `net:[4026531840]` where `4026531840` is the inode number.

### PID to Executable Mapping

- `getExeFromPID(pid uint32) string` - Reads `/proc/<pid>/exe` or `/proc/<pid>/cmdline` as fallback; called on demand, result not globally cached.

### Container Identification

- `containers map[string]*ContainerInfo` - Global cache indexed by **container UID**; protected by `mu` (RWMutex).
- `ExtractContainerUIDFromCgroup(cgroupSlice string)` - Extracts container UID from the `cri-containerd-<uid>.scope` component.
- `ExtractPodUIDFromCgroup(cgroupSlice string)` - Extracts pod UID from cgroup path (the `kubepods-<qos>-pod<uid>.slice` component).

### IP Address Resolution

- `hostIPsByNode map[string][]string` - Host IPs per node (from network interfaces)
- `getIPsFromProc(pid uint32)` - Reads pod IPs from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`
- `isHostNetNS` - Derived by comparing an event's network namespace with PID 1's network namespace on the same node

### Listening Port Tracking

- `clientWriter.broadcastedPorts map[string]bool` - **Per-connection** set of port keys already sent; key format: `nodeName:protocol:ip:port:netns`
- `scanProcNetFile(pid, netType)` - Parses `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` for listening sockets
- Browser `listeningPortByNodeNetNSProtocolPort Map<string, boolean>` - Direct listening index keyed as `nodeName/protocol/port/netns`, populated from `port.listening` events and hydrated endpoint bindings.

### Socket Identity

- TCP state events from `tp_btf/inet_sock_set_state` use `bpf_get_socket_cookie(sk)` as the preferred connection identifier.
- Accepted TCP kretprobe events do not use socket cookies on kernels/program types where that helper is unavailable; they carry PID and enrich matching local node/protocol/port rows instead.
- UDP kprobe events currently use socket cookie `0` and are keyed in the browser by endpoint tuple.

## Web View Architecture

The frontend maintains several views (Connections, Ports, Addresses, Containers), each with its own DOM table and update strategy. All views use `row.id = key` for O(1) DOM lookups.

**Important Design Principle:** Never render ellipsis ("…") with JavaScript in the browser. Ellipsis truncation should be handled by CSS `text-overflow: ellipsis` with appropriate width constraints. This ensures consistent rendering and better performance, as CSS-based ellipsis doesn't require JavaScript to compute string lengths and doesn't break full text display in tooltips.

### Browser container cache

The browser maintains `containers Map<containerUid, ContainerInfo>` keyed by `containerUid`. Container records are merged as `container.added` and `container.metainfo` events arrive, stored in memory, and persisted per container:

- `localStorage` key: `netstatd:container/<containerUid>`.
- Value: latest merged container record, including fields such as `nodeName`, `namespace`, `podName`, `podUid`, `containerName`, `image`, labels, and any observed network metadata.

Process metadata and endpoint bindings refer back to containers with `containerUid`. Pod UID is retained as metadata for display and row synchronization, but it is not the primary browser cache key.

Container images are rendered as external links when the registry is recognized. Docker Hub, `mirror.gcr.io` (mapped to Docker Hub), GHCR package pages, Quay repositories, and GCR image pages are linked with `target="_blank"` and `rel="noopener noreferrer"`.

When nodes report a changed deployment image hash, the browser clears `localStorage` and schedules a reload. This prevents stale container, endpoint binding, pod-IP owner, and user hostname cache entries from being reused across incompatible UI/server versions.

### Browser network ownership cache

The browser resolves connection endpoints from the most specific available ownership evidence, then falls back to broader hints. Browser-side ownership hints are persisted in `localStorage` so mappings survive page reloads and WebSocket reconnects.

Listening port process metadata is kept in memory in `processMetadataByPort`, keyed by `nodeName/protocol/port/netns`. It is populated from `connection.accepted` plus `process.metainfo` and is used to render the Last PID and cgroup columns in the Ports view.

#### Endpoint binding cache

Endpoint bindings map a concrete socket address back to the node, network namespace, and process that owns a listening endpoint:

```text
protocol,laddr,lport -> nodeName,netns,port,pid
```

This is the browser-side cache used to resolve a local endpoint address back to the node and network namespace that owns the listening socket. The in-memory representation is `endpointBindingByAddress`, keyed by local address and local port. The persisted key/value data must contain the same information:

- `localStorage` key: `netstatd:endpoint-binding/<protocol>/<laddr>/<lport>`, for example `netstatd:endpoint-binding/TCP/10.244.1.20/8080`.
- Value: owner binding with `nodeName`, `netns`, `port`, `pid`, `exe`, and `cgroupSlice`. Include `containerUid` only when present.

Endpoint bindings are populated from `port.listening` events and hydrated from browser storage. They describe listening endpoints, not arbitrary observed connections.

#### Pod-IP owner cache

The browser also persists confirmed pod-IP ownership hints for remote endpoint rendering:

- `localStorage` key: `netstatd:pod-ip-owner/<ip>`, for example `netstatd:pod-ip-owner/10.244.1.20`.
- Value: owner hint with `namespace`, `podName`, `nodeName`, and `netns`.

Only non-host-network pod observations are stored. Confirmed hints come from local connection observations where process metadata identifies a pod network namespace and a pod. Multiple containers in the same pod are treated as one owner. If an IP is claimed by different pod identities or later reported as a host IP, the browser drops the pod-IP hint instead of using a stale or ambiguous owner.

This cache is intentionally less authoritative than endpoint bindings. It exists so a remote IP can still render as `namespace/pod` after reload or reconnect when the browser has previously confirmed that IP belongs to a pod. It does not prove ownership of a specific port, process, or container.

#### Local endpoint resolution

For the local side of a connection row, the browser resolves `protocol/localIP/localPort` as follows:

1. If the row itself has pod/container metadata, prefer that local row context for display and filtering.
2. Otherwise, look up an endpoint binding for the exact protocol, IP, and port.
3. If the binding has `containerUid`, load the container record directly.
4. Otherwise, use the binding's `nodeName/netns/port`, then `nodeName/netns`, to find a remembered pod owner.
5. If no binding exists, fall back to pod-IP owner hints, then host-IP detection, then explicit external hostname mappings, then unknown.

The row's own process metadata is also used for display. When a local row has pod/container metadata, the endpoint uses that row context instead of relying only on global address ownership.

#### Remote endpoint resolution

For the remote side of a connection row, the browser uses the same `resolveEndpoint(protocol, remoteIP, remotePort)` path, but it usually has less direct process evidence. Resolution order is:

1. Exact endpoint binding for `protocol/remoteIP/remotePort`, if one has been learned from a listening port or another connection.
2. Stored or in-memory pod-IP owner hint for `remoteIP`, unless that IP is currently marked ambiguous.
3. Host-IP detection from `host.info` events.
4. User-supplied external hostname mapping from `netstatd:external-hostname/<ip>`.
5. Unknown, rendered as external in the connections table.

Closed connections do not remove endpoint bindings, pod-IP owner hints, or container records. Those caches are invalidated by container deletion, ambiguous pod-IP claims, host-IP reports, or image-hash storage reset.

`localStorage` is for browser-side ownership caches and explicit user hostname mappings, not for arbitrary UI state. Endpoint bindings are the authoritative cache for socket ownership and must be keyed with protocol, address, and port. Pod-IP owner entries are best-effort identity hints for display and must be discarded when contradicted by more specific live observations.

## Security

Current implementation:

- Requires privileged mode for eBPF program loading
- Host network and host PID namespace access
- Read-only `/proc` mount for IP detection, port scanning, and executable resolution
- WebSocket allows all origins (development mode)
- No authentication or authorization

Production recommendations:

- WebSocket authentication and authorization
- TLS/HTTPS for production deployments
- Network policies to restrict pod-to-pod communication
- Consider using seccomp profiles to limit syscalls
- Implement RBAC for API endpoints
- Restrict WebSocket origins in production

## Metrics

The server exposes Prometheus metrics at `/metrics`:

- `netstatd_events_total{protocol,family}` - Total events by protocol and address family
- `netstatd_events_by_state{protocol,family,state}` - Events by TCP/UDP state

Metrics use protocol numbers (6=TCP, 17=UDP) and address family numbers (2=IPv4, 10=IPv6) as labels.
