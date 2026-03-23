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

**Architecture Design:** The server performs PID-based connection-to-container matching using a fast lookup map. eBPF events include the process PID, which is matched to the container's root process PID to identify the container UID. The system also scans `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` to discover listening ports.

## Operation Modes

### Mode 1: Self-Contained DaemonSet

Each pod runs independently on port 5280, serving only its local node's data:

- Single-pod WebSocket endpoint: `/conntrack`
- REST API: `/api/containers`, `/api/services`
- DNSTap collection on port 5253
- Headless service (`netstatd-headless`) for pod discovery

### Mode 2: DaemonSet + Multiplexer

Pods run both single-pod (5280) and multiplexer (6280) endpoints:

- **Port 5280**: Single-pod data
- **Port 6280**: Fanout endpoint that aggregates from all pods
  - WebSocket endpoint: `/conntrack` (connects to all pods' port 5280)
  - Provides cluster-wide view from single connection
- **Port 5253**: Single-pod DNSTap collection
- **Port 6253**: Fanout DNSTap aggregation

**Fanout Architecture:** The multiplexer discovers all pods via the headless service DNS, connects to each pod's single-pod endpoint, and aggregates events.

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

- **PID** (`uint32`) - Process ID from `bpf_get_current_pid_tgid()` (may be 0 for kernel-initiated connections)
- **Address Family** (`uint16`) - AF_INET (2) or AF_INET6 (10)
- **Source Port** (`uint16`) - Local port number
- **Destination Port** (`uint16`) - Remote port number
- **State** (`uint32`) - TCP state (1=ESTABLISHED, 7=CLOSE) or 0 for UDP
- **Protocol** (`uint8`) - 6 for TCP, 17 for UDP
- **Source IP** - IPv4 (uint32) or IPv6 (16 bytes)
- **Destination IP** - IPv4 (uint32) or IPv6 (16 bytes)

**Additional Data Available from eBPF (Not Currently Captured):**

From `struct sock`:

- **Socket Cookie** (`uint64`) - Unique socket identifier via `bpf_get_socket_cookie()` (stable across connection lifetime, previously used but removed for simplicity)
- **Socket Inode** (`uint64`) - Socket inode number from `sk->sk_socket->inode`
- **UID/GID** (`uint32`) - User/group ID via `bpf_get_current_uid_gid()`
- **Comm** (`char[16]`) - Process name via `bpf_get_current_comm()`
- **Cgroup ID** (`uint64`) - Cgroup identifier via `bpf_get_current_cgroup_id()`
- **Network Namespace** (`uint32`) - Network namespace ID from socket
- **Socket Options** - SO_REUSEADDR, SO_KEEPALIVE, etc.
- **TCP Metrics** - RTT, congestion window, retransmits (from `struct tcp_sock`)
- **Socket Buffer Stats** - Send/receive buffer sizes, queued bytes

From tracepoint/kprobe context:

- **Timestamp** (`uint64`) - Event timestamp via `bpf_ktime_get_ns()`
- **CPU ID** (`uint32`) - CPU where event occurred via `bpf_get_smp_processor_id()`
- **Task Struct Fields** - Parent PID, thread group ID, etc.

**Why Some Data Isn't Captured:**

- **Socket Cookie**: Removed for simplicity; endpoint-based keys work well for deduplication
- **Socket Inode**: Available via `/proc/<pid>/fd/*` scanning (used for listening port PID resolution)
- **UID/GID**: Can be obtained from `/proc/<pid>/status` when needed
- **Comm**: Process name resolved via `/proc/<pid>/exe` for better accuracy
- **TCP Metrics**: Would add overhead and complexity; focus is on connection tracking
- **Timestamps**: Event ordering handled by ring buffer; absolute timestamps not needed
- **Cgroup ID**: Cgroup slice obtained via `/proc/<pid>/cgroup` for full path

**Trade-offs:**

The current implementation prioritizes:

1. **Minimal overhead** - Only essential data captured in eBPF
2. **Simplicity** - Complex data resolved in userspace where debugging is easier
3. **Flexibility** - `/proc` filesystem provides rich metadata without eBPF complexity
4. **Compatibility** - Fewer kernel version dependencies

Additional data can be added to the eBPF program if specific use cases require it (e.g., socket cookies for more reliable connection tracking, TCP metrics for performance analysis).

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

**REST API:**

- `GET /api/containers` - List containers with metadata
- `GET /api/services` - Service name mappings from /etc/services and custom services file

**WebSocket API:**

- `/conntrack` - Single pod events (port 5280)
- `/conntrack` - Cluster-wide fanout (port 6280)

**Event Types:**

- `host.info` - Host IP addresses and node information
- `container.added` - New container starts (includes `podIPs`, `usesHostNetwork`)
- `container.deleted` - Container stops
- `connection.event` - TCP/UDP connection event (includes `protocol`, `state`, `pid`, `exe`, `sockCookie`)
- `port.listening` - Listening port discovered (includes `netns`, `exe`)

**PID-based Container Matching:**
The server maintains a fast lookup map (PID → container UID). When an eBPF event arrives with a PID, it looks up the container UID and includes it in the WebSocket event.

**Listening Port Discovery:**
When a container starts or a connection event occurs, the server scans `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` to discover listening ports. This provides a complete view of exposed services.

**Executable Resolution:**
The server resolves PIDs to executable names by reading `/proc/<pid>/exe` symlinks and caches the results for performance.

**Network Namespace Tracking:**
Each listening port includes its network namespace identifier (`/proc/<pid>/ns/net`) to distinguish between ports in different namespaces (e.g., host vs. pod network).

## Default Configuration

- Containerd socket: `/run/containerd/containerd.sock`
- Single-pod HTTP server: `[::]:5280`
- Multiplexer HTTP server: `[::]:6280`
- DNSTap ports: 5253 (single-pod), 6253 (multiplexer)
- Headless service name: `netstatd-headless`

Environment variables:

- `CONTAINERD_SOCKET` - Override containerd socket path
- `FANOUT_SERVICE` - Headless service name for fanout (required for multiplexer mode)
- `NODE_NAME` - Node name (injected by Kubernetes)

Command-line flags:

- `--log-level` - Set log level: debug, info, warn, error (default: info)

## Data Lookup Mechanisms

### Network Namespace Tracking

Network namespaces are identified by their inode numbers (uint64) extracted from `/proc/<pid>/ns/net` symlinks. The format is `net:[4026531840]` where `4026531840` is the inode number.

**Go Backend:**

- `getNetNS(pid uint32) uint64` - Reads `/proc/<pid>/ns/net` and parses the inode number
- `parseNetNSInode(netns string) uint64` - Extracts inode from "net:[XXXXXX]" format
- `scannedNetNS map[uint64]bool` - Tracks which network namespaces have been scanned for listening ports
- `ListeningPort.NetNS uint64` - Stores the network namespace inode for each listening port

**Browser/JavaScript:**

- Network namespace inodes are received as numbers in WebSocket events
- Used in port lookup keys: `${nodeName}:${ip}:${port}:${netns || 0}`
- Displayed in the Ports view table for debugging

### PID to Executable Mapping

**Go Backend:**

- `pidToExe map[uint32]string` - Cache of PID to executable name mappings
- `getOrResolveExe(pid uint32) string` - Gets from cache or resolves via `/proc/<pid>/exe` symlink
- `getExeFromPID(pid uint32) string` - Reads `/proc/<pid>/exe` or `/proc/<pid>/cmdline` as fallback
- Executable names are sent in connection events and port listening events

**Browser/JavaScript:**

- `pidToExe Map<number, string>` - Client-side cache of PID to executable mappings
- `resolvePidToExe(pid)` - Fetches from `/api/pid-exe?pid=X` if not cached
- Displayed in Connections and Ports views

### Container Identification

**Go Backend:**

- `containers map[string]*ContainerInfo` - Indexed by pod UID
- `pidToContainerUID map[uint32]string` - Fast PID to container UID lookup
- `extractContainerUIDFromCgroup(cgroupSlice string)` - Extracts container UID from cgroup path
- Container info includes: namespace, pod name, container name, IPs, host network flag

**Browser/JavaScript:**

- `containers Map<string, ContainerInfo>` - Indexed by container UID
- `ipToPod Map<string, PodInfo>` - Maps pod IPs to pod metadata
- Used to enrich connection events with pod/container information

### IP Address Resolution

**Go Backend:**

- `hostIPsByNode map[string][]string` - Host IPs per node (from network interfaces)
- `getIPsFromProc(pid uint32)` - Reads pod IPs from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`
- `isHostNetwork(pid uint32)` - Compares netns with PID 1's netns

**Browser/JavaScript:**

- `ipToPod Map<string, PodInfo>` - Maps pod IPs to pod metadata (namespace, pod name, container name, node)
- `hostIPsByNode Map<string, string[]>` - Host IPs per node
- `discoveredIPs Map<string, IPInfo>` - All discovered IPs with type (pod/host/loopback), pod info, node, hostname
- Used for connection filtering and display

### Listening Port Tracking

**Go Backend:**

- `broadcastedPorts map[string]bool` - Tracks which ports have been broadcast (key: `nodeName:protocol:ip:port:netns`)
- `scanProcNetFile(pid, netType)` - Parses `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` for listening sockets
- `findPIDForSocket(uid, inode)` - Scans `/proc/*/fd/` to find PID owning a socket inode

**Browser/JavaScript:**

- `listeningPorts Map<string, PortInfo>` - Key: `${nodeName}:${ip}:${port}:${netns || 0}`
- Used to mark listening ports with 🎧 emoji in Connections view
- Displayed in dedicated Ports view with filtering

### DNS Resolution (DNSTap)

**Go Backend:**

- `DNSCache` - Maps IP addresses to hostnames with TTL-based expiration
- `dnstap.Collector` - Listens on TCP port for DNSTap framestream protocol
- Parses DNS responses to extract A/AAAA records
- Cache is shared with server for hostname lookups

**Browser/JavaScript:**

- DNS hostnames are included in `discoveredIPs` metadata
- Displayed in IPs view "Hostname" column
- Currently populated via DNSTap integration (future enhancement)

### Connection Deduplication

**Browser/JavaScript:**

- Optional deduplication based on canonical endpoint pairs
- Creates key by sorting endpoints: `${protocol}-${first}-${second}`
- Keeps connection with lower local port when duplicates exist
- Controlled by "Dedup" checkbox filter

## Security

Current implementation:

- Requires privileged mode for eBPF program loading
- Host network and host PID namespace access
- Read-only `/proc` mount for IP detection, port scanning, and executable resolution
- WebSocket allows all origins (development mode)

Production recommendations:

- WebSocket authentication and authorization
- TLS/HTTPS for production deployments
- Network policies to restrict pod-to-pod communication
- Consider using seccomp profiles to limit syscalls
- Implement RBAC for API endpoints
