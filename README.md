# netstatd

Real-time network connection monitoring for Kubernetes clusters using eBPF. Live instance at 
https://netstat.ee-lte-1.codemowers.io/
## Overview

netstatd is a Kubernetes DaemonSet that provides real-time visibility into network connections across your cluster. It uses eBPF to efficiently capture TCP and UDP connection events from the kernel and correlates them with container metadata from containerd.

## Features

- **Real-time Connection Tracking**: Monitor TCP and UDP connections as they happen
- **Container Correlation**: Automatically match connections to pods and containers
- **Listening Port Discovery**: Identify which services are exposed by each pod
- **Web Interface**: Interactive UI with five views (Connections, Ports, Addresses, Events, Deployment)
- **Cluster-wide View**: Multiplexer mode aggregates data from all nodes
- **Prometheus Metrics**: Built-in metrics endpoint for monitoring
- **IPv4 and IPv6 Support**: Full dual-stack networking support
- **Host Network Detection**: Automatically identifies pods using host networking
- **Socket Cookie Tracking**: Stable TCP connection tracking even when PID is unavailable
- **Loopback Filtering**: Loopback traffic filtered at eBPF kernel level for efficiency

## Quick Start

### Deploy as DaemonSet

```bash
kubectl apply -f deployment.yaml
```

### Access the UI

Forward the port to your local machine:

```bash
kubectl port-forward -n kube-system daemonset/netstatd 5280:5280
```

Then open http://localhost:5280 in your browser.

### Cluster-wide View

For a cluster-wide view, use the multiplexer port:

```bash
kubectl port-forward -n kube-system daemonset/netstatd 6280:6280
```

Then open http://localhost:6280 in your browser.

## Requirements

- Kubernetes cluster with containerd runtime
- Linux kernel 5.8+ (for eBPF tp_btf support)
- Privileged mode for eBPF program loading
- Host network and host PID namespace access

## Configuration

### Environment Variables

- `CONTAINERD_SOCKET`: Path to containerd socket (default: `/run/containerd/containerd.sock`)
- `FANOUT_SERVICE`: Headless service name for multiplexer mode (default: `netstatd-headless`)
- `NODE_NAME`: Node name (automatically injected by Kubernetes)

### Command-line Flags

- `--log-level`: Set log level: trace, debug, info, warn, error (default: warn)
- `--http-port`: HTTP port for single-pod server (default: 5280)
- `--http-mux-port`: HTTP port for multiplexer server (default: 6280)
- `--disable-tcp`: Disable TCP connection monitoring
- `--enable-udp`: Enable UDP connection monitoring (disabled by default)

**Note:** Loopback connections (127.0.0.0/8 and ::1) are always filtered at the eBPF kernel level for performance.

## API

### REST API

- `GET /metrics` - Prometheus metrics

### WebSocket API

- `ws://host:5280/conntrack` - Single pod events
- `ws://host:6280/conntrack` - Cluster-wide fanout

### Event Types

- `host.info` - Host IP addresses and node information
- `container.added` - New container starts (includes container and pod metadata)
- `container.deleted` - Container stops
- `connection.event` - TCP/UDP connection event from eBPF
  - Includes: protocol (string), state (string), socket cookie, node name, IPs, and ports
- `connection.accepted` - Accepted inbound TCP connection PID enrichment
  - Includes the same connection fields plus PID; process/container metadata is sent first as `process.metainfo`/`container.metainfo`
- `port.listening` - Listening port discovered
  - Includes: protocol (string), IP, port, network namespace, host-netns flag, and pod metadata when resolved
- `process.metainfo` - PID metadata for executable, cgroup slice, container UID, and network namespace

## Web Interface

The web interface provides five views:

### Connections View

- Real-time list of active TCP/UDP connections
- Filter by namespace, pod, node, protocol, state, port, IP family, and dedupe
- Columns are `Proto`, `Local Node`, `Local Endpoint`, `Remote Node`, `Remote Endpoint`, `State`, `PID`, `Exe`, and `Net NS Type`
- Visual indicators for pod, host, and external connections
- Color-coded connection endpoints (pod=green, host=blue, external=red)
- Socket cookie-based tracking for stable TCP connection identification
- Automatic cleanup of destroyed connections with visual fade-out animation

### Ports View

- List of all listening TCP/UDP ports discovered across the cluster
- Filter by port number, node, namespace, netns, IP family, and endpoint type
- Shows which pod/container owns each port (when available)
- Network namespace tracking for port isolation
- Last accepted PID and cgroup slice are filled from `connection.accepted`/`process.metainfo`
- Identifies host network pods and host processes

### Addresses View

- All discovered IP addresses in the cluster
- Categorized as pod or host
- Filter by IP, type, IP family, pod, node
- Automatic detection of host network pod IPs
- Shows pod and namespace associations for pod IPs

### Deployment View

- Quick reference for deploying netstatd
- Example DaemonSet configuration
- Service definitions for headless and regular services

### Events View

- Real-time event stream showing last 25 events
- Displays all WebSocket events (container.added, connection.event, port.listening, etc.)
- Timestamp, event type, node name, and full event data
- Useful for debugging and understanding system behavior

## Metrics

Prometheus metrics are available at `/metrics`:

- `netstatd_events_total{protocol,family}`: Total events by protocol (6=TCP, 17=UDP) and IP family (2=IPv4, 10=IPv6)
- `netstatd_events_by_state{protocol,family,state}`: Events by connection state (ESTABLISHED, CLOSE, etc.)

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

## Security Considerations

netstatd requires elevated privileges to function:

- **Privileged mode**: Required for loading eBPF programs
- **Host network**: Required to monitor all network connections
- **Host PID**: Required to correlate connections with containers
- **Read-only /proc**: Required for IP detection and port scanning

In production:

- Use network policies to restrict pod-to-pod communication
- Enable TLS/HTTPS for the web interface
- Implement authentication and authorization for WebSocket connections
- Consider using seccomp profiles to limit syscalls

## Building

```bash
# Build the container image
docker build -t netstatd .

# Or use the provided Skaffold configuration
skaffold build
```

## Development

Use `skaffold dev` or `docker compose up --build`.

When commiting changes clean up:

```
go fmt ./...
npx prettier cmd --write
```

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Disclaimer

This software is provided as-is without any warranties. Use at your own risk.

Developed by [codemowers.io](https://codemowers.io)
