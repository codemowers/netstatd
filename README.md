# netstatd

Real-time network connection monitoring for Kubernetes clusters using eBPF.

## Overview

netstatd is a Kubernetes DaemonSet that provides real-time visibility into network connections across your cluster. It uses eBPF to efficiently capture TCP and UDP connection events from the kernel and correlates them with container metadata from containerd.

## Features

- **Real-time Connection Tracking**: Monitor TCP and UDP connections as they happen
- **Container Correlation**: Automatically match connections to pods and containers
- **Listening Port Discovery**: Identify which services are exposed by each pod
- **DNS Integration**: Optional DNSTap collector for hostname resolution
- **Web Interface**: Interactive UI with four views (Connections, Ports, IPs, Deployment)
- **Cluster-wide View**: Multiplexer mode aggregates data from all nodes
- **Prometheus Metrics**: Built-in metrics endpoint for monitoring
- **IPv4 and IPv6 Support**: Full dual-stack networking support
- **Host Network Detection**: Automatically identifies pods using host networking

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

- `--log-level`: Set log level: trace, debug, info, warn, error (default: info)
- `--http-port`: HTTP port for single-pod server (default: 5280)
- `--http-mux-port`: HTTP port for multiplexer server (default: 6280)
- `--dnstap-port`: DNSTap port for single-pod server (default: 5253)
- `--dnstap-mux-port`: DNSTap port for multiplexer server (default: 6253)

## API

### REST API

- `GET /api/containers` - List containers with metadata (supports `?namespace=` and `?podName=` filters)
- `GET /api/pid-exe?pid=<pid>` - Resolve PID to executable name
- `GET /metrics` - Prometheus metrics

### WebSocket API

- `ws://host:5280/netstat` - Single pod events
- `ws://host:6280/netstat` - Cluster-wide fanout

### Event Types

- `host.info` - Host IP addresses and node information
- `container.added` - New container starts (includes `usesHostNetwork` flag)
- `container.deleted` - Container stops
- `connection.event` - TCP/UDP connection event from eBPF (includes PID and executable)
- `port.listening` - Listening port discovered (includes network namespace)

## Web Interface

The web interface provides four main views:

### Connections View

- Real-time list of active connections
- Filter by namespace, pod, node, protocol, state, port, IP family
- Visual indicators for pod, host, and external connections
- Executable name for each connection
- Support for loopback and host network filtering
- Color-coded connection endpoints (pod=green, host=blue, external=red)

### Ports View

- List of listening TCP/UDP ports
- Filter by IP, protocol, port number, node, executable
- Shows which pod/container owns each port
- Network namespace tracking
- Identifies host network pods

### IPs View

- All discovered IP addresses in the cluster
- Categorized as pod, host, or loopback
- Filter by IP, type, IP family, node
- Hostname resolution from DNS cache
- Automatic detection of host network pod IPs

### Deployment View

- Quick reference for deploying netstatd
- Example DaemonSet configuration
- Service definitions for headless and regular services

## Metrics

Prometheus metrics are available at `/metrics`:

- `netstatd_events_total{protocol,family}`: Total events by protocol and IP family
- `netstatd_events_by_state{protocol,family,state}`: Events by connection state

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

### Prerequisites

- Go 1.21+
- Linux development environment
- clang and llvm (for eBPF compilation)
- bpf2go tool: `go install github.com/cilium/ebpf/cmd/bpf2go@latest`

### Regenerate eBPF Code

```bash
cd internal/ebpf
go generate
```

### Run Locally

```bash
# Build
go build -o netstatd cmd/server/main.go

# Run (requires root for eBPF)
sudo ./netstatd --log-level=debug
```

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Disclaimer

This software is provided as-is without any warranties. Use at your own risk.

Developed by [codemowers.io](https://codemowers.io)
