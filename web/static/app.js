let ws = null;
let containers = new Map();
let connections = new Map();
let lastCleanupTime = 0;
const UDP_EXPIRE_MS = 10000; // 10 seconds
let eventCount = 0;
let eventCountsByType = {}; // Track counts per event type
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;
let namespaces = new Set();
let podNames = new Set();
let nodeNames = new Set();
let isConnected = false;
let shouldConnect = false;

// Track all active timeouts for cleanup
let activeTimeouts = new Set();

// IP to pod lookup table
let ipToPod = new Map();

// Host IPs by node
let hostIPsByNode = new Map();

// Persistent IP to pod metadata mapping (stored in localStorage)
let persistentPodIPs = new Map();

// Persistent IP to host metadata mapping (stored in localStorage)
let persistentHostIPs = new Map();

// Track all discovered IPs with their metadata
let discoveredIPs = new Map(); // key: ip, value: {type, podInfo, node, hostname}

// PID to executable cache
let pidToExe = new Map(); // key: pid, value: executable name

// Listening ports
let listeningPorts = new Map(); // key: "protocol:ip:port:netns:node", value: port info

const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const connectionsList = document.getElementById("connectionsList");
const eventCountEl = document.getElementById("eventCount");

// Filter elements
const filterNamespace = document.getElementById("filterNamespace");
const filterPod = document.getElementById("filterPod");
const filterNode = document.getElementById("filterNode");
const filterProtocol = document.getElementById("filterProtocol");
const filterState = document.getElementById("filterState");
const filterPortType = document.getElementById("filterPortType");
const filterPort = document.getElementById("filterPort");
const filterIPFamily = document.getElementById("filterIPFamily");
const filterLoopback = document.getElementById("filterLoopback");
const filterHost = document.getElementById("filterHost");
const filterPodCheckbox = document.getElementById("filterPodCheckbox");
const filterDedup = document.getElementById("filterDedup");
const filterExternal = document.getElementById("filterExternal");
const toggleButton = document.getElementById("toggleConnection");

// IP view filter elements
const filterIP = document.getElementById("filterIP");
const filterIPType = document.getElementById("filterIPType");
const filterIPFamilyIPs = document.getElementById("filterIPFamilyIPs");
const filterIPNode = document.getElementById("filterIPNode");
const ipsList = document.getElementById("ipsList");

// Ports view filter elements
const filterPortIP = document.getElementById("filterPortIP");
const filterPortProtocol = document.getElementById("filterPortProtocol");
const filterPortNumber = document.getElementById("filterPortNumber");
const filterPortNode = document.getElementById("filterPortNode");
const filterPortExe = document.getElementById("filterPortExe");
const portsList = document.getElementById("portsList");

// Services mapping (port/protocol -> service name)
let services = {};

function getServiceName(port, protocol) {
  // Return port as string - no service name decoding
  return port.toString();
}

function connect() {
  if (!shouldConnect) return;

  // Clear existing connections when reconnecting
  connections.clear();
  renderConnections();

  // Determine which WebSocket endpoint to use
  // Check if we're on the multiplexer port (6280) or single-pod port (5280)
  const port = window.location.port;
  let wsPath;

  if (port === "6280") {
    // On multiplexer port, use the fanout endpoint
    wsPath = "/netstat";
  } else {
    // On single-pod port, use regular endpoint
    wsPath = "/netstat";
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}${wsPath}`;

  console.log(`Connecting to WebSocket: ${wsUrl}`);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log("WebSocket connected");
    isConnected = true;
    statusIndicator.classList.add("connected");
    statusIndicator.classList.remove("disconnected");
    statusText.textContent = "Connected";
    toggleButton.textContent = "Stop";
    toggleButton.classList.add("connected");
    toggleButton.classList.remove("disconnected");
    reconnectAttempts = 0;
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleEvent(data);
    } catch (e) {
      console.error("Failed to parse message:", e);
    }
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  ws.onclose = () => {
    console.log("WebSocket disconnected");
    isConnected = false;
    statusIndicator.classList.remove("connected");
    statusIndicator.classList.add("disconnected");
    statusText.textContent = "Disconnected";
    toggleButton.textContent = "Start";
    toggleButton.classList.remove("connected");
    toggleButton.classList.add("disconnected");

    // Attempt to reconnect only if shouldConnect is true
    if (shouldConnect && reconnectAttempts < maxReconnectAttempts) {
      reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
      statusText.textContent = `Reconnecting in ${delay / 1000}s...`;
      setTimeout(connect, delay);
    } else if (!shouldConnect) {
      statusText.textContent = "Stopped";
    } else {
      statusText.textContent = "Connection failed";
    }
  };
}

function disconnect() {
  shouldConnect = false;
  if (ws) {
    ws.close();
    ws = null;
  }

  // Cancel all active timeouts
  for (const timeoutId of activeTimeouts) {
    clearTimeout(timeoutId);
  }
  activeTimeouts.clear();

  // Don't clear connections when stopping - keep them visible for inspection
  // Only clear animation flags
  for (const [key, conn] of connections.entries()) {
    conn.isNew = false;
    conn.isDestroyed = false;
  }

  // Re-render to show current state without animations
  renderConnections();
}

function toggleConnection() {
  if (isConnected || shouldConnect) {
    disconnect();
  } else {
    // Clear connections before reconnecting to start fresh
    connections.clear();
    // Also clear discovered IPs
    discoveredIPs.clear();
    // Clear container and runtime IP lookup maps (but keep persistent ones)
    containers.clear();
    ipToPod.clear();
    hostIPsByNode.clear();
    // Clear filter sets
    namespaces.clear();
    podNames.clear();
    nodeNames.clear();
    updateFilterDropdowns();

    shouldConnect = true;
    connect();
  }
}

function handleEvent(event) {
  eventCount++;
  eventCountEl.textContent = eventCount;

  // Track event counts by type
  if (!eventCountsByType[event.type]) {
    eventCountsByType[event.type] = 0;
  }
  eventCountsByType[event.type]++;

  // Store node name if present
  const nodeName = event.nodeName || "unknown";

  switch (event.type) {
    case "host.info":
      handleHostInfo(event, nodeName);
      break;
    case "container.added":
      handleContainerAdded(event, nodeName);
      break;
    case "container.deleted":
      handleContainerDeleted(event);
      break;
    case "connection.event":
      handleConnectionEvent(event, nodeName);
      break;
    case "port.listening":
      handlePortListening(event, nodeName);
      break;
    default:
      console.warn("Unknown event type:", event.type);
  }

  // Event count is updated directly above, no need for updateStats()
}

function handleHostInfo(data, nodeName) {
  const hostIPs = data.hostIPs || [];
  hostIPsByNode.set(nodeName, hostIPs);

  // Update discovered IPs
  for (const ip of hostIPs) {
    discoveredIPs.set(ip, {
      type: "host",
      podInfo: null,
      node: nodeName,
      hostname: null,
    });
  }
  renderIPs();
}

function handleContainerAdded(data, nodeName) {
  const uid = data.podUID || data.containerUID || data.containerId;

  const podIPs = data.podIPs || [];

  // Use the usesHostNetwork flag from the backend (more reliable than IP comparison)
  const usesHostNetwork = data.usesHostNetwork || false;

  containers.set(uid, {
    id: data.containerId,
    name: data.name,
    namespace: data.namespace,
    pid: data.pid,
    podName: data.podName,
    containerName: data.containerName,
    labels: data.labels,
    annotations: data.annotations,
    podIPs: podIPs,
    nodeName: nodeName,
    usesHostNetwork: usesHostNetwork,
  });

  // Build IP to pod lookup table only if not using host network
  if (!usesHostNetwork && podIPs.length > 0) {
    for (const ip of podIPs) {
      ipToPod.set(ip, {
        uid: uid,
        namespace: data.namespace,
        podName: data.podName,
        containerName: data.containerName,
        nodeName: nodeName,
      });

      // Add to discovered IPs
      discoveredIPs.set(ip, {
        type: "pod",
        podInfo: {
          namespace: data.namespace,
          podName: data.podName,
          containerName: data.containerName,
        },
        node: nodeName,
        hostname: null,
      });
    }
  } else if (usesHostNetwork) {
    // Still add to discovered IPs as host network IPs
    for (const ip of podIPs) {
      discoveredIPs.set(ip, {
        type: "host",
        podInfo: {
          namespace: data.namespace,
          podName: data.podName,
          containerName: data.containerName,
        },
        node: nodeName,
        hostname: null,
      });
    }
  }

  // Update namespace and pod name sets for filters
  if (data.namespace) {
    namespaces.add(data.namespace);
  }
  if (data.podName) {
    podNames.add(data.podName);
  }
  updateFilterDropdowns();
  renderIPs();
}

function handleContainerDeleted(event) {
  const container = containers.get(event.containerUID);

  // Remove from IP lookup table
  if (container && container.podIPs) {
    for (const ip of container.podIPs) {
      ipToPod.delete(ip);
    }
  }

  containers.delete(event.containerUID);
  // Remove connections for this container
  for (const [key, conn] of connections.entries()) {
    if (conn.containerUID === event.containerUID) {
      connections.delete(key);
    }
  }
  renderConnections();
}

function handlePortListening(data, nodeName) {
  // Create unique key using node name, IP, port, and network namespace inode
  // This prevents flapping when multiple processes in different namespaces use the same port
  const key = `${nodeName}:${data.ip}:${data.port}:${data.netns || 0}`;

  // Store port info
  const portInfo = {
    protocol: data.protocol,
    ip: data.ip,
    port: data.port,
    pid: data.pid,
    exe: data.exe || "",
    netns: data.netns || 0,
    nodeName: nodeName,
    podName: data.podName || "",
    namespace: data.namespace || "",
    containerName: data.containerName || "",
  };

  listeningPorts.set(key, portInfo);

  // Update IP mappings based on listening port
  if (data.ip) {
    // Check if this is a pod IP (has pod metadata)
    if (data.namespace && data.podName) {
      updatePodIPMapping(data.ip, portInfo);
    } else {
      // Otherwise treat as host IP
      updateHostIPMapping(data.ip, portInfo);
    }
  }

  renderPorts();
}

function handleConnectionEvent(event, nodeName) {
  // This function handles both TCP and UDP connection events
  const key = getConnectionKey(event, nodeName);
  const existing = connections.get(key);
  const now = Date.now();

  // State is a string from the backend (or null/empty for unknown)
  const state = event.state || "-";
  // Protocol is a string from the backend (empty if unknown)
  const protocol = event.protocol || "";

  // Cache executable name if provided by server
  if (event.pid && event.pid > 0 && event.exe) {
    pidToExe.set(event.pid, event.exe);
  }

  // Only resolve PID to executable if we don't have it cached and server didn't send it
  if (event.pid && event.pid > 0 && !pidToExe.has(event.pid) && !event.exe) {
    resolvePidToExe(event.pid);
  }

  // Check if this is a CLOSE event
  const isCloseEvent = protocol === "TCP" && state === "CLOSE";

  // Add IPs to discovered IPs
  const ipsToAdd = [event.sourceIP, event.destIP];
  for (const ip of ipsToAdd) {
    if (!discoveredIPs.has(ip)) {
      // Check if it's a loopback IP
      const isLoopback = ip.startsWith("127.") || ip === "::1";
      if (isLoopback) {
        discoveredIPs.set(ip, {
          type: "loopback",
          podInfo: null,
          node: nodeName,
          hostname: null,
        });
      }
    }
  }

  if (existing) {
    // Update existing connection
    existing.protocol = protocol;
    existing.state = state;
    existing.isNew = false;
    existing.lastSeen = now; // Update timestamp

    // If this is a CLOSE event, mark for removal
    if (isCloseEvent) {
      existing.isDestroyed = true;
      // Remove after 10 seconds to match the fadeOut animation duration
      const timeoutId = setTimeout(() => {
        connections.delete(key);
        activeTimeouts.delete(timeoutId);
        renderConnections();
      }, 10000);
      activeTimeouts.add(timeoutId);
    }
  } else {
    // If this is a CLOSE event for a connection we never saw, skip it
    // (connection was already closed before we started monitoring)
    if (isCloseEvent) {
      return;
    }

    // Create new connection - store string values
    connections.set(key, {
      protocol: protocol || "",
      sourceIP: event.sourceIP,
      sourcePort: event.sourcePort,
      destIP: event.destIP,
      destPort: event.destPort,
      state: state,
      direction: event.direction,
      nodeName: nodeName,
      sockCookie: event.sockCookie || 0,
      pid: event.pid || 0,
      cgroupSlice: event.cgroupSlice || "",
      isNew: true,
      isDestroyed: false,
      lastSeen: now, // Add timestamp
    });

    // Track node names
    if (nodeName) {
      nodeNames.add(nodeName);
      updateFilterDropdowns();
    }

    // Remove new flag after animation
    const timeoutId = setTimeout(() => {
      const conn = connections.get(key);
      if (conn) {
        conn.isNew = false;
        renderConnections();
      }
      activeTimeouts.delete(timeoutId);
    }, 500);
    activeTimeouts.add(timeoutId);
  }

  // Clean up old UDP connections periodically
  cleanupOldUDPConnections();

  renderConnections();
  renderIPs();
}

function resolvePidToExe(pid) {
  // Fetch executable name for this PID
  fetch(`/api/pid-exe?pid=${pid}`)
    .then((response) => response.json())
    .then((data) => {
      if (data.exe) {
        pidToExe.set(pid, data.exe);
        // Re-render connections to show the new executable
        renderConnections();
      }
    })
    .catch((error) => {
      console.debug("Failed to resolve PID to exe:", pid, error);
    });
}

function getConnectionKey(conn, nodeName) {
  // For TCP, always use socket cookie as primary tracking mechanism
  // Socket cookie is stable across the connection lifetime and works even when PID=0
  if (conn.protocol === "TCP" && conn.sockCookie && conn.sockCookie !== 0) {
    return `${nodeName}-cookie-${conn.sockCookie}`;
  }

  // For UDP or when socket cookie is unavailable, use endpoint-based key
  const ep1 = `${conn.sourceIP}:${conn.sourcePort}`;
  const ep2 = `${conn.destIP}:${conn.destPort}`;
  const [first, second] = ep1 < ep2 ? [ep1, ep2] : [ep2, ep1];

  return `${nodeName}-${conn.protocol}-${first}-${second}`;
}

function updateFilterDropdowns() {
  // Update namespace dropdown
  const currentNs = filterNamespace.value;
  const sortedNamespaces = Array.from(namespaces).sort();

  // Rebuild namespace datalist
  let nsDatalist = document.getElementById("namespaceList");
  if (!nsDatalist) {
    nsDatalist = document.createElement("datalist");
    nsDatalist.id = "namespaceList";
    filterNamespace.setAttribute("list", "namespaceList");
    filterNamespace.parentNode.appendChild(nsDatalist);
  }

  nsDatalist.innerHTML = sortedNamespaces
    .map((ns) => `<option value="${ns}">`)
    .join("");

  // Update pod dropdown
  const currentPod = filterPod.value;
  const sortedPods = Array.from(podNames).sort();

  // Rebuild pod datalist
  let podDatalist = document.getElementById("podList");
  if (!podDatalist) {
    podDatalist = document.createElement("datalist");
    podDatalist.id = "podList";
    filterPod.setAttribute("list", "podList");
    filterPod.parentNode.appendChild(podDatalist);
  }

  podDatalist.innerHTML = sortedPods
    .map((pod) => `<option value="${pod}">`)
    .join("");

  // Update node dropdown
  const currentNode = filterNode.value;
  const sortedNodes = Array.from(nodeNames).sort();

  // Rebuild node select options
  const firstOption = filterNode.querySelector('option[value=""]');
  filterNode.innerHTML = "";
  if (firstOption) {
    filterNode.appendChild(firstOption);
  } else {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "All Nodes";
    filterNode.appendChild(opt);
  }

  sortedNodes.forEach((node) => {
    const opt = document.createElement("option");
    opt.value = node;
    opt.textContent = node;
    if (node === currentNode) {
      opt.selected = true;
    }
    filterNode.appendChild(opt);
  });
}

function isLoopbackConnection(conn) {
  // Check if either IP is loopback (127.0.0.0/8 or ::1)
  return (
    conn.sourceIP.startsWith("127.") ||
    conn.sourceIP === "::1" ||
    conn.destIP.startsWith("127.") ||
    conn.destIP === "::1"
  );
}

function isHostConnection(conn) {
  // Check if either IP is a host IP
  for (const [nodeName, ips] of hostIPsByNode.entries()) {
    if (ips.includes(conn.sourceIP) || ips.includes(conn.destIP)) {
      return true;
    }
  }
  return false;
}

function isPodConnection(conn) {
  // Check if at least one endpoint is a pod (not host and not loopback)
  const srcPod = getPodInfoForIP(conn.sourceIP);
  const dstPod = getPodInfoForIP(conn.destIP);

  // Also check if they're not host IPs
  const srcIsHost = isHostIP(conn.sourceIP);
  const dstIsHost = isHostIP(conn.destIP);

  // At least one endpoint should be a pod and not host IP
  return (srcPod && !srcIsHost) || (dstPod && !dstIsHost);
}

function isExternalConnection(conn) {
  // Check if at least one endpoint is external (not pod, not host, not loopback)
  const srcPod = getPodInfoForIP(conn.sourceIP);
  const dstPod = getPodInfoForIP(conn.destIP);
  const srcIsHost = isHostIP(conn.sourceIP);
  const dstIsHost = isHostIP(conn.destIP);
  const isLoopback = isLoopbackConnection(conn);

  // External if at least one endpoint is not pod, not host, and not loopback
  const srcIsExternal = !srcPod && !srcIsHost && !isLoopback;
  const dstIsExternal = !dstPod && !dstIsHost && !isLoopback;

  return srcIsExternal || dstIsExternal;
}

function isHostIP(ip) {
  // Check if IP is a host IP
  for (const [nodeName, ips] of hostIPsByNode.entries()) {
    if (ips.includes(ip)) {
      return true;
    }
  }
  return false;
}

function getIPFamily(ip) {
  // Check if IP is IPv4 or IPv6
  if (ip.includes(".")) {
    return "ipv4";
  } else if (ip.includes(":")) {
    return "ipv6";
  }
  return "unknown";
}

function matchesFilters(conn, container) {
  const namespace = filterNamespace.value.toLowerCase();
  const pod = filterPod.value.toLowerCase();
  const node = filterNode.value.toLowerCase();
  const protocol = filterProtocol.value.toLowerCase();
  const state = filterState.value;
  const portType = filterPortType.value;
  const portValue = filterPort.value;
  const ipFamily = filterIPFamily.value;
  const showLoopback = filterLoopback.checked;
  const showHost = filterHost.checked;
  const showPod = filterPodCheckbox.checked;
  const showExternal = filterExternal ? filterExternal.checked : true;

  // Get listening ports for marking
  const listeningPortsSet = new Set();
  for (const [key, port] of listeningPorts.entries()) {
    // Create key as "protocol:ip:port"
    const portKey = `${port.protocol}:${port.ip}:${port.port}`;
    listeningPortsSet.add(portKey);
  }

  // Filter by IP family
  if (ipFamily) {
    const srcFamily = getIPFamily(conn.sourceIP);
    const dstFamily = getIPFamily(conn.destIP);
    // Show connection if either endpoint matches the selected family
    if (srcFamily !== ipFamily && dstFamily !== ipFamily) {
      return false;
    }
  }

  // Filter loopback connections - include if either endpoint is loopback
  if (!showLoopback && isLoopbackConnection(conn)) {
    return false;
  }

  // Filter host connections - include if either endpoint is host
  if (!showHost && isHostConnection(conn)) {
    return false;
  }

  // Filter pod connections - hide if pod checkbox is unchecked and connection involves a pod
  if (!showPod && isPodConnection(conn)) {
    return false;
  }

  // Filter external connections - hide if external checkbox is unchecked and connection involves external
  if (!showExternal && isExternalConnection(conn)) {
    return false;
  }

  // Match node
  if (node && conn.nodeName?.toLowerCase() !== node) {
    return false;
  }

  // Match protocol by name (protocol is now a string)
  if (protocol && conn.protocol.toLowerCase() !== protocol) {
    return false;
  }

  // Match state by name (state is now a string)
  if (state && conn.state !== state) {
    return false;
  }

  // Match port
  if (portValue) {
    const portNum = parseInt(portValue, 10);
    if (!isNaN(portNum)) {
      if (portType === "local") {
        // Match local port (source port)
        if (conn.sourcePort !== portNum) {
          return false;
        }
      } else if (portType === "remote") {
        // Match remote port (destination port)
        if (conn.destPort !== portNum) {
          return false;
        }
      } else {
        // Match any port (source or destination)
        if (conn.sourcePort !== portNum && conn.destPort !== portNum) {
          return false;
        }
      }
    }
  }

  if (container) {
    if (namespace && !container.namespace?.toLowerCase().includes(namespace)) {
      return false;
    }
    if (pod && !container.podName?.toLowerCase().includes(pod)) {
      return false;
    }
  } else if (namespace || pod) {
    return false;
  }

  return true;
}

function getNodeNameForHostIP(ip) {
  // First check runtime hostIPsByNode
  for (const [nodeName, ips] of hostIPsByNode.entries()) {
    if (ips.includes(ip)) {
      return nodeName;
    }
  }

  // Then check persistent storage
  const hostInfo = persistentHostIPs.get(ip);
  if (hostInfo && hostInfo.nodeName) {
    return hostInfo.nodeName;
  }

  return null;
}

function cleanupOldUDPConnections() {
  const now = Date.now();
  // Only clean up every 5 seconds to avoid performance issues
  if (now - lastCleanupTime < 5000) {
    return;
  }
  lastCleanupTime = now;

  let needsRender = false;
  for (const [key, conn] of connections.entries()) {
    // Only process UDP connections (protocol is now a string)
    if (conn.protocol === "UDP" && conn.lastSeen) {
      const age = now - conn.lastSeen;
      if (age > UDP_EXPIRE_MS) {
        // Mark as destroyed and schedule removal
        conn.isDestroyed = true;
        const timeoutId = setTimeout(() => {
          connections.delete(key);
          activeTimeouts.delete(timeoutId);
          renderConnections();
        }, 10000); // Match the fadeOut animation duration
        activeTimeouts.add(timeoutId);
        needsRender = true;
      }
    }
  }
  if (needsRender) {
    renderConnections();
  }
}

function renderConnections() {
  // Get listening ports for marking
  const listeningPortsSet = new Set();
  for (const [key, port] of listeningPorts.entries()) {
    // Create key as "protocol:ip:port"
    const portKey = `${port.protocol}:${port.ip}:${port.port}`;
    listeningPortsSet.add(portKey);
  }

  let filteredConnections = Array.from(connections.values())
    .map((conn) => {
      // Check if either IP is a host IP
      const hostIPs = hostIPsByNode.get(conn.nodeName) || [];
      const srcIsHost = hostIPs.includes(conn.sourceIP);
      const dstIsHost = hostIPs.includes(conn.destIP);

      // Use IP lookup table to find pod info (check both runtime and persistent)
      const srcPod = getPodInfoForIP(conn.sourceIP);
      const dstPod = getPodInfoForIP(conn.destIP);

      // Prefer source pod, fall back to dest pod
      const matchedPod = srcPod || dstPod;
      const matchedContainer = matchedPod
        ? containers.get(matchedPod.uid)
        : null;

      return {
        conn,
        container: matchedContainer,
        srcPod,
        dstPod,
        srcIsHost,
        dstIsHost,
      };
    })
    .filter(({ conn, container }) => {
      return matchesFilters(conn, container);
    });

  // Apply deduplication if checkbox is checked
  if (filterDedup && filterDedup.checked) {
    const dedupMap = new Map();

    for (const item of filteredConnections) {
      const conn = item.conn;

      // Create a canonical key by sorting the endpoints
      const ep1 = `${conn.sourceIP}:${conn.sourcePort}`;
      const ep2 = `${conn.destIP}:${conn.destPort}`;

      // Sort endpoints to create a consistent key
      const [first, second] = ep1 < ep2 ? [ep1, ep2] : [ep2, ep1];
      const dedupKey = `${conn.protocol}-${first}-${second}`;

      // Check if we already have this connection
      const existing = dedupMap.get(dedupKey);

      if (!existing) {
        // First time seeing this connection pair
        dedupMap.set(dedupKey, item);
      } else {
        // We have a duplicate - keep the one with lower local port
        // Determine which connection has the lower local port
        if (conn.sourcePort < existing.conn.sourcePort) {
          dedupMap.set(dedupKey, item);
        }
      }
    }

    filteredConnections = Array.from(dedupMap.values());
  }

  if (filteredConnections.length === 0) {
    connectionsList.innerHTML =
      '<tr><td colspan="9" class="empty-state">No connections match the current filters</td></tr>';
    return;
  }

  connectionsList.innerHTML = filteredConnections
    .map(({ conn, container, srcPod, dstPod, srcIsHost, dstIsHost }) => {
      const rowClass = conn.isNew ? "new" : conn.isDestroyed ? "destroyed" : "";
      const nodeName = conn.nodeName || "-";

      // Get service names (currently just returns port number)
      const srcService = getServiceName(conn.sourcePort, conn.protocol);
      const dstService = getServiceName(conn.destPort, conn.protocol);

      // Format port with service name: "443 (https)" or just "443" if no service
      // Check if ports are listening (protocol is now a string like "TCP" or "UDP")
      const srcPortKey = `${conn.protocol}:${conn.sourceIP}:${conn.sourcePort}`;
      const dstPortKey = `${conn.protocol}:${conn.destIP}:${conn.destPort}`;
      const srcIsListening = listeningPortsSet.has(srcPortKey);
      const dstIsListening = listeningPortsSet.has(dstPortKey);

      const srcPortDisplay =
        conn.sourcePort === 0
          ? "-"
          : srcService !== conn.sourcePort.toString()
            ? `${conn.sourcePort} (${srcService})${srcIsListening ? " 🎧" : ""}`
            : `${conn.sourcePort}${srcIsListening ? " 🎧" : ""}`;

      const dstPortDisplay =
        conn.destPort === 0
          ? "-"
          : dstService !== conn.destPort.toString()
            ? `${conn.destPort} (${dstService})${dstIsListening ? " 🎧" : ""}`
            : `${conn.destPort}${dstIsListening ? " 🎧" : ""}`;

      // State is a string from the backend (or "-" for unknown)
      const stateName = conn.state || "-";

      // Get executable name from PID
      const exe = conn.pid && conn.pid > 0 ? pidToExe.get(conn.pid) || "" : "";

      // Get cgroup slice
      const cgroupDisplay = conn.cgroupSlice || "-";

      // Check if source is loopback
      const srcIsLoopback =
        conn.sourceIP.startsWith("127.") || conn.sourceIP === "::1";
      // Check if destination is loopback
      const dstIsLoopback =
        conn.destIP.startsWith("127.") || conn.destIP === "::1";

      // Determine source type and color
      let srcType, srcColor, srcDisplay;
      if (srcIsLoopback) {
        srcType = "loopback";
        srcColor = "#808080"; // Gray for localhost
        srcDisplay = `localhost (${conn.sourceIP})`;
      } else if (srcIsHost) {
        srcType = "host";
        srcColor = "#0077FF"; // More blue
        // Get node name for this host IP
        const hostNodeName = getNodeNameForHostIP(conn.sourceIP) || nodeName;
        srcDisplay = `${hostNodeName} (${conn.sourceIP})`;
      } else if (srcPod) {
        srcType = "pod";
        srcColor = "#00AA00"; // More green
        srcDisplay = `${srcPod.namespace}/${srcPod.podName} (${conn.sourceIP})`;
      } else {
        srcType = "external";
        srcColor = "#FF0000"; // Bright Red - more saturated
        srcDisplay = conn.sourceIP;
      }

      // Determine destination type and color
      let dstType, dstColor, dstDisplay;
      if (dstIsLoopback) {
        dstType = "loopback";
        dstColor = "#808080"; // Gray for localhost
        dstDisplay = `localhost (${conn.destIP})`;
      } else if (dstIsHost) {
        dstType = "host";
        dstColor = "#0077FF"; // More blue
        // Get node name for this host IP
        const hostNodeName = getNodeNameForHostIP(conn.destIP) || nodeName;
        dstDisplay = `${hostNodeName} (${conn.destIP})`;
      } else if (dstPod) {
        dstType = "pod";
        dstColor = "#00AA00"; // More green
        dstDisplay = `${dstPod.namespace}/${dstPod.podName} (${conn.destIP})`;
      } else {
        dstType = "external";
        dstColor = "#FF0000"; // Bright Red - more saturated
        dstDisplay = conn.destIP;
      }

      // Create tooltip with full details
      const srcTooltip = srcDisplay;
      const dstTooltip = dstDisplay;

      return `
            <tr class="${rowClass}">
                <td class="protocol">${conn.protocol}</td>
                <td class="state">${stateName}</td>
                <td class="address" title="${srcTooltip}">
                    <span class="address-circle" style="color: ${srcColor}">●</span>
                    <span class="address-text">${srcDisplay}</span>
                </td>
                <td class="port">${srcPortDisplay}</td>
                <td class="address" title="${dstTooltip}">
                    <span class="address-circle" style="color: ${dstColor}">●</span>
                    <span class="address-text">${dstDisplay}</span>
                </td>
                <td class="port">${dstPortDisplay}</td>
                <td class="node-name">${nodeName}</td>
            </tr>
        `;
    })
    .join("");
}

function renderPorts() {
  const ipFilter = filterPortIP ? filterPortIP.value.toLowerCase() : "";
  const protocolFilter = filterPortProtocol ? filterPortProtocol.value : "";
  const portFilter = filterPortNumber ? filterPortNumber.value : "";
  const nodeFilter = filterPortNode ? filterPortNode.value.toLowerCase() : "";
  const exeFilter = filterPortExe ? filterPortExe.value.toLowerCase() : "";

  const filteredPorts = Array.from(listeningPorts.values()).filter((port) => {
    // Filter by IP
    if (ipFilter && !port.ip.toLowerCase().includes(ipFilter)) {
      return false;
    }
    // Filter by protocol
    if (protocolFilter && port.protocol.toString() !== protocolFilter) {
      return false;
    }
    // Filter by port number
    if (portFilter && port.port.toString() !== portFilter) {
      return false;
    }
    // Filter by node
    if (
      nodeFilter &&
      (!port.nodeName || !port.nodeName.toLowerCase().includes(nodeFilter))
    ) {
      return false;
    }
    // Filter by executable
    if (
      exeFilter &&
      (!port.exe || !port.exe.toLowerCase().includes(exeFilter))
    ) {
      return false;
    }
    return true;
  });

  // Sort ports: first by protocol, then by port number
  filteredPorts.sort((a, b) => {
    if (a.protocol !== b.protocol) {
      return a.protocol - b.protocol;
    }
    return a.port - b.port;
  });

  if (filteredPorts.length === 0) {
    portsList.innerHTML =
      '<tr><td colspan="11" class="empty-state">No listening ports match the current filters</td></tr>';
    return;
  }

  // Sort ports by IP address and port number
  filteredPorts.sort((a, b) => {
    // First compare IP addresses
    const ipA = a.ip || "";
    const ipB = b.ip || "";

    // Handle IPv4 vs IPv6 sorting
    // IPv4 addresses come before IPv6 addresses
    const isIPv4A = ipA.includes(".");
    const isIPv4B = ipB.includes(".");

    if (isIPv4A && !isIPv4B) return -1;
    if (!isIPv4A && isIPv4B) return 1;

    // Both are same type, do string comparison
    if (ipA < ipB) return -1;
    if (ipA > ipB) return 1;

    // If IPs are equal, compare port numbers
    return (a.port || 0) - (b.port || 0);
  });

  portsList.innerHTML = filteredPorts
    .map((port) => {
      const protocolName = port.protocol;
      const nodeDisplay = port.nodeName || "-";
      const exeDisplay = port.exe || "-";
      const netnsDisplay = port.netns && port.netns !== 0 ? port.netns : "-";
      const pidDisplay = port.pid && port.pid !== 0 ? port.pid : "-";

      const namespaceDisplay = port.namespace || "-";
      const podNameDisplay = port.podName || "-";
      const containerNameDisplay = port.containerName || "-";

      return `
            <tr>
                <td class="protocol">${protocolName}</td>
                <td class="ip-address">${port.ip}</td>
                <td class="port">${port.port}</td>
                <td class="node-name">${nodeDisplay}</td>
                <td class="pid">${pidDisplay}</td>
                <td class="executable">${exeDisplay}</td>
                <td class="ip-namespace">${namespaceDisplay}</td>
                <td class="ip-pod">${podNameDisplay}</td>
                <td class="container-name">${containerNameDisplay}</td>
                <td class="netns">${netnsDisplay}</td>
                <td class="cgroup-slice">${port.cgroupSlice || "-"}</td>
            </tr>
        `;
    })
    .join("");
}

function renderIPs() {
  const ipFilter = filterIP.value.toLowerCase();
  const typeFilter = filterIPType.value;
  const ipFamilyFilter = filterIPFamilyIPs.value;
  const nodeFilter = filterIPNode.value.toLowerCase();

  const filteredIPs = Array.from(discoveredIPs.entries()).filter(
    ([ip, info]) => {
      // Filter by IP
      if (ipFilter && !ip.toLowerCase().includes(ipFilter)) {
        return false;
      }
      // Filter by type
      if (typeFilter && info.type !== typeFilter) {
        return false;
      }
      // Filter by IP family
      if (ipFamilyFilter) {
        const ipFamily = getIPFamily(ip);
        if (ipFamily !== ipFamilyFilter) {
          return false;
        }
      }
      // Filter by node
      if (
        nodeFilter &&
        (!info.node || !info.node.toLowerCase().includes(nodeFilter))
      ) {
        return false;
      }
      return true;
    },
  );

  // Sort IPs: first by type, then by IP address
  filteredIPs.sort((a, b) => {
    const [ipA, infoA] = a;
    const [ipB, infoB] = b;

    // Sort by type first
    const typeOrder = { pod: 1, host: 2, loopback: 3 };
    const typeA = infoA.type;
    const typeB = infoB.type;
    if (typeA !== typeB) {
      return (typeOrder[typeA] || 4) - (typeOrder[typeB] || 4);
    }

    // Then sort by IP address
    // For IPv4 addresses, we can sort numerically
    const isIPv4A = ipA.includes(".");
    const isIPv4B = ipB.includes(".");

    if (isIPv4A && !isIPv4B) return -1;
    if (!isIPv4A && isIPv4B) return 1;

    if (isIPv4A && isIPv4B) {
      // Sort IPv4 numerically
      const partsA = ipA.split(".").map(Number);
      const partsB = ipB.split(".").map(Number);
      for (let i = 0; i < 4; i++) {
        if (partsA[i] !== partsB[i]) {
          return partsA[i] - partsB[i];
        }
      }
      return 0;
    } else {
      // Sort IPv6 lexicographically
      return ipA.localeCompare(ipB);
    }
  });

  if (filteredIPs.length === 0) {
    ipsList.innerHTML =
      '<tr><td colspan="6" class="empty-state">No IPs match the current filters</td></tr>';
    return;
  }

  ipsList.innerHTML = filteredIPs
    .map(([ip, info]) => {
      // Determine if it's a loopback IP
      const isLoopback = ip.startsWith("127.") || ip === "::1";
      const displayType = isLoopback ? "loopback" : info.type;

      let podDisplay = "-";
      if (info.podInfo) {
        // Only show pod name and container name, not namespace (it's in a separate column)
        podDisplay = info.podInfo.podName;
        if (info.podInfo.containerName) {
          podDisplay += ` (${info.podInfo.containerName})`;
        }
      }

      const nodeDisplay = info.node || "-";
      const hostnameDisplay = info.hostname || "-";
      const namespaceDisplay = info.podInfo?.namespace || "-";

      return `
            <tr>
                <td class="ip-address">${ip}</td>
                <td class="ip-type">${displayType}</td>
                <td class="ip-pod">${podDisplay}</td>
                <td class="ip-namespace">${namespaceDisplay}</td>
                <td class="ip-node">${nodeDisplay}</td>
                <td class="ip-hostname">${hostnameDisplay}</td>
            </tr>
        `;
    })
    .join("");
}

function updateStats() {
  // Only event count is displayed now, which is updated in handleEvent()
  // No need to update containerCount and connectionCount
}

// View switching functionality
function setupViewSwitching() {
  const navLinks = document.querySelectorAll(".nav-link");
  const views = document.querySelectorAll(".view");

  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();

      // Get the target view
      const targetView = link.getAttribute("data-view");

      // Update active nav link
      navLinks.forEach((l) => l.classList.remove("active"));
      link.classList.add("active");

      // Show target view, hide others
      views.forEach((view) => {
        view.classList.remove("active");
        if (view.id === `${targetView}View`) {
          view.classList.add("active");
        }
      });

      // If switching to connections view, make sure to render connections
      if (targetView === "connections") {
        renderConnections();
      }
      // If switching to ports view, render ports
      if (targetView === "ports") {
        renderPorts();
      }
      // If switching to IPs view, render IPs
      if (targetView === "ips") {
        renderIPs();
      }
    });
  });
}

// Helper function to print event counts by type
function printEventCountsByType() {
  console.log("=== Event Counts by Type ===");
  const sortedTypes = Object.keys(eventCountsByType).sort();
  for (const type of sortedTypes) {
    console.log(`${type}: ${eventCountsByType[type]}`);
  }
  console.log(`Total events: ${eventCount}`);
  console.log(`Total connections stored: ${connections.size}`);
  console.log("============================");
  return eventCountsByType;
}

// Function to clear persistent mappings (for debugging)
function clearPersistentMappings() {
  localStorage.removeItem("netstatd_pod_ips");
  localStorage.removeItem("netstatd_host_ips");
  persistentPodIPs.clear();
  persistentHostIPs.clear();
  console.log("Persistent mappings cleared");
}

// Make functions available globally for debugging
window.printEventCountsByType = printEventCountsByType;
window.clearPersistentMappings = clearPersistentMappings;
window.getPersistentPodIPs = () => persistentPodIPs;
window.getPersistentHostIPs = () => persistentHostIPs;

// Load persistent mappings from localStorage
function loadPersistentMappings() {
  try {
    const podData = localStorage.getItem("netstatd_pod_ips");
    if (podData) {
      const parsed = JSON.parse(podData);
      for (const [ip, info] of Object.entries(parsed)) {
        persistentPodIPs.set(ip, info);
      }
    }
  } catch (e) {
    console.error("Failed to load pod IP mappings:", e);
  }

  try {
    const hostData = localStorage.getItem("netstatd_host_ips");
    if (hostData) {
      const parsed = JSON.parse(hostData);
      for (const [ip, info] of Object.entries(parsed)) {
        persistentHostIPs.set(ip, info);
      }
    }
  } catch (e) {
    console.error("Failed to load host IP mappings:", e);
  }
}

// Save persistent mappings to localStorage
function savePersistentMappings() {
  try {
    const podObj = Object.fromEntries(persistentPodIPs);
    localStorage.setItem("netstatd_pod_ips", JSON.stringify(podObj));
  } catch (e) {
    console.error("Failed to save pod IP mappings:", e);
  }

  try {
    const hostObj = Object.fromEntries(persistentHostIPs);
    localStorage.setItem("netstatd_host_ips", JSON.stringify(hostObj));
  } catch (e) {
    console.error("Failed to save host IP mappings:", e);
  }
}

// Update pod IP mapping from listening port
function updatePodIPMapping(ip, portInfo) {
  if (!ip || !portInfo) return;

  const mapping = {
    namespace: portInfo.namespace || "",
    podName: portInfo.podName || "",
    containerName: portInfo.containerName || "",
    nodeName: portInfo.nodeName || "",
    timestamp: Date.now(),
  };

  persistentPodIPs.set(ip, mapping);
  savePersistentMappings();

  // Also update the runtime ipToPod map
  ipToPod.set(ip, {
    uid: `${mapping.namespace}-${mapping.podName}-${mapping.containerName}`,
    namespace: mapping.namespace,
    podName: mapping.podName,
    containerName: mapping.containerName,
    nodeName: mapping.nodeName,
  });
}

// Update host IP mapping from listening port
function updateHostIPMapping(ip, portInfo) {
  if (!ip || !portInfo) return;

  const mapping = {
    nodeName: portInfo.nodeName || "",
    timestamp: Date.now(),
  };

  persistentHostIPs.set(ip, mapping);
  savePersistentMappings();
}

// Get pod info for IP (check runtime first, then persistent storage)
function getPodInfoForIP(ip) {
  // First check runtime ipToPod map (from container events)
  const runtimeInfo = ipToPod.get(ip);
  if (runtimeInfo) {
    return runtimeInfo;
  }

  // Then check persistent storage
  const persistentInfo = persistentPodIPs.get(ip);
  if (persistentInfo) {
    return {
      uid: `${persistentInfo.namespace}-${persistentInfo.podName}-${persistentInfo.containerName}`,
      namespace: persistentInfo.namespace,
      podName: persistentInfo.podName,
      containerName: persistentInfo.containerName,
      nodeName: persistentInfo.nodeName,
    };
  }

  return null;
}

// Get host info for IP (check runtime first, then persistent storage)
function getHostInfoForIP(ip) {
  // First check if it's a known host IP in runtime
  for (const [nodeName, ips] of hostIPsByNode.entries()) {
    if (ips.includes(ip)) {
      return { nodeName };
    }
  }

  // Then check persistent storage
  const persistentInfo = persistentHostIPs.get(ip);
  if (persistentInfo) {
    return { nodeName: persistentInfo.nodeName };
  }

  return null;
}

// Initialize the application
function init() {
  // Load persistent mappings
  loadPersistentMappings();

  // Add filter event listeners
  filterNamespace.addEventListener("input", renderConnections);
  filterPod.addEventListener("input", renderConnections);
  filterNode.addEventListener("change", renderConnections);
  filterProtocol.addEventListener("change", renderConnections);
  filterState.addEventListener("change", renderConnections);
  filterPortType.addEventListener("change", renderConnections);
  filterPort.addEventListener("input", renderConnections);
  if (filterIPFamily)
    filterIPFamily.addEventListener("change", renderConnections);
  filterLoopback.addEventListener("change", renderConnections);
  filterHost.addEventListener("change", renderConnections);
  if (filterPodCheckbox)
    filterPodCheckbox.addEventListener("change", renderConnections);
  if (filterDedup) filterDedup.addEventListener("change", renderConnections);
  if (filterExternal)
    filterExternal.addEventListener("change", renderConnections);
  toggleButton.addEventListener("click", toggleConnection);

  // Add IP view filter listeners
  if (filterIP) filterIP.addEventListener("input", renderIPs);
  if (filterIPType) filterIPType.addEventListener("change", renderIPs);
  if (filterIPFamilyIPs)
    filterIPFamilyIPs.addEventListener("change", renderIPs);
  if (filterIPNode) filterIPNode.addEventListener("input", renderIPs);

  // Add Ports view filter listeners
  if (filterPortIP) filterPortIP.addEventListener("input", renderPorts);
  if (filterPortProtocol)
    filterPortProtocol.addEventListener("change", renderPorts);
  if (filterPortNumber) filterPortNumber.addEventListener("input", renderPorts);
  if (filterPortNode) filterPortNode.addEventListener("input", renderPorts);
  if (filterPortExe) filterPortExe.addEventListener("input", renderPorts);

  // Set up view switching
  setupViewSwitching();

  // Set up deployment view
  setupDeploymentView();

  // Auto-connect when page loads
  shouldConnect = true;
  connect();
}

// Deployment view functionality
function setupDeploymentView() {
  const deploymentType = document.getElementById("deploymentType");
  const deployEnableTCP = document.getElementById("deployEnableTCP");
  const deployEnableUDP = document.getElementById("deployEnableUDP");

  const kubernetesDeployment = document.getElementById("kubernetesDeployment");
  const kubernetesFullDeployment = document.getElementById(
    "kubernetesFullDeployment",
  );
  const dockerComposeDeployment = document.getElementById(
    "dockerComposeDeployment",
  );
  const dockerRunDeployment = document.getElementById("dockerRunDeployment");

  if (!deploymentType || !deployEnableTCP || !deployEnableUDP) {
    return; // Elements not found, skip setup
  }

  function updateDeploymentView() {
    // Hide all deployment contents
    if (kubernetesDeployment) kubernetesDeployment.style.display = "none";
    if (kubernetesFullDeployment)
      kubernetesFullDeployment.style.display = "none";
    if (dockerComposeDeployment) dockerComposeDeployment.style.display = "none";
    if (dockerRunDeployment) dockerRunDeployment.style.display = "none";

    // Show selected deployment type
    const selectedType = deploymentType.value;
    if (selectedType === "kubernetes" && kubernetesDeployment) {
      kubernetesDeployment.style.display = "block";
      updateKubernetesManifest();
    } else if (selectedType === "kubernetes-full" && kubernetesFullDeployment) {
      kubernetesFullDeployment.style.display = "block";
      updateKubernetesFullManifest();
    } else if (selectedType === "docker-compose" && dockerComposeDeployment) {
      dockerComposeDeployment.style.display = "block";
      updateDockerComposeManifest();
    } else if (selectedType === "docker-run" && dockerRunDeployment) {
      dockerRunDeployment.style.display = "block";
      updateDockerRunCommand();
    }
  }

  function getCliArgs() {
    const args = [];
    if (!deployEnableTCP.checked) {
      args.push("-disable-tcp");
    }
    if (deployEnableUDP.checked) {
      args.push("-enable-udp");
    }
    return args;
  }

  function updateKubernetesManifest() {
    const args = getCliArgs();
    const argsYaml =
      args.length > 0
        ? `\n        args:\n${args.map((arg) => `        - "${arg}"`).join("\n")}`
        : "";

    const manifest = `cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: netstatd
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: netstatd
  template:
    metadata:
      labels:
        app: netstatd
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: netstatd
        image: codemowers/netstatd
        imagePullPolicy: Always
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName${argsYaml}
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: containerd-sock
        hostPath:
          path: /run/containerd/containerd.sock
EOF`;

    const manifestEl = document.getElementById("kubernetesManifest");
    if (manifestEl) {
      manifestEl.textContent = manifest;
    }
  }

  function updateKubernetesFullManifest() {
    const args = getCliArgs();
    const argsYaml =
      args.length > 0
        ? `\n        args:\n${args.map((arg) => `        - "${arg}"`).join("\n")}`
        : "";

    const manifest = `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: netstatd
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: netstatd
  template:
    metadata:
      labels:
        app: netstatd
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: netstatd
        image: codemowers/netstatd
        imagePullPolicy: Always
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName${argsYaml}
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: containerd-sock
        hostPath:
          path: /run/containerd/containerd.sock
---
apiVersion: v1
kind: Service
metadata:
  name: netstatd-headless
  namespace: kube-system
  labels:
    app: netstatd
spec:
  clusterIP: None
  selector:
    app: netstatd
  ports:
  - name: http
    port: 5280
    targetPort: 5280
    protocol: TCP
  - name: dnstap
    port: 5253
    targetPort: 5253
    protocol: TCP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netstatd-fanout
  namespace: kube-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: netstatd-fanout
  template:
    metadata:
      labels:
        app: netstatd-fanout
    spec:
      containers:
      - name: netstatd-fanout
        image: codemowers/netstatd
        imagePullPolicy: Always
        args:
        - "-fanout"
        - "http://netstatd-headless.kube-system.svc.cluster.local:5280/netstat"
        ports:
        - name: http
          containerPort: 6280
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: netstatd-fanout
  namespace: kube-system
  labels:
    app: netstatd-fanout
spec:
  type: ClusterIP
  selector:
    app: netstatd-fanout
  ports:
  - name: http
    port: 6280
    targetPort: 6280
    protocol: TCP`;

    const manifestEl = document.getElementById("kubernetesFullManifest");
    if (manifestEl) {
      manifestEl.textContent = manifest;
    }
  }

  function updateDockerComposeManifest() {
    const args = getCliArgs();
    const commandYaml =
      args.length > 0
        ? `\n    command:\n${args.map((arg) => `      - "${arg}"`).join("\n")}`
        : "";

    const manifest = `version: "3.8"

services:
  netstatd:
    image: codemowers/netstatd
    container_name: netstatd
    network_mode: host
    privileged: true
    pid: host
    volumes:
      - /run/containerd/containerd.sock:/run/containerd/containerd.sock:ro
      - /proc:/host/proc:ro
      - /sys/kernel/debug:/sys/kernel/debug:rw
    restart: unless-stopped${commandYaml}`;

    const manifestEl = document.getElementById("dockerComposeManifest");
    if (manifestEl) {
      manifestEl.textContent = manifest;
    }
  }

  function updateDockerRunCommand() {
    const args = getCliArgs();
    const argsStr = args.length > 0 ? ` \\\n  ${args.join(" \\\n  ")}` : "";

    const command = `docker run -d \\
  --name netstatd \\
  --privileged \\
  --network host \\
  --pid host \\
  -v /run/containerd/containerd.sock:/run/containerd/containerd.sock:ro \\
  -v /proc:/host/proc:ro \\
  -v /sys/kernel/debug:/sys/kernel/debug:rw \\
  codemowers/netstatd${argsStr}`;

    const commandEl = document.getElementById("dockerRunCommand");
    if (commandEl) {
      commandEl.textContent = command;
    }
  }

  // Add event listeners
  deploymentType.addEventListener("change", updateDeploymentView);
  deployEnableTCP.addEventListener("change", updateDeploymentView);
  deployEnableUDP.addEventListener("change", updateDeploymentView);

  // Initial render
  updateDeploymentView();
}

// Start when DOM is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
