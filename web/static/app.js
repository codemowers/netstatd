// WebSocket connection
window.ws = null;
window.shouldConnect = false; // start false; connect() sets to true

// Data structures
// containerUid -> latest merged container record from container.added/metainfo.
window.containers = new Map();

// nodeName -> host IP addresses reported by that node.
window.hostIPsByNode = new Map();

// nodeName -> host network namespace id for host/pod network classification.
window.hostNetNSByNode = new Map();

// "nodeName/pid" -> process metadata, including netns, executable, cgroup, and containerUid.
window.processMetadata = new Map();

// "nodeName/protocol/port/netns" -> process metadata cached for a known listening port.
window.processMetadataByPort = new Map();

// "nodeName/netns" -> containerUid for that pod network namespace.
window.podOwnerByNodeNetNS = new Map();

// "nodeName/netns/port" -> containerUid for an exact pod-owned endpoint.
window.podOwnerByNodeNetNSPort = new Map();

// ip -> containerUid observed from a pod-owned local endpoint.
window.podOwnerByIP = new Map();

// ip -> Set<containerUid> for IPs claimed by different pod identities.
// Multiple containers in one pod are a single owner and do not belong here.
window.ambiguousPodOwnersByIP = new Map();

// "protocol/ip/port" -> endpoint binding used to resolve addresses back to node/netns/process.
window.endpointBindingByAddress = new Map();

window.endpointBindingStoragePrefix = "netstatd:endpoint-binding/";
window.containerStoragePrefix = "netstatd:container/";
// Value shape: { namespace, podName, nodeName, netns }.
window.podIPOwnerStoragePrefix = "netstatd:pod-ip-owner/";
window.imageHashStorageKey = "netstatd:image-hash";
window.imageHashReloadTimer = null;
window.imageHashByNode = new Map();
window.externalHostnameStoragePrefix = "netstatd:external-hostname/";

// "nodeName/protocol/port/netns" -> true for precise listening-port checks.
window.listeningPortByNodeNetNSProtocolPort = new Map();

// connection row id -> timeout id for delayed cleanup of rows in closing states.
window.destroyedConnectionCleanupTimers = new Map();
window.destroyedConnectionCleanupMs = 5000;

// Event tracking
window.eventCount = 0;
window.viewCountsUpdatePending = false;
window.connectionRowsRerenderPending = false;

// ---------------------------------------------------------------------------
// Data flush — clears all in-memory state and DOM tables
// ---------------------------------------------------------------------------

function flushAllData() {
  window.containers.clear();

  window.hostIPsByNode.clear();
  window.hostNetNSByNode.clear();
  window.processMetadata.clear();
  window.processMetadataByPort.clear();
  window.podOwnerByNodeNetNS.clear();
  window.podOwnerByNodeNetNSPort.clear();
  window.podOwnerByIP.clear();
  window.ambiguousPodOwnersByIP.clear();
  window.listeningPortByNodeNetNSProtocolPort.clear();
  hydrateListeningPortsFromEndpointBindings();
  window.eventCount = 0;

  if (window.connectionsTable) window.connectionsTable.innerHTML = "";
  if (window.nodesTable) window.nodesTable.innerHTML = "";
  if (window.portsTable) window.portsTable.innerHTML = "";
  if (window.processesTable) window.processesTable.innerHTML = "";
  if (window.containersTable) window.containersTable.innerHTML = "";
  if (window.eventsList) window.eventsList.innerHTML = "";

  updateToggleButton();
  updateViewCounts();
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

function connect() {
  window.shouldConnect = true;
  // Clear all data before connecting
  flushAllData();
  updateToggleButton();

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/conntrack`;
  try {
    window.ws = new WebSocket(wsUrl);
  } catch (err) {
    console.error("Failed to create WebSocket:", err);
    return;
  }

  window.ws.onopen = () => {
    updateToggleButton();
  };

  window.ws.onmessage = (msg) => {
    const data = JSON.parse(msg.data);
    handleEvent(data);
  };

  window.ws.onclose = (event) => {
    updateToggleButton();
    if (window.shouldConnect) {
      setTimeout(connect, 2000);
    }
  };

  window.ws.onerror = (err) => {
    console.error("WebSocket error:", err);
  };
}

function disconnect() {
  window.shouldConnect = false;
  window.destroyedConnectionCleanupTimers.forEach((timer) =>
    clearTimeout(timer),
  );
  window.destroyedConnectionCleanupTimers.clear();
  if (window.ws) {
    window.ws.close();
    window.ws = null;
  }
  updateToggleButton();
}

function updateToggleButton() {
  if (!window.connectionToggleBtn) return;

  const isConnected = window.ws && window.ws.readyState === WebSocket.OPEN;
  const isConnecting =
    window.ws && window.ws.readyState === WebSocket.CONNECTING;

  window.connectionToggleBtn.className =
    "connection-toggle " +
    (isConnected ? "connected" : isConnecting ? "connecting" : "disconnected");

  let label;
  if (isConnected) {
    label = `Connected`;
  } else if (isConnecting) {
    label = `Connecting…`;
  } else if (window.shouldConnect) {
    label = `Reconnecting…`;
  } else {
    label = `Disconnected`;
  }
  window.connectionToggleBtn.textContent = label;
}

function updateViewCounts() {
  if (window.viewCountsUpdatePending) return;
  window.viewCountsUpdatePending = true;

  requestAnimationFrame(() => {
    window.viewCountsUpdatePending = false;

    const connectionsCount = window.connectionsTable
      ? window.connectionsTable.rows.length
      : 0;
    const nodesCount = window.nodesTable ? window.nodesTable.rows.length : 0;
    const portsCount = window.portsTable ? window.portsTable.rows.length : 0;
    const processesCount = window.processesTable
      ? window.processesTable.rows.length
      : 0;
    const containersCount = window.containersTable
      ? window.containersTable.rows.length
      : 0;
    const eventsCount = window.eventCount;

    // Update navigation links
    document
      .querySelectorAll('.nav-link[data-view="connections"]')
      .forEach((link) => {
        link.textContent = `Connections (${connectionsCount})`;
      });
    document
      .querySelectorAll('.nav-link[data-view="nodes"]')
      .forEach((link) => {
        link.textContent = `Nodes (${nodesCount})`;
      });
    document
      .querySelectorAll('.nav-link[data-view="ports"]')
      .forEach((link) => {
        link.textContent = `Listening Ports (${portsCount})`;
      });
    document
      .querySelectorAll('.nav-link[data-view="processes"]')
      .forEach((link) => {
        link.textContent = `Processes (${processesCount})`;
      });
    document
      .querySelectorAll('.nav-link[data-view="containers"]')
      .forEach((link) => {
        link.textContent = `Containers (${containersCount})`;
      });
    document
      .querySelectorAll('.nav-link[data-view="events"]')
      .forEach((link) => {
        link.textContent = `Events (${eventsCount})`;
      });
  });
}

// ---------------------------------------------------------------------------
// Event dispatch
// ---------------------------------------------------------------------------

function hasOwnField(data, field) {
  return Object.prototype.hasOwnProperty.call(data, field);
}
