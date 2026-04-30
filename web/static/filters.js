function applyPortFiltersToRow(row) {
  // Get filter values
  const node = window.filterPortNode
    ? window.filterPortNode.value.toLowerCase()
    : "";
  const namespace = window.filterPortNamespace
    ? window.filterPortNamespace.value.toLowerCase()
    : "";
  const portNumber = window.filterPortNumber
    ? window.filterPortNumber.value.trim()
    : "";
  const netns = window.filterPortNetNS
    ? window.filterPortNetNS.value.trim()
    : "";
  const family = window.filterPortIPFamily
    ? window.filterPortIPFamily.value
    : "";
  const type = window.filterPortType ? window.filterPortType.value : "";

  let matches = true;

  // Apply filters
  if (node && !(row.dataset.nodeName || "").toLowerCase().includes(node)) {
    matches = false;
  }
  if (
    namespace &&
    !(row.dataset.namespace || "").toLowerCase().includes(namespace)
  ) {
    matches = false;
  }
  if (portNumber && (row.dataset.port || "") !== portNumber) {
    matches = false;
  }
  if (netns && (row.dataset.netns || "") !== netns) {
    matches = false;
  }
  if (family) {
    // Get IP from the third cell (index 2)
    const rowIPCell = row.cells[2];
    if (rowIPCell) {
      // Extract text content from the cell (it may have HTML)
      const tempDiv = document.createElement("div");
      tempDiv.innerHTML = rowIPCell.innerHTML;
      const rowIP = tempDiv.textContent || tempDiv.innerText || "";
      const rowFamily = rowIP.includes(":") ? "ipv6" : "ipv4";
      if (rowFamily !== family) {
        matches = false;
      }
    }
  }
  if (type) {
    const rowType = row.dataset.portType || "";
    if (type === "pod" && rowType !== "pod") {
      matches = false;
    }
    if (type === "host" && rowType !== "host") {
      matches = false;
    }
  }

  row.style.display = matches ? "" : "none";
}

function applyPortFilters() {
  if (!window.portsTable) return;
  requestAnimationFrame(() => {
    for (const row of window.portsTable.rows) {
      applyPortFiltersToRow(row);
    }
  });
}

function applyNodeFiltersToRow(row) {
  const node = window.filterNodeName
    ? window.filterNodeName.value.toLowerCase()
    : "";
  let matches = true;

  if (node && !(row.dataset.nodeName || "").toLowerCase().includes(node)) {
    matches = false;
  }

  row.style.display = matches ? "" : "none";
}

function applyNodeFilters() {
  if (!window.nodesTable) return;
  requestAnimationFrame(() => {
    for (const row of window.nodesTable.rows) {
      applyNodeFiltersToRow(row);
    }
  });
}

function applyProcessFiltersToRow(row) {
  const node = window.filterProcessNode
    ? window.filterProcessNode.value.toLowerCase()
    : "";
  const pid = window.filterProcessPID
    ? window.filterProcessPID.value.trim()
    : "";
  const namespace = window.filterProcessNamespace
    ? window.filterProcessNamespace.value.toLowerCase()
    : "";
  const pod = window.filterProcessPod
    ? window.filterProcessPod.value.toLowerCase()
    : "";
  const network = window.filterProcessNetwork
    ? window.filterProcessNetwork.value
    : "";

  let matches = true;

  if (node && !(row.dataset.nodeName || "").toLowerCase().includes(node)) {
    matches = false;
  }
  if (pid && row.dataset.pid !== pid) {
    matches = false;
  }
  if (
    namespace &&
    !(row.dataset.namespace || "").toLowerCase().includes(namespace)
  ) {
    matches = false;
  }
  if (pod && !(row.dataset.podName || "").toLowerCase().includes(pod)) {
    matches = false;
  }
  if (network && row.dataset.network !== network) {
    matches = false;
  }

  row.style.display = matches ? "" : "none";
}

function applyProcessFilters() {
  if (!window.processesTable) return;
  requestAnimationFrame(() => {
    for (const row of window.processesTable.rows) {
      applyProcessFiltersToRow(row);
    }
  });
}

function applyContainerFiltersToRow(row) {
  const namespace = window.filterContainerNamespace
    ? window.filterContainerNamespace.value.toLowerCase()
    : "";
  const pod = window.filterContainerPod
    ? window.filterContainerPod.value.toLowerCase()
    : "";
  const node = window.filterContainerNode
    ? window.filterContainerNode.value.toLowerCase()
    : "";
  const cgroup = window.filterContainerCgroup
    ? window.filterContainerCgroup.value.toLowerCase()
    : "";
  const network = window.filterContainerNetwork
    ? window.filterContainerNetwork.value
    : "";

  let matches = true;

  if (namespace && !(row.dataset.namespace || "").includes(namespace)) {
    matches = false;
  }
  if (pod && !(row.dataset.pod || "").includes(pod)) {
    matches = false;
  }
  if (node && !(row.dataset.node || "").toLowerCase().includes(node)) {
    matches = false;
  }
  if (
    cgroup &&
    !(row.dataset.cgroupSlice || "").toLowerCase().includes(cgroup)
  ) {
    matches = false;
  }
  if (network) {
    const rowNetwork = row.dataset.network || "";
    if (network === "host" && rowNetwork !== "host") {
      matches = false;
    }
    if (network === "pod" && rowNetwork !== "pod") {
      matches = false;
    }
  }

  row.style.display = matches ? "" : "none";
}

function applyContainerFilters() {
  if (!window.containersTable) return;
  requestAnimationFrame(() => {
    for (const row of window.containersTable.rows) {
      applyContainerFiltersToRow(row);
    }
  });
}

function applyConnectionFiltersToRow(row) {
  const namespace = window.filterConnectionNamespace
    ? window.filterConnectionNamespace.value.toLowerCase()
    : "";
  const pod = window.filterConnectionPodInput
    ? window.filterConnectionPodInput.value.toLowerCase()
    : "";
  const node = window.filterConnectionNode
    ? window.filterConnectionNode.value.toLowerCase()
    : "";
  const protocol = window.filterConnectionProtocol
    ? window.filterConnectionProtocol.value.toLowerCase()
    : "";
  const state = window.filterConnectionState
    ? window.filterConnectionState.value
    : "";
  const portType = window.filterConnectionPortType
    ? window.filterConnectionPortType.value
    : "";
  const portValue = window.filterConnectionPort
    ? window.filterConnectionPort.value.trim()
    : "";
  const ipFamily = window.filterConnectionIPFamily
    ? window.filterConnectionIPFamily.value
    : "";
  const showHost = window.filterConnectionHost
    ? window.filterConnectionHost.checked
    : true;
  const showPod = window.filterConnectionPodCheck
    ? window.filterConnectionPodCheck.checked
    : true;
  const showExt = window.filterConnectionExternal
    ? window.filterConnectionExternal.checked
    : true;
  const dedupe = window.filterConnectionDedupe
    ? window.filterConnectionDedupe.checked
    : false;

  let matches = true;

  if (
    namespace &&
    !(row.dataset.namespace || "").toLowerCase().includes(namespace)
  )
    matches = false;
  if (pod && !(row.dataset.podName || "").toLowerCase().includes(pod))
    matches = false;
  if (node && !(row.dataset.nodeName || "").toLowerCase().includes(node))
    matches = false;
  if (
    protocol &&
    !(row.dataset.protocol || "").toLowerCase().includes(protocol)
  )
    matches = false;
  if (state && row.dataset.state !== state) matches = false;
  if (ipFamily && row.dataset.ipFamily !== ipFamily) matches = false;

  const localEndpointType = row.dataset.localClass || "unknown";
  const remoteEndpointType = row.dataset.remoteClass || "external";
  const isHost = localEndpointType === "host" || remoteEndpointType === "host";
  const isPod = localEndpointType === "pod" || remoteEndpointType === "pod";
  const isExternal = remoteEndpointType === "external";

  if (!showHost && isHost) matches = false;
  if (!showPod && isPod) matches = false;
  if (!showExt && isExternal) matches = false;
  if (dedupe && row.dataset.dup === "true") matches = false;

  if (portValue) {
    if (portType === "local") {
      if (row.dataset.localPort !== portValue) matches = false;
    } else if (portType === "remote") {
      if (row.dataset.remotePort !== portValue) matches = false;
    } else {
      if (
        row.dataset.localPort !== portValue &&
        row.dataset.remotePort !== portValue
      )
        matches = false;
    }
  }

  row.style.display = matches ? "" : "none";
}

function applyConnectionFilters() {
  // Use requestAnimationFrame for smoother UI updates
  requestAnimationFrame(() => {
    for (const row of window.connectionsTable.rows) {
      applyConnectionFiltersToRow(row);
    }
  });
}
