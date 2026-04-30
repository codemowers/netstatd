function syncConnectionPodMetadata(row, processInfo, containerRecord) {
  if (!row) return;
  const sourceContainer =
    processInfo && processInfo.isHostNetNS === true
      ? null
      : containerRecord ||
        (processInfo && processInfo.containerUid
          ? getContainer(processInfo.containerUid) || null
          : null);

  if (sourceContainer) {
    if (sourceContainer.namespace) {
      row.dataset.namespace = sourceContainer.namespace;
    }
    if (sourceContainer.podName) {
      row.dataset.podName = sourceContainer.podName;
    }
    if (sourceContainer.podUid) {
      row.dataset.podUid = sourceContainer.podUid;
    }
    if (sourceContainer.containerUid) {
      row.dataset.containerUid = sourceContainer.containerUid;
    }
    if (
      row.dataset.localIp &&
      ((processInfo && processInfo.isHostNetNS === false) ||
        sourceContainer.isHostNetNS === false)
    ) {
      rememberPodOwnerForIP(
        row.dataset.localIp,
        sourceContainer,
        row.dataset.nodeName,
        processInfo ? processInfo.netns : null,
        {
          type: "connection.row.metadata-sync",
          protocol: row.dataset.protocol || "",
          state: row.dataset.state || "",
          localIP: row.dataset.localIp || "",
          localPort: row.dataset.localPort || "",
          remoteIP: row.dataset.remoteIp || "",
          remotePort: row.dataset.remotePort || "",
          pid: row.dataset.pid || "",
          containerUid: row.dataset.containerUid || "",
        },
      );
    }
  } else if (
    processInfo &&
    processInfo.isHostNetNS === false &&
    processInfo.containerUid
  ) {
    row.dataset.containerUid = processInfo.containerUid;
  }
}

function formatConnectionCreatedAgo(row) {
  if (!row || !row.dataset.createdAt) return "";
  const createdAt = new Date(row.dataset.createdAt);
  if (isNaN(createdAt.getTime())) return "";
  const ageSeconds = Math.max(
    0,
    Math.floor((Date.now() - createdAt.getTime()) / 1000),
  );
  return `Created: ${ageSeconds} seconds ago`;
}

function renderConnectionStateTooltip(event) {
  const cell = event.target.closest("td.col-state");
  if (!cell) return;
  const row = cell.closest("tr");
  if (!row || !row.closest("#connectionsTableBody")) return;
  cell.title = formatConnectionCreatedAgo(row);
}

function setupConnectionStateTooltips() {
  if (!window.connectionsTable) return;
  window.connectionsTable.addEventListener(
    "mouseover",
    renderConnectionStateTooltip,
  );
  window.connectionsTable.addEventListener(
    "focusin",
    renderConnectionStateTooltip,
  );
}

function setupConnectionRowLinks() {
  if (!window.connectionsTable) return;
  window.connectionsTable.addEventListener("click", (event) => {
    const pidCell = event.target.closest("td.col-pid");
    if (pidCell) {
      const row = pidCell.closest("tr");
      const pid = row ? row.dataset.pid || "" : "";
      const nodeName = row ? row.dataset.nodeName || "" : "";
      if (!pid || !nodeName || pidCell.textContent.trim() === "-") return;
      if (window.filterProcessNode) window.filterProcessNode.value = nodeName;
      if (window.filterProcessPID) window.filterProcessPID.value = pid;
      if (window.filterProcessNamespace)
        window.filterProcessNamespace.value = "";
      if (window.filterProcessPod) window.filterProcessPod.value = "";
      if (window.filterProcessNetwork) window.filterProcessNetwork.value = "";
      if (typeof applyProcessFilters === "function") applyProcessFilters();
      if (typeof switchToView === "function") switchToView("processes");
      return;
    }

    const netnsCell = event.target.closest("td.col-netns");
    if (netnsCell) {
      const row = netnsCell.closest("tr");
      const netns = row ? row.dataset.netns || "" : "";
      if (!netns || netnsCell.textContent.trim() === "-") return;
      if (window.filterPortNode)
        window.filterPortNode.value = row.dataset.nodeName || "";
      if (window.filterPortNetNS) window.filterPortNetNS.value = netns;
      if (window.filterPortNamespace) window.filterPortNamespace.value = "";
      if (window.filterPortNumber) window.filterPortNumber.value = "";
      if (window.filterPortIPFamily) window.filterPortIPFamily.value = "";
      if (window.filterPortType) window.filterPortType.value = "";
      if (typeof applyPortFilters === "function") applyPortFilters();
      if (typeof switchToView === "function") switchToView("ports");
      return;
    }

    const cgroupCell = event.target.closest("td.col-cgroup-slice");
    if (!cgroupCell || cgroupCell.textContent.trim() === "-") return;
    const cgroupSlice = cgroupCell.textContent.trim();
    if (window.filterContainerNode) window.filterContainerNode.value = "";
    if (window.filterContainerNamespace)
      window.filterContainerNamespace.value = "";
    if (window.filterContainerPod) window.filterContainerPod.value = "";
    if (window.filterContainerCgroup)
      window.filterContainerCgroup.value = cgroupSlice;
    if (window.filterContainerNetwork) window.filterContainerNetwork.value = "";
    if (typeof applyContainerFilters === "function") applyContainerFilters();
    if (typeof switchToView === "function") switchToView("containers");
  });
}

function isConnectionClosingState(state) {
  return (
    state === "CLOSE" ||
    state === "CLOSED" ||
    state === "TIME_WAIT" ||
    state === "CLOSING"
  );
}

function assertStableSockCookiePort(row, event, field, nextPort) {
  if (!row || !event || !event.sockCookie || !nextPort) return;
  const previous = row.dataset[field] || "";
  const next = String(nextPort);
  if (!previous || previous === "0" || next === "0" || previous === next) {
    return;
  }
  console.assert(
    false,
    `sockCookie ${event.sockCookie} changed ${field} from ${previous} to ${next}`,
    {
      row,
      event,
      previous,
      next,
      field,
    },
  );
}

function updateConnectionRowProcessMetadata(
  row,
  isAcceptedEvent,
  pid,
  processInfo,
  cgroupSliceText,
) {
  if (!row) return;
  if (!isAcceptedEvent && !processInfo) {
    if (!row.cells[6].textContent) row.cells[6].textContent = "-";
    if (!row.cells[7].textContent) row.cells[7].textContent = "-";
    if (!row.cells[8].textContent) setTailClippedTextCell(row.cells[8], "");
    if (!row.cells[9].textContent) setTailClippedTextCell(row.cells[9], "");
    return;
  }
  if (isAcceptedEvent) {
    row.dataset.pid = String(pid);
  }
  if (processInfo && processInfo.containerUid) {
    if (!processInfo.cgroupSlice) {
      console.warn(
        "Container process metadata missing cgroupSlice",
        processInfo,
      );
    }
    row.dataset.containerUid = processInfo.containerUid;
    if (processInfo.netns) {
      row.dataset.netns = String(processInfo.netns);
    }
  }
  if (processInfo && processInfo.netns) {
    row.dataset.netns = String(processInfo.netns);
  }

  row.cells[6].textContent = isAcceptedEvent ? pid : "-";
  row.cells[6].title = row.dataset.netns || "";
  row.cells[6].classList.toggle("clickable-cell", isAcceptedEvent);
  row.cells[7].textContent = row.dataset.netns || "-";
  row.cells[7].title = row.dataset.netns || "";
  row.cells[7].classList.toggle("clickable-cell", Boolean(row.dataset.netns));

  const exeText = (processInfo ? processInfo.exe : "") || "-";
  setTailClippedTextCell(row.cells[8], exeText === "-" ? "" : exeText);
  row.cells[8].title = cgroupSliceText === "-" ? "" : cgroupSliceText;
  setTailClippedTextCell(
    row.cells[9],
    cgroupSliceText === "-" ? "" : cgroupSliceText,
  );
  row.cells[9].classList.toggle("clickable-cell", cgroupSliceText !== "-");
}

function updateListeningPortsFromAcceptedEvent(
  event,
  processInfo,
  containerRecord,
) {
  if (!event || !processInfo || !processInfo.netns) return 0;
  const { nodeName, protocol, localPort } = event;
  const netns = processInfo.netns;
  if (!nodeName || !protocol || !localPort) return 0;

  rememberProcessMetadataForPort(
    nodeName,
    protocol,
    localPort,
    netns,
    processInfo,
  );

  if (containerRecord && processInfo.isHostNetNS === false) {
    rememberPodOwnerForNetNSPort(nodeName, netns, localPort, containerRecord);
  }

  const portSelector =
    `#portsTableBody tr[data-node-name="${cssAttrValue(nodeName)}"]` +
    `[data-protocol="${cssAttrValue(protocol)}"]` +
    `[data-port="${cssAttrValue(localPort)}"]` +
    `[data-netns="${cssAttrValue(netns)}"]`;
  const rows = document.querySelectorAll(portSelector);
  rows.forEach((row) => {
    updatePortMetadataForRow(
      row,
      {
        nodeName,
        protocol,
        port: localPort,
        netns,
        cgroupSlice: processInfo.cgroupSlice || "",
        containerUid: processInfo.containerUid || "",
        isHostNetNS: processInfo.isHostNetNS,
      },
      containerRecord,
    );
    applyPortFiltersToRow(row);
  });
  return rows.length;
}

function handleConnectionAcceptedEvent(event) {
  const { nodeName, protocol, localIP, localPort, pid } = event;
  const processKey = `${nodeName}/${pid}`;
  const processInfo = window.processMetadata.get(processKey) || null;
  const containerRecord =
    processInfo && processInfo.isHostNetNS === false && processInfo.containerUid
      ? getContainer(processInfo.containerUid) || null
      : null;

  if (typeof observeProcessLocalIP === "function") {
    observeProcessLocalIP(nodeName, pid, localIP);
  }

  if (
    processInfo &&
    processInfo.isHostNetNS === false &&
    containerRecord &&
    localIP
  ) {
    rememberPodOwnerForIP(
      localIP,
      containerRecord,
      nodeName,
      processInfo.netns,
      { type: event.type, event },
    );
  }

  updateDropdownsFromEvent({
    nodeName,
    namespace: containerRecord ? containerRecord.namespace : "",
    podName: containerRecord ? containerRecord.podName : "",
  });

  const updatedPortRows = updateListeningPortsFromAcceptedEvent(
    event,
    processInfo,
    containerRecord,
  );

  const selector =
    `tr[data-node-name="${cssAttrValue(nodeName)}"]` +
    `[data-protocol="${cssAttrValue(protocol)}"]` +
    `[data-local-ip="${cssAttrValue(localIP)}"]` +
    `[data-local-port="${cssAttrValue(localPort)}"]`;
  const rows = window.connectionsTable
    ? window.connectionsTable.querySelectorAll(selector)
    : [];
  const cgroupSliceText = (processInfo && processInfo.cgroupSlice) || "-";

  rows.forEach((row) => {
    syncConnectionPodMetadata(row, processInfo, containerRecord);
    updateConnectionRowProcessMetadata(
      row,
      true,
      pid,
      processInfo,
      cgroupSliceText,
    );
    renderConnectionEndpoints(row);
    markDuplicateConnectionRow(row);
    applyConnectionFiltersToRow(row);
  });
  if (rows.length || updatedPortRows) updateViewCounts();
}

function handleConnectionEvent(event) {
  // Destructure event properties with default values
  const {
    state,
    protocol,
    nodeName,
    localIP,
    remoteIP,
    localPort,
    remotePort,
    pid,
  } = event;
  const isAcceptedEvent = event.type === "connection.accepted";

  console.assert(nodeName, "Connection event must have nodeName", event);
  console.assert(
    protocol === "TCP" || protocol === "UDP",
    "Connection event must have TCP or UDP protocol",
    event,
  );
  console.assert(
    hasOwnField(event, "state") && typeof event.state === "string",
    "Connection event must have state string",
    event,
  );
  console.assert(
    hasOwnField(event, "localIP") && typeof event.localIP === "string",
    "Connection event must have localIP string",
    event,
  );
  console.assert(
    hasOwnField(event, "remoteIP") && typeof event.remoteIP === "string",
    "Connection event must have remoteIP string",
    event,
  );
  console.assert(
    isAcceptedEvent || !hasOwnField(event, "pid"),
    "connection.event must not have pid",
    event,
  );
  if (isAcceptedEvent) {
    console.assert(
      typeof pid === "number" && pid > 0,
      "connection.accepted event must have pid number",
      event,
    );
  }
  if (isAcceptedEvent) {
    handleConnectionAcceptedEvent(event);
    return;
  }
  console.assert(
    hasOwnField(event, "sockCookie") && typeof event.sockCookie === "number",
    "Connection event must have sockCookie number",
    event,
  );
  let connectionKey;
  if (event.sockCookie && event.sockCookie !== 0) {
    connectionKey = `${nodeName}-cookie-${event.sockCookie}`;
  } else {
    const endpoints = [
      `${localIP}:${localPort}`,
      `${remoteIP}:${remotePort}`,
    ].sort();
    connectionKey = `${nodeName}-${protocol}-${endpoints[0]}-${endpoints[1]}`;
  }

  let row = document.getElementById(connectionKey);
  const isNewRow = !row;
  const previousLocalPort = row ? row.dataset.localPort || "" : "";
  const previousRemotePort = row ? row.dataset.remotePort || "" : "";
  const isClosingState = isConnectionClosingState(state);
  if (isNewRow && isClosingState) {
    return;
  }

  updateDropdownsFromEvent({
    nodeName,
    namespace: "",
    podName: "",
  });

  const localPortChanged =
    localPort !== undefined && previousLocalPort !== String(localPort);
  const remotePortChanged =
    remotePort !== undefined && previousRemotePort !== String(remotePort);
  const shouldRerenderEndpoints =
    isNewRow ||
    state === "ESTABLISHED" ||
    localPortChanged ||
    remotePortChanged;

  // Build row if it doesn't exist
  if (isNewRow) {
    row = document.createElement("tr");
    row.id = connectionKey;
    let createdAt = new Date();
    if (event.timestamp) {
      const eventTimestamp = new Date(event.timestamp);
      if (!isNaN(eventTimestamp.getTime())) createdAt = eventTimestamp;
    }
    row.dataset.createdAt = createdAt.toISOString();

    // Create cells with dummy content
    for (let i = 0; i < 10; i++) {
      const td = document.createElement("td");
      row.appendChild(td);
    }
    // Assign classes
    row.cells[0].className = "col-protocol";
    row.cells[1].className = "col-state";
    row.cells[2].className = "col-node";
    row.cells[3].className = "col-endpoint";
    row.cells[4].className = "col-node";
    row.cells[5].className = "col-endpoint";
    row.cells[6].className = "col-pid";
    row.cells[7].className = "col-netns";
    row.cells[8].className = "col-exe";
    row.cells[9].className = "col-cgroup-slice";

    if (window.connectionsTable) {
      window.connectionsTable.appendChild(row);
    }
  }

  // Update dataset attributes (always)
  assertStableSockCookiePort(row, event, "localPort", localPort);
  assertStableSockCookiePort(row, event, "remotePort", remotePort);
  row.dataset.protocol = protocol;
  row.dataset.state = state;
  row.dataset.localIp = localIP;
  row.dataset.remoteIp = remoteIP;
  if (localPort !== undefined) row.dataset.localPort = String(localPort);
  if (remotePort !== undefined) row.dataset.remotePort = String(remotePort);
  row.dataset.nodeName = nodeName;
  row.dataset.ipFamily = getIPFamily(localIP);
  updateConnectionRowProcessMetadata(row, false, pid, null, "-");
  // Update cell contents (always)
  if (isNewRow) {
    row.cells[0].textContent = protocol || "-";
  }
  if (shouldRerenderEndpoints) {
    renderConnectionEndpoints(row);
  }
  markDuplicateConnectionRow(row);
  row.cells[1].textContent = state || "-";
  applyConnectionFiltersToRow(row);

  if (isClosingState) {
    if (row) {
      row.classList.add("destroyed");
      if (!window.destroyedConnectionCleanupTimers.has(connectionKey)) {
        const cleanupTimer = setTimeout(() => {
          const currentRow = document.getElementById(connectionKey);
          if (currentRow && currentRow.classList.contains("destroyed")) {
            removeConnectionRowAndDedupePeer(currentRow);
          }
          window.destroyedConnectionCleanupTimers.delete(connectionKey);
          updateViewCounts();
        }, window.destroyedConnectionCleanupMs);
        window.destroyedConnectionCleanupTimers.set(
          connectionKey,
          cleanupTimer,
        );
      }
    }
    updateViewCounts();
    return;
  }

  row.classList.remove("destroyed");
  const cleanupTimer =
    window.destroyedConnectionCleanupTimers.get(connectionKey);
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    window.destroyedConnectionCleanupTimers.delete(connectionKey);
  }

  updateViewCounts();
}
