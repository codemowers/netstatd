function isValidRoutableIP(ip) {
  if (!ip || ip === "" || ip === "0.0.0.0" || ip === "::" || ip === "::0") {
    return false;
  }
  if (ip.startsWith("127.")) {
    return false;
  }
  if (ip === "::1") {
    return false;
  }
  if (!ip.includes(".") && !ip.includes(":")) {
    return false;
  }
  return true;
}

function resolveEndpoint(protocol, ip, port) {
  const binding = getEndpointBinding(protocol, ip, port);
  const boundContainer = getContainerForEndpointBinding(binding);
  if (boundContainer && (boundContainer.podName || boundContainer.namespace)) {
    const owner = podOwner(boundContainer);
    if (
      binding &&
      (isHostNetNS(binding.nodeName, binding.netns) ||
        boundContainer.isHostNetNS === true)
    ) {
      owner.type = "host";
    }
    return owner;
  }

  if (!window.ambiguousPodOwnersByIP.has(ip)) {
    const containerUid = window.podOwnerByIP.get(ip);
    let container = containerUid ? getContainer(containerUid) || null : null;
    let storedPodOwner = null;
    if (!containerUid && isValidRoutableIP(ip) && window.localStorage) {
      const stored = localStorage.getItem(podIPOwnerStorageKey(ip));
      if (stored) {
        const owner = JSON.parse(stored);
        if (
          owner &&
          owner.namespace &&
          owner.podName &&
          owner.nodeName &&
          owner.netns
        ) {
          if (
            owner.nodeName &&
            owner.netns &&
            isHostNetNS(owner.nodeName, owner.netns)
          ) {
            forgetStoredPodIPOwner(ip);
          } else {
            storedPodOwner = {
              type: "pod",
              namespace: owner.namespace || "",
              podName: owner.podName || "",
              nodeName: owner.nodeName || "",
              netns: owner.netns || 0,
            };
          }
        } else {
          forgetStoredPodIPOwner(ip);
        }
      }
    }
    if (container && (container.podName || container.namespace)) {
      return podOwner(container);
    }
    if (storedPodOwner) {
      return storedPodOwner;
    }
  }

  const hostNodeName = getNodeNameForHostIP(ip);
  if (hostNodeName) {
    return { type: "host", nodeName: hostNodeName };
  }
  const hostname = getExternalHostname(ip);
  if (hostname) {
    return { type: "unknown", hostname };
  }
  return { type: "unknown" };
}

function typeClasses(type) {
  if (type === "pod") return { cls: "endpoint-pod" };
  if (type === "host") return { cls: "endpoint-host" };
  if (type === "external") return { cls: "endpoint-external" };
  return { cls: "endpoint-unknown" };
}

function colorSpan(text, type, title) {
  const { cls } = typeClasses(type);
  const titleAttr = title ? ` title="${title}"` : "";
  return `<span class="${cls}"${titleAttr}>${text}</span>`;
}

function setTailClippedTextCell(cell, value) {
  const text = value || "-";
  const span = document.createElement("span");
  span.className = "ltr-tail";
  span.textContent = text;
  cell.replaceChildren(span);
  cell.title = value || "";
}

function podLabel(resolved) {
  const ns = resolved.namespace || "";
  const pod = resolved.podName || "";
  const ctr = resolved.containerName || "";
  const parts = [ns, pod, ctr].filter(Boolean);

  if (!parts.length) return null;
  return parts.join("/");
}

function formatPortSuffix(port) {
  if (!port) return "";
  return `<span class="endpoint-port">:${port}</span>`;
}

function endpointDisplayType(resolved) {
  return resolved.type || "unknown";
}

function endpointDisplayLabel(ip, resolved, unknownLabel) {
  const displayIP = formatIP(ip);
  const pod = podLabel(resolved);
  if (pod) return pod;
  if (resolved.hostname) return resolved.hostname;
  return unknownLabel || displayIP;
}

function resolveLocalEndpoint(row, protocol, ip, port) {
  const containerUid = row.dataset.containerUid || "";
  if (containerUid) {
    const container = getContainer(containerUid);
    if (container && (container.podName || container.namespace)) {
      return podOwner(container);
    }
  }

  const namespace = row.dataset.namespace || "";
  const podName = row.dataset.podName || "";
  if (namespace || podName) {
    return {
      type: "pod",
      namespace,
      podName,
      nodeName: row.dataset.nodeName || "",
    };
  }

  return resolveEndpoint(protocol, ip, port);
}

function formatEndpointFromResolved(
  ip,
  port,
  resolved,
  isListening,
  unknownLabel,
  hideHostLabel,
  tooltip,
) {
  const portSuffix = formatPortSuffix(port);
  const listenMark = isListening ? " 🎧" : "";
  const displayIP = formatIP(ip);
  const title =
    tooltip ||
    `${resolved.hostname ? `${resolved.hostname} ` : ""}${displayIP}${port ? `:${port}` : ""}`;
  const type = endpointDisplayType(resolved);
  const { cls } = typeClasses(type);
  if (type === "host" && hideHostLabel && !podLabel(resolved)) {
    return `${listenMark}<span class="${cls}" title="${title}">${portSuffix}</span>`;
  }

  const label = endpointDisplayLabel(ip, resolved, unknownLabel);
  return `${listenMark}<span class="${cls}" title="${title}">${label}</span>${portSuffix}`;
}

function endpointTooltip(ip, port, metadata) {
  const lines = [`${formatIP(ip)}${port ? `:${port}` : ""}`];
  if (!metadata) return lines.join("\n");
  if (metadata.netns) lines.push(`netns: ${metadata.netns}`);
  if (metadata.pid) lines.push(`pid: ${metadata.pid}`);
  if (metadata.exe) lines.push(`exe: ${metadata.exe}`);
  if (metadata.cgroupSlice) lines.push(`cgroup: ${metadata.cgroupSlice}`);
  return lines.join("\n");
}

function localEndpointMetadata(row) {
  const pid =
    parseInt(row.dataset.pid || "", 10) ||
    parseInt(row.cells[6] ? row.cells[6].textContent || "" : "", 10) ||
    0;
  const exe = row.cells[7] ? row.cells[7].textContent || "" : "";
  const cgroupSlice = row.cells[8] ? row.cells[8].textContent || "" : "";
  return {
    netns: parseInt(row.dataset.netns || "", 10) || 0,
    pid,
    exe: exe === "-" ? "" : exe,
    cgroupSlice: cgroupSlice === "-" ? "" : cgroupSlice,
  };
}

function remoteEndpointMetadata(protocol, ip, port) {
  const binding = getEndpointBinding(protocol, ip, port);
  if (binding) return binding;

  const hostNodeName = getNodeNameForHostIP(ip);
  if (hostNodeName) {
    return { netns: window.hostNetNSByNode.get(hostNodeName) || 0 };
  }
  return null;
}

function renderConnectionEndpoints(row) {
  const ip = row.dataset.localIp;
  const port = row.dataset.localPort;
  const protocol = row.dataset.protocol;
  const remoteIP = row.dataset.remoteIp || "";
  const remotePort = row.dataset.remotePort || "";
  const localNodeCell = row.cells[2];
  const localCell = row.cells[3];
  const remoteNodeCell = row.cells[4];
  const remoteCell = row.cells[5];
  if (!localNodeCell || !localCell || !remoteNodeCell || !remoteCell) return;

  const localResolved = resolveLocalEndpoint(
    row,
    protocol,
    ip,
    parseInt(port, 10) || 0,
  );
  const remoteResolved = resolveEndpoint(
    protocol,
    remoteIP,
    parseInt(remotePort, 10) || 0,
  );
  const remoteRendered =
    remoteResolved.type === "unknown"
      ? { ...remoteResolved, type: "external" }
      : remoteResolved;
  const localListening = isConnectionRowLocalListening(
    row,
    protocol,
    parseInt(port, 10) || 0,
    ip,
  );
  const remoteListening = isListeningPort(
    protocol,
    remoteIP,
    parseInt(remotePort, 10) || 0,
  );

  row.dataset.localClass =
    localResolved.type === "unknown" ? "" : localResolved.type || "";
  row.dataset.remoteClass = remoteRendered.type || "external";
  row.dataset.localListening = localListening ? "true" : "false";
  row.dataset.remoteListening = remoteListening ? "true" : "false";

  localNodeCell.textContent =
    localResolved.nodeName || row.dataset.nodeName || "-";
  localCell.innerHTML = formatEndpointFromResolved(
    ip,
    port,
    localResolved,
    localListening,
    undefined,
    false,
    endpointTooltip(ip, port, localEndpointMetadata(row)),
  );

  remoteNodeCell.textContent = remoteRendered.nodeName || "-";
  remoteCell.innerHTML = formatEndpointFromResolved(
    remoteIP,
    remotePort,
    remoteRendered,
    remoteListening,
    undefined,
    true,
    endpointTooltip(
      remoteIP,
      remotePort,
      remoteEndpointMetadata(protocol, remoteIP, parseInt(remotePort, 10) || 0),
    ),
  );
}

function scheduleDirtyConnectionRowsRender() {
  if (window.connectionRowsRerenderPending) return;
  window.connectionRowsRerenderPending = true;
  requestAnimationFrame(() => {
    window.connectionRowsRerenderPending = false;
    if (!window.connectionsTable) return;
    const rows = window.connectionsTable.querySelectorAll(
      'tr[data-endpoints-dirty="true"]',
    );
    rows.forEach((row) => {
      delete row.dataset.endpointsDirty;
      renderConnectionEndpoints(row);
      if (typeof applyConnectionFiltersToRow === "function") {
        applyConnectionFiltersToRow(row);
      }
    });
  });
}

function markConnectionRowDirty(row) {
  if (!row) return false;
  row.dataset.endpointsDirty = "true";
  scheduleDirtyConnectionRowsRender();
  return true;
}

function markConnectionRowsDirty(selector) {
  if (!window.connectionsTable) return false;
  const rows = selector
    ? window.connectionsTable.querySelectorAll(selector)
    : window.connectionsTable.rows;
  let changed = false;
  for (const row of rows) {
    row.dataset.endpointsDirty = "true";
    changed = true;
  }
  if (changed) scheduleDirtyConnectionRowsRender();
  return changed;
}

function makeConnectionEndpointSelector(protocol, ip, port) {
  if (!protocol || !ip || !port) return "";
  const escapedProtocol = cssAttrValue(protocol);
  const escapedIP = cssAttrValue(ip);
  const escapedPort = cssAttrValue(port);
  return [
    `tr[data-protocol="${escapedProtocol}"][data-local-ip="${escapedIP}"][data-local-port="${escapedPort}"]`,
    `tr[data-protocol="${escapedProtocol}"][data-remote-ip="${escapedIP}"][data-remote-port="${escapedPort}"]`,
  ].join(", ");
}

function markConnectionRowsForEndpoint(protocol, ip, port) {
  const selector = makeConnectionEndpointSelector(protocol, ip, port);
  return selector ? markConnectionRowsDirty(selector) : false;
}

function markConnectionRowsForEndpointKey(key) {
  const parts = String(key || "").split("/");
  if (parts.length !== 3) return false;
  return markConnectionRowsForEndpoint(parts[0], parts[1], parts[2]);
}

function markConnectionRowsForIP(ip) {
  if (!ip) return false;
  const escapedIP = cssAttrValue(ip);
  return markConnectionRowsDirty(
    [
      `tr[data-local-ip="${escapedIP}"]`,
      `tr[data-remote-ip="${escapedIP}"]`,
    ].join(", "),
  );
}

function markConnectionRowsForContainer(containerUid) {
  if (!containerUid) return false;
  return markConnectionRowsDirty(
    `tr[data-container-uid="${cssAttrValue(containerUid)}"]`,
  );
}

function markConnectionRowsForNodeNetNS(nodeName, netns, port) {
  if (!nodeName || !netns) return false;
  let selector =
    `tr[data-node-name="${cssAttrValue(nodeName)}"]` +
    `[data-netns="${cssAttrValue(netns)}"]`;
  if (port) selector += `[data-local-port="${cssAttrValue(port)}"]`;
  return markConnectionRowsDirty(selector);
}

function cssAttrValue(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}

function markDuplicateConnectionRow(row) {
  if (!row) return;

  const setDupValue = (targetRow, value) => {
    if (!targetRow) return;
    if (targetRow.dataset.dup === value) return;
    targetRow.dataset.dup = value;
  };

  setDupValue(row, "false");

  const matches = findOppositeConnectionRows(row);
  if (row.dataset.localListening === "true") {
    for (const match of matches) {
      setDupValue(match, "true");
      if (
        window.filterConnectionDedupe &&
        window.filterConnectionDedupe.checked
      ) {
        applyConnectionFiltersToRow(match);
      }
    }
  } else if (matches.length > 0) {
    setDupValue(row, "true");
  }

  if (window.filterConnectionDedupe && window.filterConnectionDedupe.checked) {
    applyConnectionFiltersToRow(row);
  }
}

function findOppositeConnectionRows(row) {
  if (!row || !window.connectionsTable) return [];

  const protocol = cssAttrValue(row.dataset.protocol);
  const localIP = cssAttrValue(row.dataset.localIp);
  const localPort = cssAttrValue(row.dataset.localPort);
  const remoteIP = cssAttrValue(row.dataset.remoteIp);
  const remotePort = cssAttrValue(row.dataset.remotePort);

  let selector = "";
  if (protocol && localIP && localPort && remoteIP && remotePort) {
    selector = [
      `tr[data-protocol="${protocol}"]`,
      `[data-local-ip="${remoteIP}"]`,
      `[data-local-port="${remotePort}"]`,
      `[data-remote-ip="${localIP}"]`,
      `[data-remote-port="${localPort}"]`,
    ].join("");
  }
  if (!selector) return [];

  return Array.from(window.connectionsTable.querySelectorAll(selector)).filter(
    (match) => match !== row,
  );
}

function removeConnectionRowAndDedupePeer(row) {
  if (!row) return false;

  const rowsToRemove = [row];
  if (window.filterConnectionDedupe && window.filterConnectionDedupe.checked) {
    rowsToRemove.push(...findOppositeConnectionRows(row));
  }

  let removed = false;
  for (const targetRow of rowsToRemove) {
    if (!targetRow || !targetRow.parentNode) continue;
    const cleanupTimer = window.destroyedConnectionCleanupTimers
      ? window.destroyedConnectionCleanupTimers.get(targetRow.id)
      : null;
    if (cleanupTimer) {
      clearTimeout(cleanupTimer);
      window.destroyedConnectionCleanupTimers.delete(targetRow.id);
    }
    targetRow.remove();
    removed = true;
  }
  return removed;
}

function isConnectionRowLocalListening(row, protocol, port, ip) {
  if (!port) return false;
  const nodeName = row.dataset.nodeName || "";
  const netns = parseInt(row.dataset.netns || "", 10);

  if (
    nodeName &&
    netns &&
    isListeningPortByOwner(nodeName, netns, protocol, port)
  ) {
    return true;
  }
  return isListeningPort(protocol, ip, port);
}

function isListeningPort(protocol, ip, port) {
  if (!port) return false;
  const endpointBinding = getEndpointBinding(protocol, ip, port);
  if (endpointBinding) {
    return isListeningPortByOwner(
      endpointBinding.nodeName,
      endpointBinding.netns,
      endpointBinding.protocol,
      endpointBinding.port,
    );
  }

  const hostNodeName = getNodeNameForHostIP(ip);
  if (hostNodeName) {
    return isListeningPortByOwner(
      hostNodeName,
      window.hostNetNSByNode.get(hostNodeName),
      protocol,
      port,
    );
  }

  return false;
}

function isListeningPortByOwner(nodeName, netns, protocol, port) {
  if (!nodeName || !netns || !protocol || !port) return false;
  return (
    window.listeningPortByNodeNetNSProtocolPort.get(
      makeListeningPortKey(nodeName, netns, protocol, port),
    ) === true
  );
}

function formatIP(ip) {
  if (!ip) return "-";
  if (ip.includes(":")) return `[${ip}]`;
  return ip;
}

function getIPFamily(ip) {
  if (!ip) return "unknown";
  if (ip.includes(".")) return "IPv4";
  if (ip.includes(":")) return "IPv6";
  return "unknown";
}

function getNodeNameForHostIP(ip) {
  for (const [nodeName, ips] of window.hostIPsByNode) {
    if (ips.includes(ip)) return nodeName;
  }
  return null;
}

function makeNodeNetNSKey(nodeName, netns) {
  if (!nodeName || !netns) return null;
  return `${nodeName}/${netns}`;
}

function makeNodeNetNSPortKey(nodeName, netns, port) {
  if (!nodeName || !netns || !port) return null;
  return `${nodeName}/${netns}/${port}`;
}

function makeEndpointAddressKey(protocol, ip, port) {
  if (!protocol || !ip || !port) return null;
  return `${protocol}/${ip}/${port}`;
}

function getEndpointBinding(protocol, ip, port) {
  const key = makeEndpointAddressKey(protocol, ip, port);
  if (!key) return null;

  const cached = window.endpointBindingByAddress.get(key);
  if (cached) return cached;
  if (!window.localStorage) return null;

  const stored = localStorage.getItem(
    `${window.endpointBindingStoragePrefix}${key}`,
  );
  if (!stored) return null;
  const binding = JSON.parse(stored);
  if (!isEndpointBinding(binding)) return null;
  window.endpointBindingByAddress.set(key, binding);
  return binding;
}

function isEndpointBinding(binding) {
  return Boolean(
    binding &&
    binding.nodeName &&
    binding.netns &&
    binding.port &&
    binding.protocol,
  );
}

function sameEndpointBinding(left, right) {
  return Boolean(
    left &&
    right &&
    left.nodeName === right.nodeName &&
    left.netns === right.netns &&
    left.port === right.port &&
    left.pid === right.pid &&
    left.protocol === right.protocol &&
    left.exe === right.exe &&
    left.cgroupSlice === right.cgroupSlice &&
    left.containerUid === right.containerUid,
  );
}

function hasEndpointProcessIdentity(binding) {
  return Boolean(
    binding && (binding.pid || binding.exe || binding.cgroupSlice),
  );
}

function isEndpointBindingEnrichment(existing, binding) {
  return Boolean(
    existing &&
    binding &&
    existing.nodeName === binding.nodeName &&
    existing.netns === binding.netns &&
    existing.port === binding.port &&
    existing.protocol === binding.protocol &&
    !hasEndpointProcessIdentity(existing) &&
    hasEndpointProcessIdentity(binding),
  );
}

function setEndpointBinding(key, binding, options) {
  if (!key || !isEndpointBinding(binding)) return;
  const shouldRememberListening = options ? options.listening !== false : true;
  const shouldPersist = options ? options.persist !== false : true;
  const existing = window.endpointBindingByAddress.get(key);
  if (existing && sameEndpointBinding(existing, binding)) {
    if (shouldRememberListening) {
      rememberListeningPort(
        binding.nodeName,
        binding.netns,
        binding.port,
        binding.protocol,
      );
    }
    if (!shouldPersist || !window.localStorage) return;
    localStorage.setItem(
      `${window.endpointBindingStoragePrefix}${key}`,
      JSON.stringify(binding),
    );
    return;
  }
  if (
    existing &&
    hasEndpointProcessIdentity(existing) &&
    !hasEndpointProcessIdentity(binding)
  ) {
    return;
  }
  if (existing && !isEndpointBindingEnrichment(existing, binding)) {
    console.log(
      `Endpoint binding changed: ${key}`,
      "old:",
      existing,
      "new:",
      binding,
    );
  }

  window.endpointBindingByAddress.set(key, binding);
  if (shouldRememberListening) {
    rememberListeningPort(
      binding.nodeName,
      binding.netns,
      binding.port,
      binding.protocol,
    );
  }
  markConnectionRowsForEndpointKey(key);
  if (!shouldPersist || !window.localStorage) return;
  localStorage.setItem(
    `${window.endpointBindingStoragePrefix}${key}`,
    JSON.stringify(binding),
  );
}

function rememberListeningEndpointBinding(portEvent) {
  const { protocol, ip, port, nodeName, netns } = portEvent;
  if (!isValidRoutableIP(ip)) return false;
  const key = makeEndpointAddressKey(protocol, ip, port);
  if (!key || !nodeName || !netns || !port) return false;
  const binding = {
    nodeName,
    netns,
    port,
    protocol,
    pid: portEvent.pid || 0,
    exe: portEvent.exe || "",
    cgroupSlice: portEvent.cgroupSlice || "",
    containerUid: portEvent.containerUid || "",
  };
  const existing = getEndpointBinding(protocol, ip, port);
  if (existing && sameEndpointBinding(existing, binding)) {
    return false;
  }

  setEndpointBinding(key, binding);
  return !existing;
}

function rememberListeningPort(nodeName, netns, port, protocol) {
  if (!nodeName || !netns || !port || !protocol) return false;
  window.listeningPortByNodeNetNSProtocolPort.set(
    makeListeningPortKey(nodeName, netns, protocol, port),
    true,
  );
  return true;
}

function makeListeningPortKey(nodeName, netns, protocol, port) {
  return `${nodeName}/${protocol}/${port}/${netns}`;
}

function hydrateListeningPortsFromEndpointBindings() {
  for (const [, binding] of window.endpointBindingByAddress) {
    rememberListeningPort(
      binding.nodeName,
      binding.netns,
      binding.port,
      binding.protocol,
    );
  }
}

function makePortProcessKey(nodeName, protocol, port, netns) {
  if (!nodeName || !protocol || !port || !netns) return null;
  return `${nodeName}/${protocol}/${port}/${netns}`;
}

function rememberEndpointBinding(connectionEvent, processInfo, options) {
  console.assert(
    connectionEvent,
    "rememberEndpointBinding requires connectionEvent",
    connectionEvent,
  );
  console.assert(
    processInfo,
    "rememberEndpointBinding requires processInfo",
    processInfo,
  );
  const { protocol, localIP, localPort, nodeName } = connectionEvent;
  const netns = processInfo.netns;
  const ip = localIP;
  const port = localPort;
  const pid = processInfo.pid || 0;
  if (!isValidRoutableIP(ip)) return false;
  const key = makeEndpointAddressKey(protocol, ip, port);
  if (!key || !nodeName || !netns || !port) return false;
  if (!pid || !protocol) return false;
  const binding = {
    nodeName,
    netns,
    port,
    pid,
    protocol,
    exe: processInfo ? processInfo.exe || "" : "",
    cgroupSlice: processInfo ? processInfo.cgroupSlice || "" : "",
  };
  if (processInfo && processInfo.containerUid) {
    binding.containerUid = processInfo.containerUid;
  }
  const existing = getEndpointBinding(protocol, ip, port);
  if (sameEndpointBinding(existing, binding)) {
    setEndpointBinding(key, binding, options);
    return false;
  }
  if (hasEndpointProcessIdentity(existing)) {
    return false;
  }
  setEndpointBinding(key, binding, options);
  return true;
}

function rememberProcessMetadataForPort(
  nodeName,
  protocol,
  port,
  netns,
  processInfo,
) {
  const key = makePortProcessKey(nodeName, protocol, port, netns);
  if (!key || !processInfo) return false;
  const existing = window.processMetadataByPort.get(key);
  if (
    existing &&
    existing.pid === processInfo.pid &&
    existing.cgroupSlice === processInfo.cgroupSlice &&
    existing.exe === processInfo.exe
  ) {
    return false;
  }
  if (existing && (existing.pid || existing.exe || existing.cgroupSlice)) {
    return false;
  }
  window.processMetadataByPort.set(key, {
    pid: processInfo.pid,
    exe: processInfo.exe || "",
    netns: processInfo.netns,
    cgroupSlice: processInfo.cgroupSlice || "",
    isHostNetNS: processInfo.isHostNetNS,
    nodeName,
  });
  return true;
}

function isHostNetNS(nodeName, netns) {
  if (!nodeName || !netns) return false;
  return window.hostNetNSByNode.get(nodeName) === netns;
}

function podOwner(containerRecord) {
  if (!containerRecord) return { type: "unknown" };
  return {
    type: "pod",
    containerUid: containerRecord.containerUid || "",
    podName: containerRecord.podName || "",
    namespace: containerRecord.namespace || "",
    containerName: containerRecord.containerName || "",
    nodeName: containerRecord.nodeName || "",
    isHostNetNS: containerRecord.isHostNetNS,
  };
}

function rememberPodOwnerForNetNS(nodeName, netns, containerRecord) {
  const key = makeNodeNetNSKey(nodeName, netns);
  if (!key || !containerRecord || !containerRecord.containerUid) return;
  if (isHostNetNS(nodeName, netns) || containerRecord.isHostNetNS === true)
    return;
  window.podOwnerByNodeNetNS.set(key, containerRecord.containerUid);
  markConnectionRowsForNodeNetNS(nodeName, netns);
}

function rememberPodOwnerForNetNSPort(nodeName, netns, port, containerRecord) {
  const key = makeNodeNetNSPortKey(nodeName, netns, port);
  if (!key || !containerRecord || !containerRecord.containerUid) return;
  if (isHostNetNS(nodeName, netns) || containerRecord.isHostNetNS === true)
    return;
  window.podOwnerByNodeNetNSPort.set(key, containerRecord.containerUid);
  markConnectionRowsForNodeNetNS(nodeName, netns, port);
}

function getContainerForNodeNetNSPort(nodeName, netns, port) {
  if (!nodeName || !netns) return null;
  if (isHostNetNS(nodeName, netns)) return null;

  const exactKey = makeNodeNetNSPortKey(nodeName, netns, port);
  const netnsKey = makeNodeNetNSKey(nodeName, netns);
  const containerUid =
    (exactKey ? window.podOwnerByNodeNetNSPort.get(exactKey) : "") ||
    (netnsKey ? window.podOwnerByNodeNetNS.get(netnsKey) : "");
  return containerUid ? getContainer(containerUid) || null : null;
}

function getContainerForEndpointBinding(binding) {
  if (!binding) return null;
  if (binding.containerUid) {
    const container = getContainer(binding.containerUid) || null;
    if (container) return container;
  }
  return getContainerForNodeNetNSPort(
    binding.nodeName,
    binding.netns,
    binding.port,
  );
}

function containerLogDetails(containerUid, containerRecord) {
  const container = containerRecord || getContainer(containerUid) || {};
  return {
    containerUid: containerUid || container.containerUid || "",
    namespace: container.namespace || "",
    podName: container.podName || "",
    containerName: container.containerName || "",
    podUid: container.podUid || "",
    nodeName: container.nodeName || "",
  };
}

function samePodOwner(leftUid, rightRecord) {
  if (!leftUid || !rightRecord) return false;
  const left = getContainer(leftUid) || null;
  if (!left) return false;
  if (left.podUid && rightRecord.podUid && left.podUid === rightRecord.podUid) {
    return true;
  }
  return Boolean(
    left.nodeName &&
    rightRecord.nodeName &&
    left.namespace &&
    rightRecord.namespace &&
    left.podName &&
    rightRecord.podName &&
    left.nodeName === rightRecord.nodeName &&
    left.namespace === rightRecord.namespace &&
    left.podName === rightRecord.podName,
  );
}

function preferPodIPOwner(existingUid, containerRecord) {
  const existing = getContainer(existingUid) || null;
  if (!existing) return containerRecord.containerUid;
  if (!existing.podUid && containerRecord.podUid) {
    return containerRecord.containerUid;
  }
  if (!existing.containerName && containerRecord.containerName) {
    return containerRecord.containerUid;
  }
  return existingUid;
}

function removePodOwnerForContainer(containerUid) {
  if (!containerUid) return false;
  let changed = false;
  forgetStoredPodIPOwnersForContainer(containerUid);
  for (const [ip, ownerUid] of window.podOwnerByIP) {
    if (ownerUid === containerUid) {
      window.podOwnerByIP.delete(ip);
      forgetStoredPodIPOwner(ip);
      changed = true;
    }
  }
  for (const [ip, owners] of window.ambiguousPodOwnersByIP) {
    if (!owners.delete(containerUid)) continue;
    changed = true;
    if (owners.size === 1) {
      const [remainingOwner] = owners;
      window.ambiguousPodOwnersByIP.delete(ip);
      window.podOwnerByIP.set(ip, remainingOwner);
      const container = getContainer(remainingOwner) || null;
      if (container) rememberStoredPodIPOwner(ip, container);
    } else if (owners.size === 0) {
      window.ambiguousPodOwnersByIP.delete(ip);
      window.podOwnerByIP.delete(ip);
      forgetStoredPodIPOwner(ip);
    }
  }
  if (changed) markConnectionRowsForContainer(containerUid);
  return changed;
}

function forgetPodOwnerForIP(ip) {
  if (!ip) return false;
  let changed = window.podOwnerByIP.delete(ip);
  changed = window.ambiguousPodOwnersByIP.delete(ip) || changed;
  forgetStoredPodIPOwner(ip);
  if (changed) markConnectionRowsForIP(ip);
  return changed;
}

function podOwnerClaimLogDetails(ip, containerRecord, nodeName, netns, source) {
  const details = {
    ip,
    nodeName: nodeName || "",
    netns: netns || 0,
    owner: containerLogDetails(containerRecord.containerUid, containerRecord),
  };
  if (source) {
    details.source = source;
  }
  return details;
}

function rememberPodOwnerForIP(ip, containerRecord, nodeName, netns, source) {
  if (!isValidRoutableIP(ip) || !containerRecord) return;
  if (getNodeNameForHostIP(ip)) return;
  if (!containerRecord.containerUid) return;
  if (containerRecord.isHostNetNS === true) return;
  if (nodeName && netns && isHostNetNS(nodeName, netns)) return;

  const existing = window.podOwnerByIP.get(ip);
  const newOwner = containerRecord.containerUid;
  const ambiguousOwners = window.ambiguousPodOwnersByIP.get(ip);
  if (ambiguousOwners) {
    for (const ownerUid of ambiguousOwners) {
      if (samePodOwner(ownerUid, containerRecord)) {
        return;
      }
    }
    if (!ambiguousOwners.has(newOwner)) {
      ambiguousOwners.add(newOwner);
      console.log(
        `Pod owner for IP ${ip} is ambiguous:`,
        Array.from(ambiguousOwners, (containerUid) =>
          containerLogDetails(
            containerUid,
            containerUid === newOwner ? containerRecord : null,
          ),
        ),
        "trigger:",
        podOwnerClaimLogDetails(ip, containerRecord, nodeName, netns, source),
      );
    }
    return;
  }
  if (existing && existing !== newOwner) {
    if (samePodOwner(existing, containerRecord)) {
      const preferredOwner = preferPodIPOwner(existing, containerRecord);
      if (preferredOwner !== existing) {
        window.podOwnerByIP.set(ip, preferredOwner);
        rememberStoredPodIPOwner(ip, containerRecord, nodeName, netns);
        markConnectionRowsForIP(ip);
      } else {
        rememberStoredPodIPOwner(ip, getContainer(existing) || containerRecord);
      }
      return;
    }
    console.log(
      `Pod owner for IP ${ip} is ambiguous:`,
      [
        containerLogDetails(existing),
        containerLogDetails(newOwner, containerRecord),
      ],
      "trigger:",
      podOwnerClaimLogDetails(ip, containerRecord, nodeName, netns, source),
    );
    window.podOwnerByIP.delete(ip);
    window.ambiguousPodOwnersByIP.set(ip, new Set([existing, newOwner]));
    forgetStoredPodIPOwner(ip);
    markConnectionRowsForIP(ip);
    return;
  }
  if (existing === newOwner) {
    rememberStoredPodIPOwner(ip, containerRecord, nodeName, netns);
    return;
  }
  window.podOwnerByIP.set(ip, newOwner);
  rememberStoredPodIPOwner(ip, containerRecord, nodeName, netns);
  markConnectionRowsForIP(ip);
}

function getConnectionNetnsType(processInfo) {
  if (!processInfo) return "unknown";
  if (processInfo.isHostNetNS === true) return "host";
  if (processInfo.isHostNetNS === false) return "pod";
  return "unknown";
}

function rerenderConnectionRows() {
  markConnectionRowsDirty();
}
