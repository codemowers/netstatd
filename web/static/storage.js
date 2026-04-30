function externalHostnameStorageKey(ip) {
  return `${window.externalHostnameStoragePrefix}${ip}`;
}

function getExternalHostname(ip) {
  if (!window.localStorage || !ip) return "";
  const hostname = localStorage.getItem(externalHostnameStorageKey(ip));
  return typeof hostname === "string" ? hostname : "";
}

function setExternalHostname(ip, hostname) {
  if (!isValidRoutableIP(ip)) return false;
  const normalized = String(hostname || "").trim();
  if (window.localStorage) {
    if (normalized) {
      localStorage.setItem(externalHostnameStorageKey(ip), normalized);
    } else {
      localStorage.removeItem(externalHostnameStorageKey(ip));
    }
  }
  if (typeof markConnectionRowsForIP === "function") {
    markConnectionRowsForIP(ip);
  }
  return true;
}

function containerStorageKey(containerUid) {
  return `${window.containerStoragePrefix}${containerUid}`;
}

function podIPOwnerStorageKey(ip) {
  return `${window.podIPOwnerStoragePrefix}${ip}`;
}

function rememberStoredPodIPOwner(ip, containerRecord, nodeName, netns) {
  if (!window.localStorage || !ip || !containerRecord) return;
  const namespace = containerRecord.namespace || "";
  const podName = containerRecord.podName || "";
  const ownerNodeName = nodeName || containerRecord.nodeName || "";
  const ownerNetNS = netns || containerRecord.netns || 0;
  if (!namespace || !podName || !ownerNodeName || !ownerNetNS) return;
  localStorage.setItem(
    podIPOwnerStorageKey(ip),
    JSON.stringify({
      namespace,
      podName,
      nodeName: ownerNodeName,
      netns: ownerNetNS,
    }),
  );
}

function forgetStoredPodIPOwner(ip) {
  if (!window.localStorage || !ip) return;
  localStorage.removeItem(podIPOwnerStorageKey(ip));
}

function forgetStoredPodIPOwnersForContainer(containerUid) {
  if (!window.localStorage || !containerUid) return;
  const container = getContainer(containerUid) || null;
  if (!container) return;
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(window.podIPOwnerStoragePrefix)) continue;
    const stored = localStorage.getItem(key);
    if (!stored) continue;
    const owner = JSON.parse(stored);
    if (
      owner &&
      owner.nodeName === container.nodeName &&
      owner.namespace === container.namespace &&
      owner.podName === container.podName
    ) {
      localStorage.removeItem(key);
    }
  }
}

function getContainer(containerUid) {
  if (!containerUid) return null;
  const cached = window.containers.get(containerUid);
  if (cached) return cached;
  if (!window.localStorage) return null;

  const stored = localStorage.getItem(containerStorageKey(containerUid));
  if (!stored) return null;
  const container = JSON.parse(stored);
  if (!container || container.containerUid !== containerUid) return null;
  window.containers.set(containerUid, container);
  return container;
}

function rememberContainer(containerRecord) {
  if (!containerRecord || !containerRecord.containerUid) return null;
  const existing = getContainer(containerRecord.containerUid) || {};
  const container = { ...existing, ...containerRecord };
  window.containers.set(container.containerUid, container);
  if (window.localStorage) {
    localStorage.setItem(
      containerStorageKey(container.containerUid),
      JSON.stringify(container),
    );
  }
  if (typeof markConnectionRowsForContainer === "function") {
    markConnectionRowsForContainer(container.containerUid);
  }
  return container;
}

function forgetContainer(containerUid) {
  if (!containerUid) return;
  window.containers.delete(containerUid);
  if (window.localStorage) {
    localStorage.removeItem(containerStorageKey(containerUid));
  }
  if (typeof markConnectionRowsForContainer === "function") {
    markConnectionRowsForContainer(containerUid);
  }
}

function handleExternalEndpointClick(event) {
  const cell = event.target.closest("td");
  if (!cell || cell.cellIndex !== 5) return;
  const row = cell.closest("tr");
  if (!row || row.dataset.remoteClass !== "external") return;

  const ip = row.dataset.remoteIp || "";
  if (!isValidRoutableIP(ip)) return;
  const existing = getExternalHostname(ip);
  const hostname = window.prompt(
    `Hostname for ${ip} (blank removes mapping)`,
    existing,
  );
  if (hostname === null) return;
  setExternalHostname(ip, hostname);
}

function setupExternalHostnameMappingClicks() {
  if (!window.connectionsTable) return;
  window.connectionsTable.addEventListener(
    "click",
    handleExternalEndpointClick,
  );
}
