function processNetworkType(processInfo) {
  if (processInfo && processInfo.isHostNetNS === true) return "host";
  if (processInfo && processInfo.isHostNetNS === false) return "pod";
  return "unknown";
}

function formatContainerLabels(labels) {
  if (!labels || typeof labels !== "object") return "";
  return Object.entries(labels)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
}

function imageRepositoryRef(image) {
  const ref = String(image || "").trim();
  if (!ref) return "";
  const withoutDigest = ref.split("@")[0];
  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  if (lastColon > lastSlash) {
    return withoutDigest.slice(0, lastColon);
  }
  return withoutDigest;
}

function containerImageURL(image) {
  const ref = imageRepositoryRef(image);
  if (!ref) return "";

  const parts = ref.split("/").filter(Boolean);
  if (!parts.length) return "";

  const first = parts[0];
  const hasRegistry =
    first.includes(".") || first.includes(":") || first === "localhost";
  const registry = hasRegistry ? first : "docker.io";
  const pathParts = hasRegistry ? parts.slice(1) : parts;
  if (!pathParts.length) return "";

  if (
    registry === "docker.io" ||
    registry === "index.docker.io" ||
    registry === "registry-1.docker.io" ||
    registry === "mirror.gcr.io"
  ) {
    const namespace = pathParts.length === 1 ? "library" : pathParts[0];
    const repo = pathParts.length === 1 ? pathParts[0] : pathParts[1];
    if (!namespace || !repo || pathParts.length > 2) return "";
    return `https://hub.docker.com/r/${encodeURIComponent(namespace)}/${encodeURIComponent(repo)}`;
  }

  if (registry === "ghcr.io") {
    if (pathParts.length < 2) return "";
    const owner = pathParts[0];
    const repo = pathParts.length > 2 ? pathParts[1] : pathParts[0];
    const pkg = pathParts[pathParts.length - 1];
    if (!owner || !pkg) return "";
    return `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pkgs/container/${encodeURIComponent(pkg)}/`;
  }

  if (registry === "quay.io") {
    if (pathParts.length < 2) return "";
    return `https://quay.io/repository/${pathParts.map(encodeURIComponent).join("/")}?tab=tags`;
  }

  if (registry === "gcr.io" || registry.endsWith(".gcr.io")) {
    const project = pathParts[0];
    const imagePath = pathParts.slice(1).join("/");
    if (!project || !imagePath) return "";
    return `https://console.cloud.google.com/gcr/images/${encodeURIComponent(project)}/GLOBAL/${imagePath
      .split("/")
      .map(encodeURIComponent)
      .join("/")}`;
  }

  return "";
}

function setContainerImageCell(cell, image) {
  const text = image || "-";
  cell.replaceChildren();
  cell.title = image || "";
  if (!image) {
    cell.textContent = "-";
    return;
  }

  const url = containerImageURL(image);
  if (!url) {
    cell.textContent = text;
    return;
  }

  const link = document.createElement("a");
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = text;
  cell.appendChild(link);
}

function updateContainerNetworkColumns(nodeName, containerUid, processInfo) {
  if (!nodeName || !containerUid || !processInfo) return;
  const rows = document.querySelectorAll(
    `#containersTableBody tr[data-node="${cssAttrValue(nodeName)}"][data-container-uid="${cssAttrValue(containerUid)}"]`,
  );
  rows.forEach((row) => {
    const network = processNetworkType(processInfo);
    const netns = processInfo.netns || 0;
    row.dataset.network = network;
    row.dataset.netns = netns ? String(netns) : "";
    row.dataset.cgroupSlice = processInfo.cgroupSlice || "";
    const networkCell = row.querySelector(".col-network");
    if (networkCell) {
      networkCell.innerHTML = netns
        ? colorSpan(
            String(netns),
            network,
            network === "host"
              ? "host network namespace"
              : "pod network namespace",
          )
        : '<span class="endpoint-unknown">unknown</span>';
    }
    applyContainerFiltersToRow(row);
  });
}

function upsertContainerRow(container) {
  if (!window.containersTable || !container || !container.containerUid) return;

  const key = `container-${container.nodeName}-${container.containerUid}`;
  let row = document.getElementById(key);
  if (!row) {
    row = document.createElement("tr");
    row.id = key;
    for (let i = 0; i < 9; i++) {
      row.appendChild(document.createElement("td"));
    }
    row.cells[0].className = "col-node";
    row.cells[1].className = "col-container-uid";
    row.cells[2].className = "col-pod-uid";
    row.cells[3].className = "col-namespace";
    row.cells[4].className = "col-pod";
    row.cells[5].className = "col-container";
    row.cells[6].className = "col-image";
    row.cells[7].className = "col-network";
    row.cells[8].className = "col-labels";
    window.containersTable.appendChild(row);
  }

  row.dataset.namespace = (container.namespace || "").toLowerCase();
  row.dataset.pod = (container.podName || "").toLowerCase();
  row.dataset.node = container.nodeName;
  row.dataset.network = "";
  row.dataset.netns = "";
  row.dataset.cgroupSlice =
    container.cgroupSlice || row.dataset.cgroupSlice || "";
  row.dataset.containerUid = container.containerUid;
  row.dataset.podUid = container.podUid || "";
  row.dataset.labels = formatContainerLabels(container.labels);

  row.cells[0].innerHTML = colorSpan(container.nodeName, "host");
  row.cells[1].textContent = container.containerUid;
  row.cells[2].textContent = container.podUid || "-";
  row.cells[3].innerHTML = container.namespace
    ? colorSpan(container.namespace, "pod")
    : "-";
  row.cells[4].innerHTML = container.podName
    ? colorSpan(container.podName, "pod")
    : "-";
  row.cells[5].innerHTML = container.containerName
    ? colorSpan(container.containerName, "pod")
    : container.name || "-";
  setContainerImageCell(row.cells[6], container.image || "");
  row.cells[7].innerHTML = '<span class="endpoint-unknown">unknown</span>';
  const labelCount =
    container.labels && typeof container.labels === "object"
      ? Object.keys(container.labels).length
      : 0;
  row.cells[8].textContent = labelCount ? `${labelCount} labels` : "-";
  row.cells[8].title = labelCount ? "Show labels" : "";
  row.cells[8].classList.toggle("clickable-labels", labelCount > 0);

  if (container.netns) {
    updateContainerNetworkColumns(
      container.nodeName,
      container.containerUid,
      container,
    );
  }
  applyContainerFiltersToRow(row);
}

function handleContainerAdded(data) {
  console.assert(
    hasOwnField(data, "containerUid") && typeof data.containerUid === "string",
    "Container added event must have containerUid string",
    data,
  );
  console.assert(
    hasOwnField(data, "name") && typeof data.name === "string",
    "Container added event must have name string",
    data,
  );
  console.assert(
    data.nodeName,
    "Container added event must have nodeName",
    data,
  );

  updateDropdownsFromEvent(data);
  const container = rememberContainer(data);
  upsertContainerRow(container);
  updateViewCounts();
}

function setupContainerLabelClicks() {
  if (!window.containersTable) return;
  window.containersTable.addEventListener("click", (event) => {
    const cell = event.target.closest("td.col-labels");
    if (!cell || !cell.classList.contains("clickable-labels")) return;
    const row = cell.closest("tr");
    const labels = row ? row.dataset.labels || "" : "";
    if (!labels) return;
    window.alert(labels);
  });
}

function handleContainerDeleted(data) {
  if (data && data.containerUid) {
    removePodOwnerForContainer(data.containerUid);
    forgetContainer(data.containerUid);
    for (const [key, containerUid] of window.podOwnerByNodeNetNS) {
      if (containerUid === data.containerUid) {
        window.podOwnerByNodeNetNS.delete(key);
      }
    }
    for (const [key, containerUid] of window.podOwnerByNodeNetNSPort) {
      if (containerUid === data.containerUid) {
        window.podOwnerByNodeNetNSPort.delete(key);
      }
    }
    const row = document.getElementById(
      `container-${data.nodeName || ""}-${data.containerUid}`,
    );
    if (row) row.remove();
    updateViewCounts();
  }
}

function findContainerForEvent(data) {
  if (data.containerUid) {
    return getContainer(data.containerUid);
  }
  return null;
}

function handleContainerMetainfo(data) {
  console.assert(
    hasOwnField(data, "containerUid") && typeof data.containerUid === "string",
    "Container metadata event must have containerUid string",
    data,
  );
  console.assert(
    data.namespace,
    "Container metadata event must have namespace",
    data,
  );
  console.assert(
    data.podName,
    "Container metadata event must have podName",
    data,
  );
  console.assert(
    data.podUid,
    "Container metadata event must have podUid",
    data,
  );
  console.assert(
    data.nodeName,
    "Container metadata event must have nodeName",
    data,
  );
  console.assert(
    typeof data.containerName === "string",
    "Container metadata event must have containerName string",
    data,
  );

  const nodeName = data.nodeName;
  const containerUid = data.containerUid;
  const nodeSelectorValue = cssAttrValue(nodeName);
  const containerUidSelectorValue = cssAttrValue(containerUid);
  const podUidSelectorValue = cssAttrValue(data.podUid);
  updateDropdownsFromEvent(data);
  const container = rememberContainer(data);
  upsertContainerRow(container);
  if (typeof refreshProcessRowsForContainer === "function") {
    refreshProcessRowsForContainer(container);
  }

  // Select rows by exact container UID and pod UID.
  const selectors = [
    `#containersTableBody tr[data-node="${nodeSelectorValue}"][data-container-uid="${containerUidSelectorValue}"]`,
    `#portsTableBody tr[data-node-name="${nodeSelectorValue}"][data-container-uid="${containerUidSelectorValue}"]`,
    `#connectionsTableBody tr[data-node-name="${nodeSelectorValue}"][data-container-uid="${containerUidSelectorValue}"]`,
    `#containersTableBody tr[data-node="${nodeSelectorValue}"][data-pod-uid="${podUidSelectorValue}"]`,
    `#portsTableBody tr[data-node-name="${nodeSelectorValue}"][data-pod-uid="${podUidSelectorValue}"]`,
    `#connectionsTableBody tr[data-node-name="${nodeSelectorValue}"][data-pod-uid="${podUidSelectorValue}"]`,
  ];
  const rows = document.querySelectorAll(selectors.join(", "));
  rows.forEach((row) => {
    if (row.closest("#portsTableBody")) {
      updatePortMetadataForRow(row, data, container);
      return;
    }

    const nsCell = row.querySelector(".col-namespace");
    if (nsCell) nsCell.innerHTML = colorSpan(data.namespace, "pod");
    const podUidCell = row.querySelector(".col-pod-uid");
    if (podUidCell) podUidCell.textContent = data.podUid;
    const podCell = row.querySelector(".col-pod");
    if (podCell) podCell.innerHTML = colorSpan(data.podName, "pod");
    const containerCell = row.querySelector(".col-container");
    if (containerCell)
      containerCell.innerHTML = colorSpan(data.containerName, "pod");

    row.dataset.namespace = data.namespace.toLowerCase();
    row.dataset.pod = data.podName.toLowerCase();
    row.dataset.podName = data.podName;
    row.dataset.podUid = data.podUid;
    row.dataset.containerUid = data.containerUid;
    const pid = parseInt(row.dataset.pid, 10) || 0;
    const processInfo = pid
      ? window.processMetadata.get(`${nodeName}/${pid}`)
      : null;
    syncConnectionPodMetadata(row, processInfo, container);
    if (row.closest("#connectionsTableBody")) {
      markConnectionRowDirty(row);
    }
  });

  updateViewCounts();
}
