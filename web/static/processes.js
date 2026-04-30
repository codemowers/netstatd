function processRowNetwork(processInfo) {
  if (processInfo && processInfo.isHostNetNS === true) return "host";
  if (processInfo && processInfo.isHostNetNS === false) return "pod";
  return "unknown";
}

function renderProcessNetns(netns, network) {
  if (!netns) return "-";
  if (network === "pod") return colorSpan(netns, "pod", "pod");
  if (network === "host") return colorSpan(netns, "host", "host");
  return colorSpan(netns, "unknown", "unknown");
}

function upsertProcessRow(data, containerRecord) {
  if (!window.processesTable || !data || !data.nodeName || !data.pid) return;

  const key = `process-${data.nodeName}-${data.pid}`;
  let row = document.getElementById(key);
  if (!row) {
    row = document.createElement("tr");
    row.id = key;
    for (let i = 0; i < 10; i++) {
      row.appendChild(document.createElement("td"));
    }
    row.cells[0].className = "col-node";
    row.cells[1].className = "col-pid";
    row.cells[2].className = "col-exe";
    row.cells[3].className = "col-netns";
    row.cells[5].className = "col-namespace";
    row.cells[6].className = "col-pod";
    row.cells[7].className = "col-container";
    row.cells[8].className = "col-container-uid";
    row.cells[9].className = "col-cgroup-slice";
    window.processesTable.appendChild(row);
  }

  const network = processRowNetwork(data);
  const namespace = containerRecord ? containerRecord.namespace || "" : "";
  const podName = containerRecord ? containerRecord.podName || "" : "";
  const containerName = containerRecord
    ? containerRecord.containerName || ""
    : "";
  const containerUid = data.containerUid || "";
  const netns =
    data.netns !== undefined && data.netns !== null ? String(data.netns) : "";

  row.dataset.nodeName = data.nodeName;
  row.dataset.pid = String(data.pid);
  row.dataset.netns = netns;
  row.dataset.network = network;
  row.dataset.namespace = namespace;
  row.dataset.podName = podName;
  row.dataset.containerName = containerName;
  row.dataset.containerUid = containerUid;

  row.cells[0].innerHTML = colorSpan(data.nodeName, "host");
  row.cells[1].textContent = data.pid;
  setTailClippedTextCell(row.cells[2], data.exe || "");
  row.cells[3].innerHTML = renderProcessNetns(netns, network);
  row.cells[3].title = netns ? `${network} netns: ${netns}` : "";
  if (!row.cells[4].textContent) {
    row.cells[4].textContent = "-";
  }
  row.cells[5].innerHTML = namespace ? colorSpan(namespace, "pod") : "-";
  row.cells[6].innerHTML = podName ? colorSpan(podName, "pod") : "-";
  row.cells[7].innerHTML = containerName
    ? colorSpan(containerName, "pod")
    : "-";
  setTailClippedTextCell(row.cells[8], containerUid);
  setTailClippedTextCell(row.cells[9], data.cgroupSlice || "");

  applyProcessFiltersToRow(row);
}

function observeProcessLocalIP(nodeName, pid, localIP) {
  if (!window.processesTable || !nodeName || !pid || !localIP) return;
  const rows = document.querySelectorAll(
    `#processesTableBody tr[data-node-name="${cssAttrValue(nodeName)}"][data-pid="${cssAttrValue(pid)}"]`,
  );
  rows.forEach((row) => {
    if (!row.cells[4]) return;

    const observedIPs = row.dataset.observedLocalIps
      ? row.dataset.observedLocalIps.split("\n").filter(Boolean)
      : [];
    if (observedIPs.includes(localIP)) return;
    if (observedIPs.length >= 2) return;

    observedIPs.push(localIP);
    row.dataset.observedLocalIps = observedIPs.join("\n");
    row.dataset.observedLocalMultiIp = String(observedIPs.length > 1);

    if (observedIPs.length === 1) {
      row.cells[4].innerHTML = colorSpan(formatIP(localIP), "pod");
      row.cells[4].title = localIP;
      return;
    }

    row.cells[4].innerHTML = observedIPs
      .map((ip) => colorSpan(formatIP(ip), "external"))
      .join("<br>");
    row.cells[4].title = row.dataset.observedLocalIps;
  });
}

function refreshProcessRowsForContainer(containerRecord) {
  if (!containerRecord || !containerRecord.containerUid) return;
  for (const processInfo of window.processMetadata.values()) {
    if (processInfo.containerUid !== containerRecord.containerUid) continue;
    upsertProcessRow(processInfo, containerRecord);
  }
}

function handleProcessMetainfo(data) {
  const pid = data.pid;
  const nodeName = data.nodeName;
  const netns = data.netns;
  const containerUid = data.containerUid;

  // Assertions for process metadata events
  console.assert(
    hasOwnField(data, "nodeName") && typeof data.nodeName === "string",
    "Process metadata event must have nodeName string",
    data,
  );
  console.assert(
    hasOwnField(data, "pid") && typeof data.pid === "number",
    "Process metadata event must have pid number",
    data,
  );
  console.assert(pid > 0, "Process metadata event must have nonzero PID", data);
  console.assert(
    !hasOwnField(data, "exe") || typeof data.exe === "string",
    "Process metadata event exe must be string when present",
    data,
  );
  console.assert(
    hasOwnField(data, "netns") && typeof data.netns === "number",
    "Process metadata event must have netns number",
    data,
  );
  console.assert(
    hasOwnField(data, "isHostNetNS") && typeof data.isHostNetNS === "boolean",
    "Process metadata event must have isHostNetNS boolean",
    data,
  );
  console.assert(
    hasOwnField(data, "cgroupSlice") && typeof data.cgroupSlice === "string",
    "Process metadata event must have cgroupSlice string",
    data,
  );

  // Store in process metadata map with nodeName/pid key
  const processKey = `${nodeName}/${pid}`;
  if (typeof data.isHostNetNS !== "boolean") {
    data.isHostNetNS = isHostNetNS(nodeName, netns);
  }
  window.processMetadata.set(processKey, data);
  const containerRecord = containerUid ? getContainer(containerUid) : null;
  upsertProcessRow(data, containerRecord);
  if (containerUid) {
    updateContainerNetworkColumns(nodeName, containerUid, data);
  }

  if (nodeName && netns && data.isHostNetNS === false && containerRecord) {
    rememberPodOwnerForNetNS(nodeName, netns, containerRecord);
  }

  // Update connection rows that have this PID using querySelectorAll
  const rowSelector = `#connectionsTableBody tr[data-node-name="${nodeName}"][data-pid="${pid}"]`;
  const rows = document.querySelectorAll(rowSelector);
  rows.forEach((row) => {
    // Update exe cell using class selector
    const exeCell = row.querySelector(".col-exe");
    if (exeCell) {
      setTailClippedTextCell(exeCell, data.exe);
      exeCell.title = data.cgroupSlice || "";
    }
    const cgroupCell = row.querySelector(".col-cgroup-slice");
    if (cgroupCell) {
      setTailClippedTextCell(cgroupCell, data.cgroupSlice);
    }
    // Update containerUid dataset
    if (data.containerUid) {
      row.dataset.containerUid = data.containerUid;
    }
    if (data.netns) {
      row.dataset.netns = String(data.netns);
    }
    const pidCell = row.querySelector(".col-pid");
    if (pidCell) {
      pidCell.title = data.netns ? String(data.netns) : "";
    }
    syncConnectionPodMetadata(row, data, containerRecord);
    markConnectionRowDirty(row);
  });

  if (netns && netns !== 0 && data.isHostNetNS === false) {
    const portSelector = `#portsTableBody tr[data-node-name="${nodeName}"][data-netns="${netns}"]`;
    document.querySelectorAll(portSelector).forEach((row) => {
      updatePortMetadataForRow(
        row,
        data,
        data.isHostNetNS === false ? containerRecord : null,
      );
    });
  }

  updateViewCounts();
}
