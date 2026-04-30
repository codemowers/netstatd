function handleHostInfo(data) {
  console.assert(data.nodeName, "Host info event must have nodeName", data);
  console.assert(
    hasOwnField(data, "hostIPs") && Array.isArray(data.hostIPs),
    "Host info event must have hostIPs array",
    data,
  );
  window.hostIPsByNode.set(data.nodeName, data.hostIPs);
  for (const ip of data.hostIPs) {
    forgetPodOwnerForIP(ip);
  }
  addToDatalist("nodeList", data.nodeName);
  // Store host network namespace by node name for node-scoped host/pod detection.
  console.assert(
    hasOwnField(data, "hostNetNS") && typeof data.hostNetNS === "number",
    "Host info event must have hostNetNS number",
    data,
  );
  console.assert(data.hostNetNS > 0, "hostNetNS must be > 0", data);
  window.hostNetNSByNode.set(data.nodeName, data.hostNetNS);
  handleImageHash(data.nodeName, data.imageHash || "");
  upsertNodeRow(data.nodeName);
  updateViewCounts();
}

function clearBrowserStorage() {
  window.endpointBindingByAddress.clear();
  window.listeningPortByNodeNetNSProtocolPort.clear();
  if (!window.localStorage) return;
  localStorage.clear();
}

function scheduleImageHashReload() {
  if (window.imageHashReloadTimer) return;
  window.imageHashReloadTimer = setTimeout(() => {
    window.location.reload();
  }, 10000);
}

function handleImageHash(nodeName, imageHash) {
  if (!imageHash) return;

  for (const [seenNodeName, seenHash] of window.imageHashByNode) {
    if (seenNodeName !== nodeName && seenHash && seenHash !== imageHash) {
      clearBrowserStorage();
      scheduleImageHashReload();
      break;
    }
  }
  window.imageHashByNode.set(nodeName, imageHash);

  if (!window.localStorage) return;
  const storedHash = localStorage.getItem(window.imageHashStorageKey);
  if (storedHash && storedHash !== imageHash) {
    clearBrowserStorage();
  }
  localStorage.setItem(window.imageHashStorageKey, imageHash);
}

function shortHash(hash) {
  return hash ? hash.slice(0, 12) : "-";
}

function formatNodeIPs(ips) {
  if (!ips || !ips.length) return "-";
  return ips.join("\n");
}

function upsertNodeRow(nodeName) {
  if (!window.nodesTable || !nodeName) return;

  const key = `node-${nodeName}`;
  let row = document.getElementById(key);
  if (!row) {
    row = document.createElement("tr");
    row.id = key;
    for (let i = 0; i < 4; i++) {
      row.appendChild(document.createElement("td"));
    }
    row.cells[0].className = "col-node";
    row.cells[1].className = "col-ip-addresses";
    row.cells[2].className = "col-netns";
    row.cells[3].className = "col-image-hash";
    window.nodesTable.appendChild(row);
  }

  const hostNetNS = window.hostNetNSByNode.get(nodeName);
  const imageHash = window.imageHashByNode.get(nodeName) || "";
  row.dataset.nodeName = nodeName;
  row.dataset.netns = hostNetNS ? String(hostNetNS) : "";
  row.dataset.imageHash = imageHash;

  row.cells[0].innerHTML = colorSpan(nodeName, "host");
  row.cells[1].textContent = formatNodeIPs(window.hostIPsByNode.get(nodeName));
  row.cells[2].innerHTML = hostNetNS
    ? colorSpan(String(hostNetNS), "host", "host network namespace")
    : "-";
  row.cells[3].textContent = shortHash(imageHash);
  row.cells[3].title = imageHash;

  applyNodeFiltersToRow(row);
}
