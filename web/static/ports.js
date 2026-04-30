function inferPortType(data, containerRecord) {
  if (containerRecord && containerRecord.podName) return "pod";
  if (data.isHostNetNS === true) return "host";
  if (data.isHostNetNS === false) return "pod";
  return "unknown";
}

function inferPortNetnsType(data, containerRecord) {
  if (data.isHostNetNS === true) return "host";
  if (data.isHostNetNS === false) return "pod";
  return "unknown";
}

function renderNetnsValue(netnsDisplay, networkScope) {
  if (!netnsDisplay || netnsDisplay === "-") return "-";
  if (networkScope === "pod") return colorSpan(netnsDisplay, "pod", "pod");
  if (networkScope === "host") return colorSpan(netnsDisplay, "host", "host");
  return colorSpan(netnsDisplay, "unknown", "unknown");
}

function updatePortMetadataForRow(row, data, containerRecord) {
  if (data.netns !== undefined && data.netns !== null) {
    row.dataset.netns = String(data.netns);
  }

  const nodeName = data.nodeName || row.dataset.nodeName || "";
  const netns = data.netns || parseInt(row.dataset.netns || "", 10) || 0;
  const port = data.port || parseInt(row.dataset.port || "", 10) || 0;
  const protocol = data.protocol || row.dataset.protocol || "";
  const exactProcessInfo =
    nodeName && protocol && netns && port
      ? window.processMetadataByPort.get(
          makePortProcessKey(nodeName, protocol, port, netns),
        ) || null
      : null;
  const isHostScope =
    data.isHostNetNS === true ||
    row.dataset.isHostNetNS === "true" ||
    (exactProcessInfo && exactProcessInfo.isHostNetNS === true);
  let exactPodOwner = null;
  if (!containerRecord && nodeName && netns && port) {
    exactPodOwner = getContainerForNodeNetNSPort(nodeName, netns, port);
    if (exactPodOwner) {
      containerRecord = exactPodOwner;
    }
  }
  if (!containerRecord && !isHostScope && row.dataset.containerUid) {
    containerRecord = getContainer(row.dataset.containerUid) || null;
  }
  if (data.containerUid) {
    row.dataset.containerUid = data.containerUid;
  } else if (isHostScope && !exactPodOwner) {
    row.dataset.containerUid = "";
  }

  const portType = inferPortType(data, containerRecord);
  const networkScope = inferPortNetnsType(data, containerRecord);
  const namespace =
    (containerRecord ? containerRecord.namespace : "") ||
    (isHostScope ? "" : row.dataset.namespace || "");
  const podName =
    (containerRecord ? containerRecord.podName : "") ||
    (isHostScope ? "" : row.dataset.podName || "");
  const containerName =
    (containerRecord ? containerRecord.containerName : "") ||
    (isHostScope ? "" : row.dataset.containerName || "");
  const cgroupSlice =
    (exactProcessInfo ? exactProcessInfo.cgroupSlice : "") ||
    (row.cells[9] ? row.cells[9].textContent : "") ||
    "";
  const lastPID =
    (exactProcessInfo ? exactProcessInfo.pid : 0) || row.dataset.lastPid || "";

  row.dataset.namespace = namespace;
  row.dataset.podName = podName;
  row.dataset.containerName = containerName;
  row.dataset.nodeName = nodeName;
  row.dataset.netns = String(netns || "");
  row.dataset.port = String(port || "");
  row.dataset.containerUid =
    data.containerUid ||
    (containerRecord ? containerRecord.containerUid : "") ||
    row.dataset.containerUid ||
    "";
  row.dataset.podUid =
    (containerRecord ? containerRecord.podUid : "") || row.dataset.podUid || "";
  row.dataset.ipFamily = getIPFamily(data.ip || row.dataset.ip || "");
  row.dataset.portType = portType;
  row.dataset.lastPid = lastPID ? String(lastPID) : "";
  if (data.isHostNetNS !== undefined || exactProcessInfo) {
    row.dataset.isHostNetNS = String(isHostScope);
  }
  row.dataset.ip = data.ip || row.dataset.ip || "";

  const netnsDisplay =
    data.netns && data.netns !== 0 ? data.netns : row.dataset.netns || "-";
  const ipDisplay = data.ip || row.dataset.ip || "-";
  const cells = row.cells;
  if (cells[0])
    cells[0].textContent = data.nodeName || row.dataset.nodeName || "-";
  if (cells[1])
    cells[1].textContent = data.protocol || row.dataset.protocol || "-";
  if (cells[2]) {
    cells[2].textContent = ipDisplay;
    if (data.ip || row.dataset.ip) {
      cells[2].title = data.ip || row.dataset.ip || "";
    } else {
      cells[2].removeAttribute("title");
    }
  }
  if (cells[3]) cells[3].textContent = data.port || row.dataset.port || "-";
  if (cells[4])
    cells[4].innerHTML = namespace ? colorSpan(namespace, "pod") : "-";
  if (cells[5]) cells[5].innerHTML = podName ? colorSpan(podName, "pod") : "-";
  if (cells[6])
    cells[6].innerHTML = containerName ? colorSpan(containerName, "pod") : "-";
  if (cells[7]) {
    cells[7].innerHTML = renderNetnsValue(String(netnsDisplay), networkScope);
    if (data.netns || row.dataset.netns) {
      cells[7].title = `${networkScope} netns: ${data.netns || row.dataset.netns}`;
    } else {
      cells[7].removeAttribute("title");
    }
  }
  if (cells[8]) cells[8].textContent = lastPID || "-";
  if (cells[9]) setTailClippedTextCell(cells[9], cgroupSlice);

  if (portType === "pod" && data.nodeName && data.netns && containerRecord) {
    rememberPodOwnerForNetNS(data.nodeName, data.netns, containerRecord);
  }
  if (portType === "pod" && row.dataset.ip && containerRecord) {
    rememberPodOwnerForIP(row.dataset.ip, containerRecord, nodeName, netns, {
      type: "port.listening",
      event: data,
      row: {
        protocol: row.dataset.protocol || "",
        ip: row.dataset.ip || "",
        port: row.dataset.port || "",
        nodeName: row.dataset.nodeName || "",
        netns: row.dataset.netns || "",
        containerUid: row.dataset.containerUid || "",
      },
    });
  }
}

function handlePortListening(data) {
  // Destructure data properties
  const { nodeName, netns, protocol, ip, port } = data;

  console.assert(nodeName, "Port listening event must have nodeName", data);
  console.assert(
    protocol === "TCP" || protocol === "UDP",
    "Port listening event must have TCP or UDP protocol",
    data,
  );
  console.assert(
    typeof ip === "string",
    "Port listening event must have ip string",
    data,
  );
  console.assert(
    typeof port === "number",
    "Port listening event must have port number",
    data,
  );
  console.assert(
    typeof netns === "number",
    "Port listening event must have netns number",
    data,
  );
  console.assert(
    hasOwnField(data, "isHostNetNS") && typeof data.isHostNetNS === "boolean",
    "Port listening event must have isHostNetNS boolean",
    data,
  );

  // Track listening port by owner tuple (node/protocol/port/netns).
  if (netns !== 0) {
    rememberListeningPort(nodeName, netns, port, protocol);
    rememberListeningEndpointBinding(data);
  }

  const containerRecord = findContainerForEvent(data);

  if (typeof data.isHostNetNS !== "boolean") {
    data.isHostNetNS = isHostNetNS(data.nodeName, data.netns);
  }

  // Check if row exists
  const key = `${nodeName}-${protocol}-${ip}-${port}-${netns}`;
  let row = document.getElementById(key);
  if (!row) {
    row = document.createElement("tr");
    row.id = key;
    row.dataset.protocol = data.protocol;
    row.dataset.nodeName = data.nodeName;
    row.dataset.ip = data.ip;
    row.dataset.port = String(data.port);
    row.dataset.netns = String(data.netns);
    row.dataset.containerUid = "";
    row.dataset.podUid = "";
    row.dataset.containerName = "";
    row.dataset.isHostNetNS = String(data.isHostNetNS);
    const classes = [
      "col-node",
      "col-protocol",
      "col-ip",
      "col-port",
      "col-namespace",
      "col-pod",
      "col-container",
      "col-netns",
      "col-pid",
      "col-cgroup-slice",
    ];
    classes.forEach((className) => {
      const td = document.createElement("td");
      td.className = className;
      row.appendChild(td);
    });
    updatePortMetadataForRow(row, data, containerRecord);

    if (window.portsTable) {
      window.portsTable.appendChild(row);
      applyPortFiltersToRow(row);
    }
  } else {
    updatePortMetadataForRow(row, data, containerRecord);
  }
  updateViewCounts();
}
