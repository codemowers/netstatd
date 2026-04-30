function eventValue(event, field) {
  const value = event ? event[field] : "";
  if (value === undefined || value === null) return "";
  return String(value);
}

function eventMatchesFilters(event) {
  const eventType = window.filterEventType ? window.filterEventType.value : "";
  const protocol = window.filterEventProtocol
    ? window.filterEventProtocol.value
    : "";
  const node = window.filterEventNode
    ? window.filterEventNode.value.toLowerCase()
    : "";
  const state = window.filterEventState ? window.filterEventState.value : "";
  const localIP = window.filterEventLocalIP
    ? window.filterEventLocalIP.value.trim().toLowerCase()
    : "";
  const remoteIP = window.filterEventRemoteIP
    ? window.filterEventRemoteIP.value.trim().toLowerCase()
    : "";
  const localPort = window.filterEventLocalPort
    ? window.filterEventLocalPort.value.trim()
    : "";
  const remotePort = window.filterEventRemotePort
    ? window.filterEventRemotePort.value.trim()
    : "";
  const pid = window.filterEventPID ? window.filterEventPID.value.trim() : "";
  const sockCookie = window.filterEventSockCookie
    ? window.filterEventSockCookie.value.trim()
    : "";

  if (eventType && eventValue(event, "type") !== eventType) return false;
  if (protocol && eventValue(event, "protocol") !== protocol) return false;
  if (node && !eventValue(event, "nodeName").toLowerCase().includes(node)) {
    return false;
  }
  if (state && eventValue(event, "state") !== state) return false;
  if (
    localIP &&
    !eventValue(event, "localIP").toLowerCase().includes(localIP)
  ) {
    return false;
  }
  if (
    remoteIP &&
    !eventValue(event, "remoteIP").toLowerCase().includes(remoteIP)
  ) {
    return false;
  }
  if (localPort && eventValue(event, "localPort") !== localPort) return false;
  if (remotePort && eventValue(event, "remotePort") !== remotePort)
    return false;
  if (pid && eventValue(event, "pid") !== pid) return false;
  if (sockCookie && eventValue(event, "sockCookie") !== sockCookie)
    return false;

  return true;
}

function clearDisplayedEvents() {
  if (window.eventsList) window.eventsList.innerHTML = "";
  if (typeof updateViewCounts === "function") updateViewCounts();
  if (typeof updateToggleButton === "function") updateToggleButton();
}

function storeAndDisplayEvent(event) {
  if (!window.eventsList) return;
  if (!eventMatchesFilters(event)) return;

  // Try to get timestamp from event
  let ts = "-";
  if (event.timestamp) {
    try {
      // Try to parse the timestamp
      const date = new Date(event.timestamp);
      if (!isNaN(date.getTime())) {
        ts = date.toLocaleTimeString();
      }
    } catch (e) {
      console.warn("Failed to parse timestamp:", event.timestamp, e);
    }
  } else {
    // Use current time if no timestamp in event
    ts = new Date().toLocaleTimeString();
  }

  const row = document.createElement("tr");
  row.innerHTML = `
    <td class="col-timestamp">${ts}</td>
    <td class="col-event-type">${event.type || "-"}</td>
    <td class="col-node">${event.nodeName || "-"}</td>
    <td><pre style="margin:0;white-space:pre-wrap;word-break:break-all">${JSON.stringify(event, null, 2)}</pre></td>
  `;

  window.eventsList.insertBefore(row, window.eventsList.firstChild);

  while (window.eventsList.rows.length > 25) {
    window.eventsList.deleteRow(window.eventsList.rows.length - 1);
  }
}
