function handleEvent(event) {
  window.eventCount++;
  updateToggleButton();

  console.assert(
    hasOwnField(event, "type") && typeof event.type === "string",
    "WebSocket event must have type string",
    event,
  );
  console.assert(
    hasOwnField(event, "timestamp") && typeof event.timestamp === "string",
    "WebSocket event must have timestamp string",
    event,
  );

  const eventType = event.type;

  if (!eventType) {
    console.warn("Event missing type field:", event);
    // Still store and display the event
    storeAndDisplayEvent(event);
    return;
  }

  switch (eventType) {
    case "host.info":
      handleHostInfo(event);
      break;
    case "container.added":
      handleContainerAdded(event);
      break;
    case "container.deleted":
      handleContainerDeleted(event);
      break;
    case "connection.event":
    case "connection.accepted":
      handleConnectionEvent(event);
      break;
    case "port.listening":
      handlePortListening(event);
      break;
    case "container.metainfo":
      handleContainerMetainfo(event);
      break;
    case "process.metainfo":
      handleProcessMetainfo(event);
      break;
    default:
      console.warn("Unknown event type:", eventType);
  }

  storeAndDisplayEvent(event);
}
