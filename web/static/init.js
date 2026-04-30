// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------

function switchToView(target) {
  document.querySelectorAll(".nav-link[data-view]").forEach((l) => {
    l.classList.toggle("active", l.getAttribute("data-view") === target);
  });
  document.querySelectorAll(".view[data-view]").forEach((v) => {
    v.classList.toggle("active", v.getAttribute("data-view") === target);
  });
}

function setupViewSwitching() {
  const activeLink = document.querySelector(".nav-link.active[data-view]");
  switchToView(
    activeLink ? activeLink.getAttribute("data-view") : "connections",
  );

  document.querySelectorAll(".nav-link[data-view]").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      switchToView(link.getAttribute("data-view"));
    });
  });
}

// ---------------------------------------------------------------------------
// Deployment view
// ---------------------------------------------------------------------------

function setupDeploymentView() {
  const deploymentType = document.getElementById("deploymentType");
  const kubernetesDeployment = document.getElementById("kubernetesDeployment");
  const dockerComposeDeployment = document.getElementById(
    "dockerComposeDeployment",
  );
  const dockerRunDeployment = document.getElementById("dockerRunDeployment");

  if (!deploymentType) return;

  function update() {
    [
      kubernetesDeployment,
      dockerComposeDeployment,
      dockerRunDeployment,
    ].forEach((el) => {
      if (el) el.style.display = "none";
    });
    const sel = deploymentType.value;
    if (sel === "kubernetes" && kubernetesDeployment)
      kubernetesDeployment.style.display = "";
    if (sel === "docker-compose" && dockerComposeDeployment)
      dockerComposeDeployment.style.display = "";
    if (sel === "docker-run" && dockerRunDeployment)
      dockerRunDeployment.style.display = "";
  }

  deploymentType.addEventListener("change", update);
  update();
}

// ---------------------------------------------------------------------------
// Debounce
// ---------------------------------------------------------------------------

function debounce(func, wait) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

function init() {
  // Get DOM elements
  window.connectionsTable = document.getElementById("connectionsTableBody");
  window.nodesTable = document.getElementById("nodesTableBody");
  window.portsTable = document.getElementById("portsTableBody");
  window.processesTable = document.getElementById("processesTableBody");
  window.eventsList = document.getElementById("eventsList");
  window.connectionToggleBtn = document.getElementById("connectionToggle");

  window.filterConnectionNamespace = document.getElementById(
    "filterConnectionNamespace",
  );
  window.filterConnectionNode = document.getElementById("filterConnectionNode");
  window.filterConnectionProtocol = document.getElementById(
    "filterConnectionProtocol",
  );
  window.filterConnectionState = document.getElementById(
    "filterConnectionState",
  );
  window.filterConnectionPortType = document.getElementById(
    "filterConnectionPortType",
  );
  window.filterConnectionPort = document.getElementById("filterConnectionPort");
  window.filterConnectionIPFamily = document.getElementById(
    "filterConnectionIPFamily",
  );
  window.filterConnectionHost = document.getElementById("filterConnectionHost");
  window.filterConnectionExternal = document.getElementById(
    "filterConnectionExternal",
  );
  window.filterConnectionDedupe = document.getElementById(
    "filterConnectionDedupe",
  );

  window.filterConnectionPodInput = document.getElementById(
    "filterConnectionPod",
  );
  window.filterConnectionPodCheck = document.getElementById(
    "filterConnectionPodCheck",
  );

  // Node filters
  window.filterNodeName = document.getElementById("filterNodeName");

  // Container filters
  window.filterContainerNamespace = document.getElementById(
    "filterContainerNamespace",
  );
  window.filterContainerPod = document.getElementById("filterContainerPod");
  window.filterContainerNode = document.getElementById("filterContainerNode");
  window.filterContainerCgroup = document.getElementById(
    "filterContainerCgroup",
  );
  window.filterContainerNetwork = document.getElementById(
    "filterContainerNetwork",
  );

  // Port filters
  window.filterPortNode = document.getElementById("filterPortNode");
  window.filterPortNamespace = document.getElementById("filterPortNamespace");
  window.filterPortNumber = document.getElementById("filterPortNumber");
  window.filterPortNetNS = document.getElementById("filterPortNetNS");
  window.filterPortIPFamily = document.getElementById("filterPortIPFamily");
  window.filterPortType = document.getElementById("filterPortType");

  // Process filters
  window.filterProcessNode = document.getElementById("filterProcessNode");
  window.filterProcessPID = document.getElementById("filterProcessPID");
  window.filterProcessNamespace = document.getElementById(
    "filterProcessNamespace",
  );
  window.filterProcessPod = document.getElementById("filterProcessPod");
  window.filterProcessNetwork = document.getElementById("filterProcessNetwork");

  // Event filters
  window.filterEventType = document.getElementById("filterEventType");
  window.filterEventProtocol = document.getElementById("filterEventProtocol");
  window.filterEventNode = document.getElementById("filterEventNode");
  window.filterEventState = document.getElementById("filterEventState");
  window.filterEventLocalIP = document.getElementById("filterEventLocalIP");
  window.filterEventRemoteIP = document.getElementById("filterEventRemoteIP");
  window.filterEventLocalPort = document.getElementById("filterEventLocalPort");
  window.filterEventRemotePort = document.getElementById(
    "filterEventRemotePort",
  );
  window.filterEventPID = document.getElementById("filterEventPID");
  window.filterEventSockCookie = document.getElementById(
    "filterEventSockCookie",
  );

  window.containersTable = document.getElementById("containersTableBody");

  if (typeof setupExternalHostnameMappingClicks === "function") {
    setupExternalHostnameMappingClicks();
  }
  if (typeof setupConnectionStateTooltips === "function") {
    setupConnectionStateTooltips();
  }
  if (typeof setupConnectionRowLinks === "function") {
    setupConnectionRowLinks();
  }
  if (typeof setupContainerLabelClicks === "function") {
    setupContainerLabelClicks();
  }

  if (window.connectionToggleBtn) {
    window.connectionToggleBtn.addEventListener("click", () => {
      if (window.shouldConnect) {
        if (typeof disconnect === "function") disconnect();
      } else {
        if (typeof connect === "function") connect();
      }
    });
  }

  // Create a single debounced filter function
  const debouncedConnFilter = debounce(() => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  }, 300);

  // Helper function to add event listeners
  const addFilterListener = (element, eventType, handler) => {
    if (element) {
      element.addEventListener(eventType, handler);
    }
  };

  addFilterListener(
    window.filterConnectionNamespace,
    "input",
    debouncedConnFilter,
  );
  addFilterListener(
    window.filterConnectionPodInput,
    "input",
    debouncedConnFilter,
  );
  addFilterListener(window.filterConnectionNode, "input", debouncedConnFilter);
  addFilterListener(window.filterConnectionProtocol, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionState, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionPortType, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionPort, "input", debouncedConnFilter);
  addFilterListener(window.filterConnectionIPFamily, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionHost, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionPodCheck, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionExternal, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });
  addFilterListener(window.filterConnectionDedupe, "change", () => {
    if (typeof applyConnectionFilters === "function") applyConnectionFilters();
  });

  // Port filter event listeners
  const debouncedPortFilter = debounce(() => {
    if (typeof applyPortFilters === "function") applyPortFilters();
  }, 300);
  if (window.filterPortNode)
    window.filterPortNode.addEventListener("input", debouncedPortFilter);
  if (window.filterPortNamespace)
    window.filterPortNamespace.addEventListener("input", debouncedPortFilter);
  if (window.filterPortNumber)
    window.filterPortNumber.addEventListener("input", debouncedPortFilter);
  if (window.filterPortNetNS)
    window.filterPortNetNS.addEventListener("input", debouncedPortFilter);
  if (window.filterPortIPFamily)
    window.filterPortIPFamily.addEventListener("change", () => {
      if (typeof applyPortFilters === "function") applyPortFilters();
    });
  if (window.filterPortType)
    window.filterPortType.addEventListener("change", () => {
      if (typeof applyPortFilters === "function") applyPortFilters();
    });

  // Node filter event listeners
  const debouncedNodeFilter = debounce(() => {
    if (typeof applyNodeFilters === "function") applyNodeFilters();
  }, 300);
  if (window.filterNodeName)
    window.filterNodeName.addEventListener("input", debouncedNodeFilter);

  // Process filter event listeners
  const debouncedProcessFilter = debounce(() => {
    if (typeof applyProcessFilters === "function") applyProcessFilters();
  }, 300);
  [
    window.filterProcessNode,
    window.filterProcessPID,
    window.filterProcessNamespace,
    window.filterProcessPod,
  ].forEach((filter) => {
    if (filter) filter.addEventListener("input", debouncedProcessFilter);
  });
  if (window.filterProcessNetwork) {
    window.filterProcessNetwork.addEventListener("change", () => {
      if (typeof applyProcessFilters === "function") applyProcessFilters();
    });
  }

  // Container filter event listeners
  const debouncedContainerFilter = debounce(() => {
    if (typeof applyContainerFilters === "function") applyContainerFilters();
  }, 300);
  if (window.filterContainerNamespace)
    window.filterContainerNamespace.addEventListener(
      "input",
      debouncedContainerFilter,
    );
  if (window.filterContainerPod)
    window.filterContainerPod.addEventListener(
      "input",
      debouncedContainerFilter,
    );
  if (window.filterContainerNode)
    window.filterContainerNode.addEventListener(
      "input",
      debouncedContainerFilter,
    );
  if (window.filterContainerCgroup)
    window.filterContainerCgroup.addEventListener(
      "input",
      debouncedContainerFilter,
    );
  if (window.filterContainerNetwork)
    window.filterContainerNetwork.addEventListener("change", () => {
      if (typeof applyContainerFilters === "function") applyContainerFilters();
    });

  // Event filter event listeners
  const clearEventsOnFilterChange = () => {
    if (typeof clearDisplayedEvents === "function") clearDisplayedEvents();
  };
  [
    window.filterEventType,
    window.filterEventProtocol,
    window.filterEventNode,
    window.filterEventState,
    window.filterEventLocalIP,
    window.filterEventRemoteIP,
    window.filterEventLocalPort,
    window.filterEventRemotePort,
    window.filterEventPID,
    window.filterEventSockCookie,
  ].forEach((filter) => {
    if (!filter) return;
    filter.addEventListener("change", clearEventsOnFilterChange);
    filter.addEventListener("input", clearEventsOnFilterChange);
  });

  const clearEventsBtn = document.getElementById("clearEvents");
  if (clearEventsBtn) {
    clearEventsBtn.addEventListener("click", () => {
      if (typeof clearDisplayedEvents === "function") clearDisplayedEvents();
    });
  }

  setupViewSwitching();
  setupDeploymentView();
  if (typeof updateViewCounts === "function") updateViewCounts(); // Initialize counts on page load
  if (typeof connect === "function") connect();
}

document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM fully loaded");
  init();
});
