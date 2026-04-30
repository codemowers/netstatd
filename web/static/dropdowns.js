function addToDatalist(datalistId, value) {
  if (!value || value.trim() === "") return;

  const datalist = document.getElementById(datalistId);
  if (!datalist) return;

  // Check if option already exists using querySelector
  const existingOption = datalist.querySelector(`option[value="${value}"]`);
  if (!existingOption) {
    const option = document.createElement("option");
    option.value = value;
    datalist.appendChild(option);
  }
}

function updateDropdownsFromEvent(data) {
  // Update node dropdown
  if (data.nodeName) {
    addToDatalist("nodeList", data.nodeName);
  }

  // Update namespace dropdown
  if (data.namespace) {
    addToDatalist("namespaceList", data.namespace);
  }

  // Update pod dropdown
  if (data.podName) {
    addToDatalist("podList", data.podName);
  }
}
