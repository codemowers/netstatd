# Agent Guidelines

## Key Principles

1. **Never mix pod UID and container UID**
   - These are distinct identifiers with different purposes
   - Pod UID identifies a Kubernetes pod
   - Container UID identifies a specific container instance
   - Do not use one as a fallback for the other

2. **Avoid arbitrary fallbacks**
   - Do not add `||` fallbacks randomly unless explicitly instructed
   - Each fallback should have a clear, justified reason
   - Prefer explicit handling of missing data over silent fallbacks

3. **Data integrity**
   - Maintain clear separation between different types of identifiers
   - When data is missing, handle it explicitly rather than substituting unrelated data
   - Document any necessary fallbacks with clear reasoning

## Examples to Avoid

### ❌ Bad: Mixing identifiers

```javascript
// Don't do this
const containerUid = event.containerUid || event.podUID;
```

### ❌ Bad: Arbitrary fallbacks

```javascript
// Don't do this without explicit instruction
const podName = data.podName || data.namespace || "unknown";
```

### ✅ Good: Explicit handling

```javascript
// Do this instead
let containerUid;
if (event.containerUid) {
  containerUid = event.containerUid;
} else {
  containerUid = null;
}
```

## When to Make Exceptions

Only deviate from these guidelines when:

- Explicitly instructed by the user
- There's a documented requirement for specific fallback behavior
- The fallback is clearly justified and doesn't compromise data integrity

## Code Organization Guidelines

4. **Use early returns where possible**
   - Return early when conditions are not met to reduce nesting
   - This makes code more readable and easier to follow
   - Avoid deep nesting by checking for invalid states first
   - Each early return should handle a specific edge case clearly

5. **Minimize the number of functions**
   - Each function should have a clear, single responsibility
   - Avoid creating helper functions that are only used once
   - Consolidate similar functionality into shared utilities
   - Remove unused functions during refactoring

6. **Reduce data duplication in JavaScript structures**
   - Store each piece of data in only one place
   - Use references instead of copying data between structures
   - Prefer targeted DOM lookup with `querySelector` and data attributes over broad table scans
   - Do not add new browser-side indexes unless there is a documented need that cannot be handled by existing maps or data attributes
   - Regularly audit data structures to ensure consistency

## Examples to Follow

### ✅ Good: Single source of truth

```javascript
// Store container data once
const containers = new Map(); // containerUid -> container info

// Access via reference, not duplication
function getContainerInfo(containerUid) {
  return containers.get(containerUid);
}
```

### ✅ Good: Scoped lookup with data attributes

```javascript
const selector =
  `tr[data-node-name="${cssAttrValue(nodeName)}"]` +
  `[data-protocol="${cssAttrValue(protocol)}"]` +
  `[data-port="${cssAttrValue(port)}"]`;
document.querySelectorAll(selector).forEach(renderRow);
```

### ❌ Bad: Data duplication

```javascript
// Don't do this - same data in multiple places
const containerInfo = { name: "app", podName: "web" };
containers.set("uid1", containerInfo);
ipToPod.set("10.0.0.1", containerInfo); // Same object reference is okay
// But if modified separately, they can get out of sync
```

## Implementation Priorities

1. **Before adding new data structures**, check if existing ones can serve the purpose
2. **Before creating new functions**, check if existing ones can be extended
3. **Regularly remove** unused variables, functions, and imports
4. **Keep data structures flat** where possible, avoiding nested duplication

## Related Files

Keep these guidelines in mind when working with:

- `web/static/app.js` - Main application logic
- Any other JavaScript files in the project
