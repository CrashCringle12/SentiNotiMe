// Unique ID for the className.
const MOUSE_VISITED_CLASSNAME = 'crx_mouse_visited';
const ELEMENT_CHANGED_CLASSNAME = 'elm_changed';

let enabled = false;
let observer, targetElem, DOMObserver, detailsElem;
let targetParents = [];

// Previous Incident Clicked Data
let previousData = {};

let incidents = {};
// Previous dom, that we want to track, so we can remove the previous styling.
var prevDOM = null;
// ---- helpers (put once, outside your mutation handler if you can) ----
function canonical(str) {
  return String(str ?? "")
    .replace(/[\uE000-\uF8FF]/g, "")        // strip Azure icon glyphs
    .replace(/([a-z])([A-Z])/g, "$1 $2")    // split camelCase
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");             // keep only letters/numbers
}

function buildCellMap(row) {
  const map = new Map();
  const cells = row.querySelectorAll('[data-automationid^="DetailsRowCell"]');

  for (const cell of cells) {
    const key = cell.getAttribute("data-automation-key") || cell.dataset?.automationKey;
    if (!key) continue;
    map.set(canonical(key), cell);
  }
  return map;
}

function getCell(map, ...keys) {
  for (const k of keys) {
    const el = map.get(canonical(k));
    if (el) return el;
  }
  return null;
}

function getText(map, ...keys) {
  const el = getCell(map, ...keys);
  return el ? el.textContent.trim() : "";
}

var deletedElementsComponent = document.createElement('div');
deletedElementsComponent.classList.add('deleted-nav');
var config = {};
var doRemoveFromQueue = true;
function loadConfig() {
  chrome.storage.local.get({
    doRemoveFromFilteredFromQueue: true, // Default values if not set
    filterTitleRegexPatterns: [],
    filterTagsRegexPatterns: [],
    filterOwnerRegexPatterns: [],
    onlyAlertOnLatest: true,
    desktopNotifications: true
  }, (items) => {
    config = {
      doRemoveFromFilteredFromQueue: items.doRemoveFromFilteredFromQueue,
      filterTitleRegexPatterns: items.filterTitleRegexPatterns,
      filterTagsRegexPatterns: items.filterTagsRegexPatterns,
      filterOwnerRegexPatterns: items.filterOwnerRegexPatterns,
      onlyAlertOnLatest: items.onlyAlertOnLatest,
      desktopNotifications: items.desktopNotifications
    };
    doRemoveFromQueue = config.doRemoveFromFilteredFromQueue;
    console.log("Config loaded:", config);
  });
}
loadConfig();
var initializing = config.desktopNotifications
function checkWordAgainstPatterns(title, patterns) {
  for (let pattern of patterns) {
    let regex = new RegExp(pattern);
    if (regex.test(title)) {
      // console.log(`{{ ${title} }}: matches pattern: ${pattern}`);
      return true;
    }
  }
  return false;
}


function checkTagsAgainstPatterns(tags, patterns) {
  //console.log("Testing Tags")
  for (let pattern of patterns) {
    // console.log(`"${pattern} Test`)
    let regex = new RegExp(pattern);
    // Splitting the string on the hyphen
    var tagsSplit = tags.split(',');
    // Check if the split array has at least two elements
    //console.log("Length: " + tagsSplit.length)
    if (tagsSplit.length > 1) {
      for (let tag of tagsSplit) {
        //console.log(`Testing ${tag} vs ${pattern}`)
        if (regex.test(tag)) {
          // console.log(`tag ${tag} : matches pattern: ${pattern}`);
          return true;
        }
      }
    } else {
      if (regex.test(tags)) {
        // console.log(`Tags ${tags}  : matches pattern: ${pattern}`);
        return true;
      }
    }
  }
  return false;
}

function getElementByXpath(path) {
  return document.evaluate(path, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
}

// Highlights the DOM element when the mouse moves
var highlightFunc = function (e) {
  var srcElement = e.srcElement;

  // For NPE checking, we check safely. We need to remove the class name
  // Since we will be styling the new one after.
  if (prevDOM != null) {
    prevDOM.classList.remove(MOUSE_VISITED_CLASSNAME);
  }
  // Add a visited class name to the element. So we can style it.
  srcElement.classList.add(MOUSE_VISITED_CLASSNAME);

  // The current element is now the previous. So we can remove the class
  // during the next iteration.
  prevDOM = srcElement;
}

function setSelectAllVisibility(visible) {
  const selectAll = document.querySelector('[aria-label="Select all items"]');
  if (selectAll) {
    console.log('Removings ' + visible)
    selectAll.style.display = visible ? '' : 'none';
  }
}

// getTargetParents stores the selected element hierarchy
// so it can be compared later to highlight the last existing
// parent.
var getTargetParents = function (element) {
  let p = [];
  let parent = element.parentElement;
  while (parent) {
    p.push(parent);
    parent = parent.parentElement;
  }

  return p
}

var checkAndUpdateIncident = function (client, incID, currentSeverity, owner, status) {
  var incident = incidents[client + incID];
  var eventType = "NONE"
  if (incident) {
    if (incident.owner != "Assign to me") {
      if (incident.owner != owner) {
        // console.log(incID + " Incident has a new Owner")
        eventType = owner + " claimed";
      } else if (incident.severity != currentSeverity) {
        // console.log(incID + " Incident ID seen before but severity changed.");
        eventType = incident.severity + " -->";
      } else if (incident.status != status) {
        eventType = "Updated";
      } else {
        //console.log("This incident " + incID + " has been seen before");
      }
    }
  } else {
    // New Incident ID
    // console.log("New Incident ID." + incID);
    eventType = "New"
  }

  // Update the in-memory object
  incidents[client + incID] = { severity: currentSeverity, status: status, owner: owner, lastSeen: new Date().toISOString() };
  return eventType;
}


// Whenever the user clicks something, create an observer that will
// notify background so the notification can be triggered.
var defaultQueue = function () {
  var e = document.querySelector(".ms-Viewport");
  if (!e) {
    return;
  }

  // After selecting the element, disable
  removeListeners();
  enabled = false;

  // Only 1 observer supported to start.
  if (observer) {
    observer.disconnect();
    DOMObserver.disconnect();
    targetElem.classList.remove(ELEMENT_CHANGED_CLASSNAME);
  }

  targetElem = e;
  observer = new MutationObserver(function () {
    console.log("&&&****************");

    // Get all rows in the queue
    var rows = document.querySelectorAll(".ms-List-cell");
    console.log("Num Rows: " + rows.length);

    var sendMessage = true;

    rows.forEach((rowCell) => {
      const cellMap = buildCellMap(rowCell);

      // Required fields for this row to be considered valid
      const severityEl = getCell(cellMap, "severity"); // key is usually "severity"
      const titleEl = getCell(cellMap, "incidentName", "incident name", "Incident name");

      if (!severityEl || !titleEl) {
        console.log("Nothing in Queue");
        return;
      }

      var severity = severityEl.textContent.trim();
      var title = titleEl.textContent.trim();

      // Workspace (optional)
      var workspace = getText(cellMap, "workspace");
      if (!workspace) {
        workspace = "TEST";
      }

      // These keys are commonly camelCase in data-automation-key
      // Add alternates if your portal uses slightly different names
      var incID = getText(cellMap, "incidentId", "Incident Id", "IncidentId");
      var numAlerts = getText(cellMap, "activeAlerts", "Active alerts", "ActiveAlerts");
      var status = getText(cellMap, "status");
      var owner = getText(cellMap, "assignedTo", "Assigned to", "AssignedTo");
      var tags = getText(cellMap, "tags");

      // Find the row DOM node you remove (keeping your original behavior)
      const ownerCell = getCell(cellMap, "assignedTo", "Assigned to", "AssignedTo") || titleEl;
      var row = ownerCell?.parentNode?.parentNode; // same pattern you used before

      // Splitting the string on the hyphen
      var workspaceSplit = workspace.split("-");
      var client = workspace;

      if (workspaceSplit.length > 1) {
        client = workspaceSplit[1].toUpperCase();
      } else {
        console.log("Split array does not have two elements.");
      }

      console.log(
        "Client: " + client +
        " ID: " + incID +
        " Sev: " + severity +
        " Own: " + owner +
        " Status:" + status
      );

      var eventType = checkAndUpdateIncident(client, incID, severity, owner, status);

      var incMatchesRegex = checkWordAgainstPatterns(title, config.filterTitleRegexPatterns);
      incMatchesRegex = incMatchesRegex ? incMatchesRegex : checkWordAgainstPatterns(owner, config.filterOwnerRegexPatterns);
      incMatchesRegex = incMatchesRegex ? incMatchesRegex : checkTagsAgainstPatterns(tags, config.filterTagsRegexPatterns);

      if (incMatchesRegex && doRemoveFromQueue && row && row.parentNode) {
        console.log(row.parentNode);
        console.log("Hiding " + client + " " + incID);
        console.log(row);
        row.parentNode.removeChild(row);
      }

      if (!initializing) {
        var message = {
          type: "notification",
          element: targetElem,
          info: {
            element: row,
            severity: severity,
            title: title,
            client: client,
            workspace: workspace,
            incID: incID,
            status: status,
            owner: owner,
            eventType: eventType,
            numAlerts: numAlerts
          }
        };

        if (eventType != "NONE" && !incMatchesRegex && config.desktopNotifications && sendMessage) {
          if (config.onlyAlertOnLatest) {
            sendMessage = false;
          }
          if (message) {
            chrome.runtime.sendMessage(message);
          }
          console.log("Sending");
        } else {
          console.log("Not sending");
        }
      }
    });
    // console.log(incidents)
    // Disconnect the observer temporarily so we can set the class name
    // to avoid triggering and endless loop.
    observer.disconnect();
    targetElem.classList.add(ELEMENT_CHANGED_CLASSNAME);
    observer.observe(targetElem, { childList: true, subtree: true, characterData: true, attributes: true });
    if (initializing) {
      console.log("Finished Initializing")
      initializing = false
    }
    detailsElem = document.querySelector(".ext-details-header-content");
    console.log(detailsElem);
    if (detailsElem) {
      // Extract Incident Id
      const incNumberMatch = document.querySelector('.msportalfx-font-semibold.ext-details-header-subtitle')?.textContent.trim().match(/Incident Id (\d+)/);
      const incNumber = incNumberMatch ? incNumberMatch[1] : '';

      // Extract incident title
      const incTitle = document.querySelector('.ext-details-header-title')?.textContent.trim() || '';

      const ownerElem = document.querySelectorAll('.msportalfx-font-semibold.msportalfx-text-ellipsis.ext-details-header-item-value')[0];
      const statusElem = document.querySelectorAll('.msportalfx-font-semibold.msportalfx-text-ellipsis.ext-details-header-item-value')[1];
      const severityElem = document.querySelectorAll('.msportalfx-font-semibold.msportalfx-text-ellipsis.ext-details-header-item-value')[2];

      const owner = ownerElem ? ownerElem.textContent.trim() : '';
      const status = statusElem ? statusElem.textContent.trim() : '';
      const severity = severityElem ? severityElem.textContent.trim() : '';

      let workspace = '';
      let description = '';

      const propertyContainers = document.querySelectorAll('.ext-propertyControl-title-container');
      propertyContainers.forEach(container => {
        const title = container.textContent.trim();
        const nextElement = container.nextElementSibling;

        if (title.includes('Workspace') && nextElement) {
          const workspaceMatch = nextElement.querySelector('article')?.textContent.trim().match(/xdrworkspace-(\w+)/);
          workspace = workspaceMatch ? workspaceMatch[1] : '';
        } else if (title.includes('Description') && nextElement) {
          description = nextElement.querySelector('article')?.textContent.trim() || '';
        }
      });

      const relevantText = { incTitle, incNumber, owner, status, severity, workspace, description };

      // Check if detailsElem exists, incTitle and incNumber are not null or blank, and relevantText has changed
      if (detailsElem && incTitle && incNumber &&
        (previousData.incTitle !== incTitle || previousData.incNumber !== incNumber || previousData.workspace !== workspace)) {
        console.log("Update")
        // Save the relevant text to Chrome storage
        chrome.storage.local.set({ relevantText: relevantText }, function () {
          console.log("Relevant text updated:", relevantText);
          previousData = relevantText; // Update previousData to the new values
          var message = {
            type: 'set-lastAlertData',
            element: detailsElem,
            info: relevantText
          }
          chrome.runtime.sendMessage(message);
        });
      } else {
        // console.log("Do not update")
      }
    }

  });

  observer.observe(targetElem, { childList: true, subtree: true, characterData: true, attributes: true });


  DOMObserver = new MutationObserver(function (mutations) {
    for (const m of mutations) {
      // A removal happened in the DOM, let's
      // check if our element was removed.
      if (m.removedNodes.length > 0) {

        if (!document.body.contains(targetElem)) {

          chrome.runtime.sendMessage({ type: 'notification', element: targetElem });

          // Disconnect the DOM observer otherwise we'll get notified
          // for each change on the DOM.
          DOMObserver.disconnect()


          // highlight it.
          p = getElementByXpath("//div[@class='ext-gridControl']")
          p.classList.add(ELEMENT_CHANGED_CLASSNAME);
        }
      }
    }
  });
  DOMObserver.observe(document.body, { childList: true, subtree: true });
}


var addListeners = function () {
  document.addEventListener('mousemove', highlightFunc, false);

}

var removeListeners = function () {
  document.removeEventListener('mousemove', highlightFunc, false);
  if (prevDOM != null) {
    prevDOM.classList.remove(MOUSE_VISITED_CLASSNAME);
  }
}

// Every time we get a new message toggle the plugin
chrome.runtime.onMessage.addListener(function (request) {
  selectMode = false;
  if (request.type == 'toggle' || request.type == 'toggle-queue-filtering') {
    // Remove any previous observers listeners if there are any;
    if (observer) {
      observer.disconnect();
      DOMObserver.disconnect();
      targetElem.classList.remove(ELEMENT_CHANGED_CLASSNAME);
      chrome.runtime.sendMessage({
        type: 'set-queue-state',
        active: false
      })

      // Show "Select all items" again when queue filtering is turned off
      setSelectAllVisibility(true);

    }
    if (enabled) {
      removeListeners();
    } else {
      console.log(selectMode);
      if (!selectMode) {
        var e = document.querySelector(".ms-Viewport");
        if (!e) {
          return;
        }

        // After selecting the element, disable
        enabled = false;

        targetElem = e;
        console.log("&&&****************");

        // Get all rows in the queue
        var rows = document.querySelectorAll(".ms-List-cell");
        console.log("Num Rows: " + rows.length);

        var sendMessage = true;

        rows.forEach((rowCell) => {
          const cellMap = buildCellMap(rowCell);

          // Required fields for this row to be considered valid
          const severityEl = getCell(cellMap, "severity"); // key is usually "severity"
          const titleEl = getCell(cellMap, "incidentName", "incident name", "Incident name");

          if (!severityEl || !titleEl) {
            console.log("Nothing in Queue");
            return;
          }

          var severity = severityEl.textContent.trim();
          var title = titleEl.textContent.trim();

          // Workspace (optional)
          var workspace = getText(cellMap, "workspace");
          if (!workspace) {
            workspace = "TEST";
          }

          // These keys are commonly camelCase in data-automation-key
          // Add alternates if your portal uses slightly different names
          var incID = getText(cellMap, "incidentId", "Incident Id", "IncidentId");
          var numAlerts = getText(cellMap, "activeAlerts", "Active alerts", "ActiveAlerts");
          var status = getText(cellMap, "status");
          var owner = getText(cellMap, "assignedTo", "Assigned to", "AssignedTo");
          var tags = getText(cellMap, "tags");

          // Find the row DOM node you remove (keeping your original behavior)
          const ownerCell = getCell(cellMap, "assignedTo", "Assigned to", "AssignedTo") || titleEl;
          var row = ownerCell?.parentNode?.parentNode; // same pattern you used before

          // Splitting the string on the hyphen
          var workspaceSplit = workspace.split("-");
          var client = workspace;

          if (workspaceSplit.length > 1) {
            client = workspaceSplit[1].toUpperCase();
          } else {
            console.log("Split array does not have two elements.");
          }

          console.log(
            "Client: " + client +
            " ID: " + incID +
            " Sev: " + severity +
            " Own: " + owner +
            " Status:" + status
          );

          var eventType = checkAndUpdateIncident(client, incID, severity, owner, status);

          var incMatchesRegex = checkWordAgainstPatterns(title, config.filterTitleRegexPatterns);
          incMatchesRegex = incMatchesRegex ? incMatchesRegex : checkWordAgainstPatterns(owner, config.filterOwnerRegexPatterns);
          incMatchesRegex = incMatchesRegex ? incMatchesRegex : checkTagsAgainstPatterns(tags, config.filterTagsRegexPatterns);

          if (incMatchesRegex && doRemoveFromQueue && row && row.parentNode) {
            console.log(row.parentNode);
            console.log("Hiding " + client + " " + incID);
            console.log(row);
            row.parentNode.removeChild(row);
          }

          if (!initializing) {
            var message = {
              type: "notification",
              element: targetElem,
              info: {
                element: row,
                severity: severity,
                title: title,
                client: client,
                workspace: workspace,
                incID: incID,
                status: status,
                owner: owner,
                eventType: eventType,
                numAlerts: numAlerts
              }
            };

            if (eventType != "NONE" && !incMatchesRegex && config.desktopNotifications && sendMessage) {
              if (config.onlyAlertOnLatest) {
                sendMessage = false;
              }
              if (message) {
                chrome.runtime.sendMessage(message);
              }
              console.log("Sending");
            } else {
              console.log("Not sending");
            }
          }
        });


        // Hide "Select all items" when queue filtering is enabled
        setSelectAllVisibility(false);

        console.log(incidents)
        // Disconnect the observer temporarily so we can set the class name
        // to avoid triggering and endless loop.
        targetElem.classList.add(ELEMENT_CHANGED_CLASSNAME);
        chrome.runtime.sendMessage({
          type: 'set-queue-state',
          active: true
        })
        if (initializing) {
          console.log("Finished Initializing")
          initializing = false
        }
        defaultQueue();
      } else {
        addListeners();
      }
    }
    enabled = !enabled;
  }
});

