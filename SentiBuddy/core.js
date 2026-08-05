// ============================================================================
// SentiBuddy content script
// ----------------------------------------------------------------------------
// Runs on both Microsoft Sentinel (portal.azure.com) and Microsoft Defender
// XDR (security.microsoft.com / mto.security.microsoft.com). The queue engine
// (row scanning, filtering, notifications, disappearance detection) is shared;
// each platform contributes a small adapter that knows how to find the queue
// root, iterate rows, extract cell values, and remove a row.
// ============================================================================

// ---- Constants -------------------------------------------------------------

const MOUSE_VISITED_CLASSNAME = 'crx_mouse_visited';
const ELEMENT_CHANGED_CLASSNAME = 'elm_changed';

// ---- Platform detection ----------------------------------------------------

function detectPlatform() {
  const host = location.hostname;
  if (host === 'portal.azure.com') return 'sentinel';
  if (host === 'security.microsoft.com' || host === 'mto.security.microsoft.com') return 'defender';
  return null; // OSINT hosts (abuseipdb, virustotal, scamalytics) — queue engine no-ops
}
const PLATFORM = detectPlatform();

// ---- Shared state ----------------------------------------------------------

let enabled = false;
let observer = null;
let DOMObserver = null;
let targetElem = null;
let detailsElem = null;

// Previous incident-clicked data (used to skip persisting unchanged details blade).
let previousData = {};

// In-memory incident tracker: keyed by (client + incID).
let incidents = {};

// Element under the mouse for the highlight overlay.
let prevDOM = null;

// Deletion tracker placeholder (kept from original code; not currently used).
const deletedElementsComponent = document.createElement('div');
deletedElementsComponent.classList.add('deleted-nav');

// Runtime config populated by loadConfig().
let config = {};
let doRemoveFromQueue = true;

// Preserves original behavior — this is intentionally read before loadConfig's
// async callback resolves, so it starts as `undefined` (falsy).
let initializing = config.desktopNotifications;

// ---- Config loading --------------------------------------------------------

function loadConfig() {
  chrome.storage.local.get({
    doRemoveFromFilteredFromQueue: true,
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
    console.log('Config loaded:', config);
  });
}
loadConfig();

// ---- Shared utilities ------------------------------------------------------

function checkWordAgainstPatterns(text, patterns) {
  for (const pattern of patterns) {
    if (new RegExp(pattern).test(text)) return true;
  }
  return false;
}

function checkTagsAgainstPatterns(tags, patterns) {
  for (const pattern of patterns) {
    const regex = new RegExp(pattern);
    const parts = tags.split(',');
    if (parts.length > 1) {
      for (const tag of parts) {
        if (regex.test(tag)) return true;
      }
    } else if (regex.test(tags)) {
      return true;
    }
  }
  return false;
}

function getElementByXpath(path) {
  return document.evaluate(path, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
}

function highlightFunc(e) {
  const src = e.srcElement;
  if (prevDOM != null) prevDOM.classList.remove(MOUSE_VISITED_CLASSNAME);
  src.classList.add(MOUSE_VISITED_CLASSNAME);
  prevDOM = src;
}

function addListeners() {
  document.addEventListener('mousemove', highlightFunc, false);
}

function removeListeners() {
  document.removeEventListener('mousemove', highlightFunc, false);
  if (prevDOM != null) prevDOM.classList.remove(MOUSE_VISITED_CLASSNAME);
}

function setSelectAllVisibility(visible) {
  const selectAll = document.querySelector('[aria-label="Select all items"]');
  if (selectAll) selectAll.style.display = visible ? '' : 'none';
}

function checkAndUpdateIncident(client, incID, currentSeverity, owner, status) {
  const incident = incidents[client + incID];
  let eventType = 'NONE';
  if (incident) {
    if (incident.owner != 'Assign to me') {
      if (incident.owner != owner) {
        eventType = owner + ' claimed';
      } else if (incident.severity != currentSeverity) {
        eventType = incident.severity + ' -->';
      } else if (incident.status != status) {
        eventType = 'Updated';
      }
    }
  } else {
    eventType = 'New';
  }
  incidents[client + incID] = {
    severity: currentSeverity,
    status,
    owner,
    lastSeen: new Date().toISOString()
  };
  return eventType;
}

// ---- Defender cell-map helpers --------------------------------------------
// Fluent DetailsList exposes cells keyed by data-automation-key. Normalize the
// key so we can match against several column-name variants.

function canonical(str) {
  return String(str ?? '')
    .replace(/[\uE000-\uF8FF]/g, '')     // strip icon glyphs
    .replace(/([a-z])([A-Z])/g, '$1 $2') // split camelCase
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function buildCellMap(row) {
  const map = new Map();
  const cells = row.querySelectorAll('[data-automationid^="DetailsRowCell"]');
  for (const cell of cells) {
    const key = cell.getAttribute('data-automation-key') || cell.dataset?.automationKey;
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
  return el ? el.textContent.trim() : '';
}

// ---- Platform adapters -----------------------------------------------------
//
// Adapter interface:
//   queueRootSelector : string      — for identity/debug
//   getQueueRoot()    : Element|null
//   getRows()         : NodeList
//   beginPass()       : any         — per-mutation context (e.g. header index)
//   parseRow(rowEl, ctx) : RowInfo|null
//   removeRow(actionRow) : void
//   readDetailsBlade() : { element, data } | null
//   getDisappearanceFallback() : Element|null
//
// RowInfo = { severity, title, workspace, incID, numAlerts, status, owner,
//             tags, actionRow }
// `actionRow` is the DOM element to feed to `removeRow` — the platform decides
// what "the row" means for detachment purposes.

const sentinelAdapter = {
  name: 'sentinel',
  queueRootSelector: '.ext-gridControl-container',

  getQueueRoot() {
    return document.querySelector('.ext-gridControl-container');
  },

  getRows() {
    return document.querySelectorAll('.fxc-gc-row-content.fxc-gc-row-content_0');
  },

  beginPass() {
    // Build a column-name → index map from the current header row.
    const headers = document.querySelectorAll('.fxc-gc-columnheader-content.fxc-gc-text');
    const indexes = {};
    headers.forEach((header, index) => {
      indexes[header.textContent.trim()] = index;
    });
    return { indexes };
  },

  parseRow(row, ctx) {
    const { indexes } = ctx;
    const elements = row.querySelectorAll('[id^="fxc-gc-cell-content"]');

    // Preserve original guard: a row is considered valid only when both
    // Severity and Title cells are present.
    if (!elements[indexes['Severity']] || !elements[indexes['Title']]) return null;

    const severity = elements[indexes['Severity']].textContent.trim();
    const title = elements[indexes['Title']].textContent.trim();

    let workspace = '';
    if (elements[indexes['Workspace']]) {
      workspace = elements[indexes['Workspace']].textContent.trim();
    } else {
      // Fallback: parse the blade subtitle. (Same behavior as before — will
      // throw if the subtitle element is missing, matching the original.)
      workspace = document
        .querySelector('.fxs-blade-title-subtitleText.msportalfx-tooltip-overflow.fxs-portal-subtext')
        .textContent.trim();
      workspace = workspace.match(/'([^']+)'/)[1];
    }

    const incID = elements[indexes['Incident number']].textContent.trim();
    const numAlerts = elements[indexes['Alerts']].textContent.trim();
    const status = elements[indexes['Status']].textContent.trim();
    const owner = elements[indexes['Owner']].textContent.trim();
    const tags = elements[indexes['Tags']].textContent.trim();
    const actionRow = elements[indexes['Owner']].parentNode.parentNode;

    return { severity, title, workspace, incID, numAlerts, status, owner, tags, actionRow };
  },

  removeRow(actionRow) {
    if (actionRow?.parentNode) actionRow.parentNode.removeChild(actionRow);
  },

  readDetailsBlade() {
    const el = document.querySelector('.ext-details-header-content');
    if (!el) return null;

    const incNumberMatch = document
      .querySelector('.msportalfx-font-semibold.ext-details-header-subtitle')
      ?.textContent.trim().match(/Incident number (\d+)/);
    const incNumber = incNumberMatch ? incNumberMatch[1] : '';
    const incTitle = document.querySelector('.ext-details-header-title')?.textContent.trim() || '';

    const items = document.querySelectorAll(
      '.msportalfx-font-semibold.msportalfx-text-ellipsis.ext-details-header-item-value'
    );
    const owner = items[0]?.textContent.trim() || '';
    const status = items[1]?.textContent.trim() || '';
    const severity = items[2]?.textContent.trim() || '';

    let workspace = '';
    let description = '';
    document.querySelectorAll('.ext-propertyControl-title-container').forEach((container) => {
      const label = container.textContent.trim();
      const next = container.nextElementSibling;
      if (!next) return;
      if (label.includes('Workspace')) {
        const m = next.querySelector('article')?.textContent.trim().match(/xdrworkspace-(\w+)/);
        workspace = m ? m[1] : '';
      } else if (label.includes('Description')) {
        description = next.querySelector('article')?.textContent.trim() || '';
      }
    });

    if (!incTitle || !incNumber) return null;
    return {
      element: el,
      data: { incTitle, incNumber, owner, status, severity, workspace, description }
    };
  },

  getDisappearanceFallback() {
    return getElementByXpath("//div[@class='ext-gridControl']");
  }
};

const defenderAdapter = {
  name: 'defender',
  queueRootSelector: '.ms-Viewport',

  getQueueRoot() {
    return document.querySelector('.ms-Viewport');
  },

  getRows() {
    return document.querySelectorAll('.ms-List-cell');
  },

  beginPass() {
    return null; // per-row cell map is built inside parseRow
  },

  parseRow(rowCell) {
    const cellMap = buildCellMap(rowCell);

    const severityEl = getCell(cellMap, 'severity');
    const titleEl = getCell(cellMap, 'name', 'incidentName', 'incident name', 'Incident name');
    if (!severityEl || !titleEl) return null;

    const severity = severityEl.textContent.trim();
    const title = titleEl.textContent.trim();

    // Defender rows don't currently expose a workspace cell; leave blank so
    // the shared client-derivation falls back to the raw workspace value.
    const workspace = getText(cellMap, 'workspace');

    const incID = getText(cellMap, 'incidentId', 'Incident Id', 'IncidentId');
    const numAlerts = getText(cellMap, 'activeAlerts', 'Active alerts', 'ActiveAlerts');
    const status = getText(cellMap, 'status');
    const owner = getText(cellMap, 'assignedTo', 'Assigned to', 'AssignedTo');
    const tags = getText(cellMap, 'tags');

    // Prefer the owner cell as the anchor for row removal (falls back to title).
    const anchorCell = getCell(cellMap, 'assignedTo', 'Assigned to', 'AssignedTo') || titleEl;
    const actionRow = anchorCell?.parentNode?.parentNode || null;

    return { severity, title, workspace, incID, numAlerts, status, owner, tags, actionRow };
  },

  removeRow(actionRow) {
    // Defender's grid nests each row two levels deeper than Sentinel's, so
    // detach at that ancestor instead.
    const target = actionRow?.parentNode?.parentNode;
    if (target?.parentNode) target.parentNode.removeChild(target);
  },

  readDetailsBlade() {
    // TODO: Defender details-pane selectors aren't wired yet — the previous
    // WIP file was calling Sentinel selectors here that never resolved.
    return null;
  },

  getDisappearanceFallback() {
    return null;
  }
};

const adapter = PLATFORM === 'sentinel'
  ? sentinelAdapter
  : PLATFORM === 'defender'
    ? defenderAdapter
    : null;

// ---- Shared per-pass row processing ---------------------------------------

function deriveClient(workspace) {
  const parts = String(workspace ?? '').split('-');
  return parts.length > 1 ? parts[1].toUpperCase() : workspace;
}

function processQueue() {
  if (!adapter) return;

  const ctx = adapter.beginPass();
  const rows = adapter.getRows();
  let sendMessage = true;

  rows.forEach((rowEl) => {
    let info;
    try {
      info = adapter.parseRow(rowEl, ctx);
    } catch (err) {
      console.log('Row parse failed:', err);
      return;
    }
    if (!info) return;

    const client = deriveClient(info.workspace);
    const eventType = checkAndUpdateIncident(client, info.incID, info.severity, info.owner, info.status);

    const matches = checkWordAgainstPatterns(info.title, config.filterTitleRegexPatterns)
      || checkWordAgainstPatterns(info.owner, config.filterOwnerRegexPatterns)
      || checkTagsAgainstPatterns(info.tags, config.filterTagsRegexPatterns);

    if (matches && doRemoveFromQueue) {
      adapter.removeRow(info.actionRow);
    }

    if (!initializing) {
      const message = {
        type: 'notification',
        element: targetElem,
        info: {
          element: info.actionRow,
          severity: info.severity,
          title: info.title,
          client,
          workspace: info.workspace,
          incID: info.incID,
          status: info.status,
          owner: info.owner,
          eventType,
          numAlerts: info.numAlerts
        }
      };

      if (eventType != 'NONE' && !matches && config.desktopNotifications && sendMessage) {
        if (config.onlyAlertOnLatest) sendMessage = false;
        chrome.runtime.sendMessage(message);
      }
    }
  });
}

function persistDetailsBladeIfChanged() {
  if (!adapter) return;
  const result = adapter.readDetailsBlade();
  if (!result) return;

  detailsElem = result.element;
  const relevantText = result.data;

  const changed =
    previousData.incTitle !== relevantText.incTitle
    || previousData.incNumber !== relevantText.incNumber
    || previousData.workspace !== relevantText.workspace;

  if (!changed) return;

  chrome.storage.local.set({ relevantText }, () => {
    console.log('Relevant text updated:', relevantText);
    previousData = relevantText;
    chrome.runtime.sendMessage({
      type: 'set-lastAlertData',
      element: detailsElem,
      info: relevantText
    });
  });
}

// ---- Observer wiring -------------------------------------------------------

function defaultQueue() {
  if (!adapter) return;

  const root = adapter.getQueueRoot();
  if (!root) return;

  // After selecting the element, disable highlight mode.
  removeListeners();
  enabled = false;

  // Only 1 observer supported to start.
  if (observer) {
    observer.disconnect();
    if (DOMObserver) DOMObserver.disconnect();
    targetElem?.classList.remove(ELEMENT_CHANGED_CLASSNAME);
  }

  targetElem = root;

  observer = new MutationObserver(() => {
    processQueue();

    // Toggle the "changed" class without re-triggering the observer.
    observer.disconnect();
    targetElem.classList.add(ELEMENT_CHANGED_CLASSNAME);
    observer.observe(targetElem, {
      childList: true, subtree: true, characterData: true, attributes: true
    });

    if (initializing) {
      console.log('Finished Initializing');
      initializing = false;
    }

    persistDetailsBladeIfChanged();

    if (enabled) setSelectAllVisibility(false);
  });

  observer.observe(targetElem, {
    childList: true, subtree: true, characterData: true, attributes: true
  });

  DOMObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.removedNodes.length === 0) continue;
      if (document.body.contains(targetElem)) continue;

      chrome.runtime.sendMessage({ type: 'notification', element: targetElem });
      DOMObserver.disconnect();

      const fallback = adapter.getDisappearanceFallback();
      if (fallback) fallback.classList.add(ELEMENT_CHANGED_CLASSNAME);
      return;
    }
  });
  DOMObserver.observe(document.body, { childList: true, subtree: true });
}

// ---- Toggle handler --------------------------------------------------------

function handleToggleFiltering() {
  if (!adapter) return;

  // Tear down any prior state.
  if (observer) {
    observer.disconnect();
    if (DOMObserver) DOMObserver.disconnect();
    targetElem?.classList.remove(ELEMENT_CHANGED_CLASSNAME);
    chrome.runtime.sendMessage({ type: 'set-queue-state', active: false });
    setSelectAllVisibility(true);
  }

  if (enabled) {
    // Turning filtering off.
    removeListeners();
  } else {
    // Turning filtering on.
    const root = adapter.getQueueRoot();
    if (!root) return;

    targetElem = root;

    // Initial synchronous pass so filtering takes effect immediately, before
    // the mutation observer waits for a DOM change.
    processQueue();

    setSelectAllVisibility(false);
    targetElem.classList.add(ELEMENT_CHANGED_CLASSNAME);
    chrome.runtime.sendMessage({ type: 'set-queue-state', active: true });

    if (initializing) {
      console.log('Finished Initializing');
      initializing = false;
    }
    defaultQueue();
  }

  enabled = !enabled;
}

// ---- Portal email extraction (Sentinel only) ------------------------------

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function extractPortalEmail() {
  const usernameEl = document.querySelector('.fxs-avatarmenu-username');
  const usernameText = (usernameEl?.textContent || '').trim();
  if (EMAIL_PATTERN.test(usernameText)) return usernameText;

  const buttonEl = document.getElementById('fxs-avatarmenu-button')
    || document.querySelector('.fxs-avatarmenu-header');
  const attrs = [
    buttonEl?.getAttribute('title'),
    buttonEl?.getAttribute('aria-label')
  ];
  for (const attr of attrs) {
    if (!attr) continue;
    const match = attr.match(/Email:\s*([^\s<>"']+@[^\s<>"']+)/i);
    if (match && EMAIL_PATTERN.test(match[1])) return match[1];
  }
  return '';
}

// ---- Message dispatch ------------------------------------------------------

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  const type = request?.type;

  if (type === 'toggle' || type === 'toggle-queue-filtering') {
    handleToggleFiltering();
    return;
  }

  if (type === 'get-portal-email') {
    if (PLATFORM !== 'sentinel') {
      sendResponse({ ok: false, error: 'unsupported-platform' });
      return true;
    }
    try {
      const email = extractPortalEmail();
      if (email) sendResponse({ ok: true, email });
      else sendResponse({ ok: false, error: 'not-found' });
    } catch (err) {
      sendResponse({ ok: false, error: err?.message || 'unknown' });
    }
    return true;
  }
});
