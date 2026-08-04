
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const ipv6Pattern = /^(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,5}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:)|fe80:(:[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|([0-9A-Fa-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))$/;
// Function to check the hash type
function checkHashType(hash) {
    const md5Pattern = /^[a-f0-9]{32}$/i;
    const sha1Pattern = /^[a-f0-9]{40}$/i;
    const sha256Pattern = /^[a-f0-9]{64}$/i;

    if (md5Pattern.test(hash)) {
        return 'MD5';
    } else if (sha1Pattern.test(hash)) {
        return 'SHA-1';
    } else if (sha256Pattern.test(hash)) {
        return 'SHA-256';
    } else {
        return 'Unknown';
    }
}
let isNotifToggled;
function setLoading() {
    document.getElementById('results').innerHTML  = `<div class="link-block"><span>🔍 Analyzing IP address...</span></div>`
}

let devData;
let data;
let clientTableSchema;
let devTableSchema;
let incidentLookbackEndpoint = '';
let incidentTableSchemaFromConfig = null;
const SAFE_URL_PROTOCOLS = ['https:'];

function sanitizeUrl(url) {
  if (!url) return '#';
  try {
    const parsed = new URL(url, 'https://google.com'); // base in case of relative URLs
    if (!SAFE_URL_PROTOCOLS.includes(parsed.protocol)) {
      return '#'; // or return null and skip the link entirely
    }
    return parsed.href;
  } catch (e) {
    return '#';
  }
}

function createTextCell(value) {
  const td = document.createElement('td');
  td.textContent = value ?? '';
  return td;
}

function createLinkCell(href, text) {
  const td = document.createElement('td');
  const safeHref = sanitizeUrl(href);

  const a = document.createElement('a');
  a.textContent = text ?? 'Link';
  a.href = safeHref;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';

  td.appendChild(a);
  return td;
}

const DEFAULT_TABLE_SCHEMAS = {
  data: {
    columns: [
      { key: 'code', displayName: 'Code' },
      { key: 'client', displayName: 'Client' },
      { key: 'department', displayName: 'Department' },
      { key: 'lead', displayName: 'Client Lead' },
      { key: 'edr', displayName: 'EDR', hyperlink: { urlField: 'edrLink' } },
      { key: 'contact', displayName: 'Contacts', hyperlink: { text: 'Info' } }
    ]
  },
  devData: {
    columns: [
      { key: 'client', displayName: 'Client' },
      { key: 'sentinelName', displayName: 'Sentinel Instance', hyperlink: { urlField: 'sentinelLink' } },
      { key: 'rgName', displayName: 'Resource Group', hyperlink: { urlField: 'rgLink' } },
      { key: 'subscriptionName', displayName: 'Subscription', hyperlink: { urlField: 'subscriptionLink' } },
      { key: 'location', displayName: 'Location' }
    ]
  }
};

function titleCaseLabel(value) {
  if (!value) return '';
  const separated = String(value).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ');
  return separated.charAt(0).toUpperCase() + separated.slice(1);
}

function getArrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function getHyperlinkConfig(column) {
  return column?.hyperlink || column?.hyperLink;
}

function cloneColumns(schema) {
  return getArrayOrEmpty(schema?.columns).map(col => ({
    ...col,
    hyperlink: getHyperlinkConfig(col) ? { ...getHyperlinkConfig(col) } : undefined
  }));
}

function normalizeSchemaColumns(schema) {
  if (!schema) return [];

  if (Array.isArray(schema?.columns)) {
    return schema.columns.map(col => ({
      ...col,
      hyperlink: getHyperlinkConfig(col) ? { ...getHyperlinkConfig(col) } : undefined
    }));
  }

  if (schema?.columns && typeof schema.columns === 'object') {
    return Object.entries(schema.columns).map(([key, value]) => ({
      key,
      displayName: value?.displayName,
      hyperlink: getHyperlinkConfig(value) ? { ...getHyperlinkConfig(value) } : undefined
    }));
  }

  if (typeof schema === 'object') {
    return Object.entries(schema).map(([key, value]) => ({
      key,
      displayName: value?.displayName,
      hyperlink: getHyperlinkConfig(value) ? { ...getHyperlinkConfig(value) } : undefined
    }));
  }

  return [];
}

function inferColumnsFromRows(rows) {
  const firstRow = rows[0] || {};
  const keys = Object.keys(firstRow).filter(key => !key.endsWith('Link'));
  return keys.map(key => {
    const linkKey = `${key}Link`;
    const hasCompanionLink = Object.prototype.hasOwnProperty.call(firstRow, linkKey);
    return {
      key,
      displayName: titleCaseLabel(key),
      hyperlink: hasCompanionLink ? { urlField: linkKey } : undefined
    };
  });
}

function resolveTableSchema(tableName, rows, schemaFromConfig) {
  const configuredColumns = normalizeSchemaColumns(schemaFromConfig);
  if (configuredColumns.length) return configuredColumns;

  const defaultColumns = cloneColumns(DEFAULT_TABLE_SCHEMAS[tableName]);
  if (defaultColumns.length) return defaultColumns;

  return inferColumnsFromRows(rows);
}

function getCellText(row, column) {
  const hyperlink = getHyperlinkConfig(column);

  if (hyperlink?.textField) {
    return row?.[hyperlink.textField] ?? '';
  }

  if (hyperlink?.text !== undefined) {
    return hyperlink.text;
  }

  return row?.[column.key] ?? '';
}

function getCellLink(row, column) {
  const hyperlink = getHyperlinkConfig(column);
  if (!hyperlink) return '';

  if (hyperlink.urlField) {
    return row?.[hyperlink.urlField] ?? '';
  }

  return row?.[column.key] ?? '';
}

function renderTableHeaders(headId, columns) {
  const tableHead = document.getElementById(headId);
  if (!tableHead) return;

  tableHead.innerHTML = '';
  const tr = document.createElement('tr');

  columns.forEach(column => {
    const th = document.createElement('th');
    th.textContent = column.displayName || titleCaseLabel(column.key);
    tr.appendChild(th);
  });

  tableHead.appendChild(tr);
}

function renderRows(bodyId, rows, columns) {
  const tableBody = document.getElementById(bodyId);
  if (!tableBody) return;

  tableBody.innerHTML = '';

  rows.forEach(row => {
    const tr = document.createElement('tr');

    columns.forEach(column => {
      if (getHyperlinkConfig(column)) {
        tr.appendChild(createLinkCell(getCellLink(row, column), getCellText(row, column)));
      } else {
        tr.appendChild(createTextCell(row?.[column.key] ?? ''));
      }
    });

    tableBody.appendChild(tr);
  });
}

// Client Info Table Functions
function renderTable(filteredData) {
  renderRows('tableBody', filteredData, clientTableSchema || []);
}

// Development Table Functions
function renderDevTable(filteredData) {
  renderRows('devTableBody', filteredData, devTableSchema || []);
}

function configureTableSchemas(tableDataConfig) {
  const schemas = tableDataConfig?.schemas || {};
  clientTableSchema = resolveTableSchema('data', data, schemas.data);
  devTableSchema = resolveTableSchema('devData', devData, schemas.devData);

  renderTableHeaders('tableHead', clientTableSchema);
  renderTableHeaders('devTableHead', devTableSchema);
}

function extractIncidentLookbackEndpoint(config) {
  if (!config || typeof config !== 'object') return '';
  const candidates = [
    config.incidentLookbackEndpoint,
    config['incident-lookback-endpoint'],
    config.incidentLookbackUrl,
    config['incident-lookback-url']
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim();
    }
  }
  return '';
}

function extractIncidentTableSchema(config) {
  if (!config || typeof config !== 'object') return null;
  const schemas = config.tableData?.schemas || config.schemas || {};
  return schemas.incidents || schemas.incident || null;
}

function applyMasterConfig(config) {
  incidentLookbackEndpoint = extractIncidentLookbackEndpoint(config);
  incidentTableSchemaFromConfig = extractIncidentTableSchema(config);
}

var configDataURL = '';
function loadConfigURL() {
  chrome.storage.local.get({
    configDataURL: ''
  }, (items) => {
    configDataURL = items.configDataURL
    fetchClientData();
  });
}

async function fetchClientData() {
    const cacheKey = 'cachedConfig';
    const timestampKey = 'cachedConfigTimestamp';
    const now = Date.now();
    const cacheDuration = 30 * 60 * 1000; // 5 minutes in milliseconds
  
    const cachedData = localStorage.getItem(cacheKey);
    const cachedTimestamp = localStorage.getItem(timestampKey);
  
    if (cachedData && cachedTimestamp && (now - parseInt(cachedTimestamp) < cacheDuration)) {
      // Use cached data
      const parsedCached = JSON.parse(cachedData);
      devData = getArrayOrEmpty(parsedCached?.tableData?.devData);
      data = getArrayOrEmpty(parsedCached?.tableData?.data);
      configureTableSchemas(parsedCached?.tableData);
      applyMasterConfig(parsedCached);
    } else {
        try {        
          const response = await fetch(configDataURL); // Replace with actual URL
          const result = await response.json();
          devData = getArrayOrEmpty(result?.tableData?.devData);
          data = getArrayOrEmpty(result?.tableData?.data);
          configureTableSchemas(result?.tableData);
          applyMasterConfig(result);

        // Cache result
        localStorage.setItem(cacheKey, JSON.stringify(result));
        localStorage.setItem(timestampKey, now.toString());
  
      } catch (error) {
        console.error('Failed to fetch client data:', error);
        return;
      }
    }

    if (!clientTableSchema || !devTableSchema) {
      configureTableSchemas();
    }

    renderTable(data);
    renderDevTable(devData);
  }
  
document.getElementById("searchBox").addEventListener("input", function () {
  const query = this.value.toLowerCase();
  const filtered = data.filter(item => String(item?.code ?? '').toLowerCase().includes(query));
  renderTable(filtered);
});


document.getElementById("devSearchBox").addEventListener("input", function () {
  const query = this.value.toLowerCase();
  const filtered = devData.filter(item => String(item?.client ?? '').toLowerCase().includes(query));
  renderDevTable(filtered);
});

document.getElementById("revealBtn").addEventListener("click", function () {
  const content = document.getElementById("spoilerContent");
  content.classList.toggle("revealed");

  this.textContent = content.classList.contains("revealed") ? "Hide" : "Reveal";
});
document.getElementById("revealBtn2").addEventListener("click", function () {
  const content = document.getElementById("spoilerContent2");
  content.classList.toggle("revealed");

  this.textContent = content.classList.contains("revealed") ? "Hide" : "Reveal";
});

document.getElementById("searchBox").addEventListener("keydown", function (event) {
    if (event.key !== "Enter") return;

    const spoiler = document.getElementById("spoilerContent");

    if (event.shiftKey) {
        return;
    }

    spoiler.classList.add("revealed");

    const btn = document.getElementById("revealBtn");
    btn.textContent = "Hide";
});



document.getElementById("devSearchBox").addEventListener("keydown", function (event) {
    if (event.key !== "Enter") return;

    const spoiler = document.getElementById("spoilerContent2");

    if (event.shiftKey) {
        return;
    }

    spoiler.classList.add("revealed");

    const btn = document.getElementById("revealBtn2");
    btn.textContent = "Hide";
});

function showTab(tab) {
  if (tab === "osint") {
    tab = "queue";
  }

  const sections = {
    client: "clientSection",
    queue: "queueSection",
    development: "developmentSection",
    incidents: "incidentsSection"
  };

  const buttons = {
    client: "clientBtn",
    queue: "queueBtn",
    development: "developmentBtn",
    incidents: "incidentsBtn"
  };

  Object.keys(sections).forEach(key => {
    const sectionEl = document.getElementById(sections[key]);
    if (sectionEl) {
      sectionEl.style.display = key === tab ? "block" : "none";
    }
  });

  Object.keys(buttons).forEach(key => {
    const btnEl = document.getElementById(buttons[key]);
    if (btnEl) {
      btnEl.classList.toggle("active", key === tab);
    }
  });

  chrome.storage.local.set({ lastPopupTab: tab });
}


// Navigation Functions
document.getElementById("clientBtn").addEventListener("click", () => {
  showTab("client");
});

document.getElementById("developmentBtn").addEventListener("click", () => {
  showTab("development");
});

document.getElementById("queueBtn").addEventListener("click", () => {
  showTab("queue");
});

document.getElementById("incidentsBtn").addEventListener("click", () => {
  showTab("incidents");
  refreshPortalEmail();
});

// --- Incident lookback tab -------------------------------------------------

const INCIDENT_ARRAY_KEYS = ['incidents', 'rows', 'data', 'items', 'results'];
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PORTAL_URL_PREFIX = 'https://portal.azure.com/';

function setEmailHint(message, tone) {
  const el = document.getElementById('lookbackEmailHint');
  if (!el) return;
  el.textContent = message || '';
  el.classList.remove('is-success', 'is-error');
  if (tone === 'success') el.classList.add('is-success');
  if (tone === 'error') el.classList.add('is-error');
}

function setLookbackEmail(value, tone, hint) {
  const input = document.getElementById('lookbackEmail');
  if (!input) return;
  input.value = value || '';
  input.readOnly = true;
  input.placeholder = value ? '' : 'Detecting from Azure portal...';
  setEmailHint(hint || '', tone);
}

function requestPortalEmailFromTab(tabId) {
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, { type: 'get-portal-email' }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }
        resolve(response || { ok: false, error: 'no-response' });
      });
    } catch (err) {
      resolve({ ok: false, error: err?.message || 'send-failed' });
    }
  });
}

async function refreshPortalEmail() {
  try {
    const [tab] = await new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, resolve);
    });

    if (!tab || !tab.id || !tab.url || !tab.url.startsWith(PORTAL_URL_PREFIX)) {
      setLookbackEmail('', 'error', 'Failed to pull email. Open portal.azure.com and reopen this popup.');
      return;
    }

    const response = await requestPortalEmailFromTab(tab.id);
    if (response?.ok && EMAIL_PATTERN.test(response.email)) {
      setLookbackEmail(response.email, 'success', `Auto-detected from Azure portal: ${response.email}`);
    } else {
      setLookbackEmail('', 'error', 'Failed to pull email. Open portal.azure.com and reopen this popup.');
    }
  } catch (err) {
    console.error('Portal email lookup failed:', err);
    setLookbackEmail('', 'error', 'Failed to pull email. Open portal.azure.com and reopen this popup.');
  }
}

function getBrowserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

function getSupportedTimezones() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const zones = Intl.supportedValuesOf('timeZone');
      if (Array.isArray(zones) && zones.length) return zones;
    }
  } catch { /* fall through */ }
  return [
    'UTC', 'America/Los_Angeles', 'America/Denver', 'America/Chicago',
    'America/New_York', 'America/Toronto', 'America/Sao_Paulo',
    'Europe/London', 'Europe/Berlin', 'Europe/Madrid', 'Europe/Paris',
    'Europe/Amsterdam', 'Europe/Athens', 'Africa/Johannesburg',
    'Asia/Dubai', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Hong_Kong',
    'Asia/Tokyo', 'Australia/Sydney', 'Pacific/Auckland'
  ];
}

function populateTimezoneSelect() {
  const select = document.getElementById('lookbackTimezone');
  if (!select || select.dataset.populated === 'true') return;

  const zones = getSupportedTimezones();
  const browserZone = getBrowserTimezone();
  const fragment = document.createDocumentFragment();

  zones.forEach(zone => {
    const option = document.createElement('option');
    option.value = zone;
    option.textContent = zone;
    fragment.appendChild(option);
  });

  select.appendChild(fragment);
  if (zones.includes(browserZone)) {
    select.value = browserZone;
  }
  select.dataset.populated = 'true';
}

function setIncidentStatus(message, tone) {
  const el = document.getElementById('incidentStatus');
  if (!el) return;
  el.textContent = message || '';
  el.classList.remove('is-success', 'is-error');
  if (tone === 'success') el.classList.add('is-success');
  if (tone === 'error') el.classList.add('is-error');
}

function findIncidentRows(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];

  for (const key of INCIDENT_ARRAY_KEYS) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (Array.isArray(payload?.tableData?.incidents)) return payload.tableData.incidents;
  if (Array.isArray(payload?.tableData?.data)) return payload.tableData.data;
  return [];
}

function findIncidentSchema(payload) {
  if (!payload || typeof payload !== 'object') return null;
  return payload.schema
    || payload.schemas?.incidents
    || payload.tableData?.schemas?.incidents
    || incidentTableSchemaFromConfig
    || null;
}

function renderIncidentResults(payload) {
  const resultsEl = document.getElementById('incidentResults');
  if (!resultsEl) return;

  const rows = findIncidentRows(payload);
  if (!rows.length) {
    resultsEl.style.display = 'none';
    return;
  }

  const columns = resolveTableSchema('incidents', rows, findIncidentSchema(payload));
  renderTableHeaders('incidentTableHead', columns);
  renderRows('incidentTableBody', rows, columns);
  resultsEl.style.display = 'block';
}

function clearIncidentResults() {
  const resultsEl = document.getElementById('incidentResults');
  if (!resultsEl) return;
  resultsEl.style.display = 'none';
  const head = document.getElementById('incidentTableHead');
  const body = document.getElementById('incidentTableBody');
  if (head) head.innerHTML = '';
  if (body) body.innerHTML = '';
}

async function submitIncidentLookback() {
  const hoursInput = document.getElementById('lookbackHours');
  const tzSelect = document.getElementById('lookbackTimezone');
  const emailInput = document.getElementById('lookbackEmail');
  const submitBtn = document.getElementById('submitLookback');
  if (!hoursInput || !tzSelect || !emailInput) return;

  const hours = Number(hoursInput.value);
  const timezone = tzSelect.value;
  const email = emailInput.value.trim();

  if (!Number.isFinite(hours) || hours <= 0) {
    setIncidentStatus('Enter a positive number of hours to look back.', 'error');
    return;
  }
  if (!timezone) {
    setIncidentStatus('Select a timezone.', 'error');
    return;
  }
  if (!EMAIL_PATTERN.test(email)) {
    setIncidentStatus('Failed to pull email. Open portal.azure.com in the active tab and reopen this popup.', 'error');
    return;
  }
  if (!incidentLookbackEndpoint) {
    setIncidentStatus('Incident lookback endpoint is not configured. Add "incidentLookbackEndpoint" to the master config.', 'error');
    return;
  }

  let safeEndpoint;
  try {
    const parsed = new URL(incidentLookbackEndpoint);
    if (parsed.protocol !== 'https:') {
      setIncidentStatus('Incident lookback endpoint must be an https URL.', 'error');
      return;
    }
    safeEndpoint = parsed.href;
  } catch {
    setIncidentStatus('Incident lookback endpoint is not a valid URL.', 'error');
    return;
  }

  clearIncidentResults();
  setIncidentStatus('Sending request...');
  if (submitBtn && typeof submitBtn.setAttribute === 'function') {
    submitBtn.setAttribute('disabled', 'true');
  }

  try {
    const response = await fetch(safeEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        lookbackHours: hours,
        timezone,
        email
      })
    });

    if (!response.ok) {
      throw new Error(`Request failed with status ${response.status}`);
    }

    let payload = null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
    }

    setIncidentStatus('Email will be sent shortly.', 'success');
    if (payload) renderIncidentResults(payload);
  } catch (error) {
    console.error('Incident lookback request failed:', error);
    setIncidentStatus(`Request failed: ${error?.message || 'unknown error'}`, 'error');
  } finally {
    if (submitBtn && typeof submitBtn.removeAttribute === 'function') {
      submitBtn.removeAttribute('disabled');
    }
  }
}

function initIncidentLookbackTab() {
  populateTimezoneSelect();

  const submitBtn = document.getElementById('submitLookback');
  if (submitBtn && !submitBtn.dataset.bound) {
    submitBtn.dataset.bound = 'true';
    submitBtn.addEventListener('click', () => {
      submitIncidentLookback();
    });
  }

  const hoursEl = document.getElementById('lookbackHours');
  if (hoursEl && hoursEl.dataset.enterBound !== 'true') {
    hoursEl.dataset.enterBound = 'true';
    hoursEl.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        submitIncidentLookback();
      }
    });
  }

  refreshPortalEmail();
}

// Close modal when clicking outside of it
window.addEventListener("click", (event) => {
  const modal = document.getElementById("settingsModal");
  if (event.target === modal) {
    modal.style.display = "none";
  }
});
loadConfigURL()

// OSINT Analysis via Enter key in input box
document.getElementById("osintInput").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;

  const inputEl = event.target;
  const value = inputEl.value.trim();
  const osintResults = document.getElementById("results");
  const copyAllBtn = document.getElementById("copyAllBtn");

  osintResults.innerHTML = "";
  copyAllBtn.style.display = "none";

  if (!value) return;

  // Detect IP vs hash
  const isIPv4 = ipv4Pattern.test(value);
  const isIPv6 = ipv6Pattern.test(value);
  const hashType = checkHashType(value); // MD5 / SHA-1 / SHA-256 / Unknown

  if (!(isIPv4 || isIPv6 || hashType !== "Unknown")) {
    osintResults.innerHTML = `
      <div class="link-block">
        <span>⚠️ Please enter a valid IP address or hash, then press Enter.</span>
      </div>
    `;
    return;
  }

  // Show loading state
  osintResults.innerHTML = `
    <div class="link-block">
      <span>🔍 Analyzing ${isIPv4 || isIPv6 ? "IP address" : `${hashType} hash`}...</span>
    </div>
  `;

  if (isIPv4 || isIPv6) {
    // Use your existing IP flow
    chrome.runtime.sendMessage(
      { ip: value, type: "search-ip" },
      (response) => {
        if (chrome.runtime.lastError) {
          osintResults.innerHTML = `
            <div class="link-block">
              <span>❌ Error: ${chrome.runtime.lastError.message}</span>
            </div>
          `;
        } else {
          displayResults(response); // existing function
        }
      }
    );
  } else {
    // Hash flow
    chrome.runtime.sendMessage(
      { hash: value, type: "search-hash" },
      (response) => {
        if (chrome.runtime.lastError) {
          osintResults.innerHTML = `
            <div class="link-block">
              <span>❌ Error: ${chrome.runtime.lastError.message}</span>
            </div>
          `;
        } else {
          displayResults(response); // existing function
        }
      }
    );
  }
});


// Helper function to make API requests through Chrome extension
async function makeApiRequest(url, headers) {
  return new Promise((resolve, reject) => {
    fetch(url, {
      method: 'GET',
      headers: headers,
      mode: 'cors'
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => resolve(data))
    .catch(error => reject(error));
  });
}

function extractAnalysisData(ip, vtData, abuseData) {
  // Extract VirusTotal data
  const vtAttributes = vtData?.data?.attributes || {};
  const vtStats = vtAttributes.last_analysis_stats || {};
  const vtScore = `${vtStats.malicious || 0}/${Object.values(vtStats).reduce((a, b) => a + b, 0)}`;
  
  // Enhanced VPN detection from multiple sources
  let isVPN = false;
  
  // Check categories
  const vtCategories = vtAttributes.categories || {};
  if (Object.values(vtCategories).some(category => 
    category.toLowerCase().includes('vpn') || 
    category.toLowerCase().includes('proxy') ||
    category.toLowerCase().includes('anonymizer')
  )) {
    isVPN = true;
  }
  
  // Check last_analysis_results for VPN indicators
  const analysisResults = vtAttributes.last_analysis_results || {};
  for (const [engine, result] of Object.entries(analysisResults)) {
    if (result.result && typeof result.result === 'string') {
      const resultText = result.result.toLowerCase();
      if (resultText.includes('vpn') || resultText.includes('proxy') || 
          resultText.includes('anonymizer') || resultText.includes('tor')) {
        isVPN = true;
        break;
      }
    }
  }
  
  // Check ASN and network info for hosting/VPN providers
  const asn = vtAttributes.asn || 0;
  const asOwner = vtAttributes.as_owner || '';
  const network = vtAttributes.network || '';
  
  const vpnProviders = ['nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost', 
                       'privateinternetaccess', 'tunnelbear', 'windscribe', 'hotspot shield',
                       'purevpn', 'ipvanish', 'vyprvpn', 'torguard', 'perfect privacy',
                       'mullvad', 'ovpn', 'azire', 'ivpn', 'hide.me', 'vpn.ac'];
  
  const hostingProviders = ['digital ocean', 'amazon', 'google cloud', 'microsoft azure',
                           'ovh', 'hetzner', 'linode', 'vultr', 'scaleway', 'contabo'];
  
  if (asOwner.toLowerCase().includes('vpn') || 
      asOwner.toLowerCase().includes('proxy') ||
      vpnProviders.some(provider => asOwner.toLowerCase().includes(provider)) ||
      hostingProviders.some(provider => asOwner.toLowerCase().includes(provider))) {
    isVPN = true;
  }

  // Extract AbuseIPDB data
  const abuseResult = abuseData?.data || {};
  const abuseScore = `${abuseResult.abuseConfidencePercentage || 0}%`;
  const isp = abuseResult.isp || "Unknown";
  const countryCode = abuseResult.countryName || "Unknown";

  return {
    ip,
    isp,
    location: countryCode,
    vtScore,
    abuseScore,
    isVPN,
    vtData, // Include raw VT data for debugging
    abuseData, // Include raw AbuseIPDB data for debugging
    debugInfo: {
      categories: vtCategories,
      asn: asn,
      asOwner: asOwner,
      network: network
    }
  };
}
let analysisText = '';

// Global function to toggle AbuseIPDB debug info
window.toggleAbuseDebug = function(button) {
  const debugDiv = button.closest('.link-block').querySelector('.abuse-debug-content');
  if (debugDiv.style.display === 'none') {
    debugDiv.style.display = 'block';
    button.textContent = 'Hide';
  } else {
    debugDiv.style.display = 'none';
    button.textContent = 'Show';
  }
};

// Global function to copy analysis results
window.copyAnalysisResults = function(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.textContent;
    button.textContent = "Copied!";
    setTimeout(() => button.textContent = originalText, 1000);
  }).catch(err => {
    console.error('Failed to copy text: ', err);
  });
};



function displayReferenceLinks(ip) {
  const osintResults = document.getElementById("results");
  
  const urls = [
    `https://www.virustotal.com/gui/ip-address/${ip}`,
    `https://www.abuseipdb.com/check/${ip}`,
    `https://spur.us/context/${ip}`,
    `https://scamalytics.com/ip/${ip}`
  ];

  const labels = ["VirusTotal", "AbuseIPDB", "Spur.us", "Scamalytics"];

  urls.forEach((url, index) => {
    const div = document.createElement("div");
    div.className = "link-block";
    div.innerHTML = `
      <a href="${url}" target="_blank" style="text-decoration: none; color: inherit;">
        🔗 ${labels[index]}
      </a>
      <button class="copy-btn" data-url="${url}">Copy</button>
    `;
    osintResults.appendChild(div);
  });

  // Add copy functionality to individual buttons
  document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(btn.dataset.url).then(() => {
        const originalText = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => btn.textContent = originalText, 1000);
      });
    });
  });

  // Setup Copy All functionality
  const copyAllBtn = document.getElementById("copyAllBtn");
  copyAllBtn.onclick = () => {
    const fullText = urls.join('\n');
    navigator.clipboard.writeText(fullText).then(() => {
      const originalText = copyAllBtn.textContent;
      copyAllBtn.textContent = "Copied!";
      setTimeout(() => copyAllBtn.textContent = originalText, 1000);
    });
  };
}

// button selectors
const queueButton = document.querySelector('senti-button#startQueueFiltering');
const defangUrlButton = document.querySelector('senti-button#defangURL');
const ipCheckButton = document.querySelector('senti-button#checkIp');
const hashCheckButton = document.querySelector('senti-button#checkHash');
const notificationButton = document.querySelector('senti-button#notificationToggle');
const settingsButton = document.getElementById("settingsBtn");
const themeToggleButton = document.getElementById('themeToggleBtn');
const startQueueButton = document.getElementById('startQueueFiltering');
const timerToggleButton = document.getElementById('toggleTimerCount');
const openDashboardButton = document.getElementById('openDashboard');

let dashboardConfig = {
  dashboardTitle: 'Open Dashboard',
  dashboardLink: ''
};

function sanitizeHttpsUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.href : '';
  } catch {
    return '';
  }
}

function updateDashboardButtonUI() {
  if (!openDashboardButton) return;

  const buttonTitle = (dashboardConfig.dashboardTitle || 'Open Dashboard').trim();
  const destination = sanitizeHttpsUrl(dashboardConfig.dashboardLink);
  const tooltipText = destination ? `Open: ${buttonTitle}` : `${buttonTitle} (URL not configured)`;

  openDashboardButton.setText(buttonTitle);
  openDashboardButton.setAttribute('tooltip', tooltipText);
}

function applyPopupTheme(theme) {
  const activeTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.setAttribute('data-theme', activeTheme);

  if (themeToggleButton) {
    themeToggleButton.textContent = activeTheme === 'dark' ? '☀️' : '🌙';
    themeToggleButton.title = activeTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  }
}

document.addEventListener('DOMContentLoaded', () => {

   chrome.storage.local.get({ lastPopupTab: 'client' }, (result) => {
        showTab(result.lastPopupTab);
    });

  initIncidentLookbackTab();
    
    // Check the current state of the queue filtering
    chrome.runtime.sendMessage({ type: 'get-queue-state' }, (response) => {
        if (response.active) {
            startQueueButton.setText('Queue Filtering: On');
            startQueueButton.setColor('#107C10');
        } else {
            startQueueButton.setText('Queue Filtering: Off');
            startQueueButton.setColor('#D83B01');
        } 
    });

    chrome.storage.local.get(["desktopNotifications"]).then((result) => {
        if (result.desktopNotifications) {
            notificationButton.setText('Notifications: On');
            notificationButton.setColor('#107C10');
        } else {
            notificationButton.setText('Notifications: Off');
            notificationButton.setColor('#D83B01');
        }
    });

    chrome.storage.local.get({ timerCountVisible: true }, (result) => {
        const visible = result.timerCountVisible;
        updateTimerCountButton(visible);
        updateTimerCountInAllTabs(visible);
    });

  chrome.storage.local.get({ popupTheme: 'light' }, (result) => {
    applyPopupTheme(result.popupTheme);
    });

  chrome.storage.local.get({ dashboardTitle: 'Open Dashboard', dashboardLink: '' }, (result) => {
    dashboardConfig = {
      dashboardTitle: result.dashboardTitle,
      dashboardLink: result.dashboardLink
    };
    updateDashboardButtonUI();
  });

});

if (themeToggleButton) {
  themeToggleButton.addEventListener('click', () => {
    const currentTheme = document.body.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyPopupTheme(nextTheme);
    chrome.storage.local.set({ popupTheme: nextTheme });
  });
}

document.getElementById('openDashboard').addEventListener('click', () => {
  const destination = sanitizeHttpsUrl(dashboardConfig.dashboardLink);
  if (!destination) {
    document.getElementById('results').textContent = 'Dashboard URL is not configured in Options.';
    return;
  }

    chrome.tabs.create({
      url: destination
    });
  });
  

notificationButton.addEventListener('click', () => {
    chrome.storage.local.get(["desktopNotifications"]).then((result) => {
        isNotifToggled = !result.desktopNotifications
        if (isNotifToggled) {
            notificationButton.setText('Notifications: On');
            notificationButton.setColor('#107C10');
            chrome.runtime.sendMessage({ type: 'set-notifications', enabled: true }, response => {
                console.log('Notification enable response:', response);
            });
        } else {
            notificationButton.setText('Notifications: Off');
            notificationButton.setColor('#D83B01');
            chrome.runtime.sendMessage({ type: 'set-notifications', enabled: false }, response => {
                console.log('Notification disable response:', response);
            });
        }
      });
    // Update the configuration in storage
    chrome.storage.local.set({ desktopNotifications: !isNotifToggled }, () => {
    console.log('Notification settings updated');
        });
});

settingsButton.addEventListener('click', async () => {
    try {
        if (chrome.runtime.openOptionsPage) {
            chrome.runtime.openOptionsPage();
        } else {
            window.open(chrome.runtime.getURL('options.html'));
        }
    } catch (error) {
        document.getElementById('results').textContent = 'Failed to open settings';
    }
});

ipCheckButton.addEventListener('click', async () => {
    setLoading();
    try {
        const text = await navigator.clipboard.readText();
        if (ipv4Pattern.test(text.trim()) || ipv6Pattern.test(text.trim())) {
            chrome.runtime.sendMessage({ ip: text.trim(), type: "search-ip" }, function(response) {
                console.log("Response Received")
                displayResults(response);
            });
        } else {
            document.getElementById('results').textContent = 'No valid IP address found in clipboard.';
        }
    } catch (error) {
        document.getElementById('results').textContent = 'Failed to access clipboard.';
    }
});
hashCheckButton.addEventListener('click', async () => {
    setLoading();
    try {
        const text = await navigator.clipboard.readText();
        var hashType = checkHashType(text.trim())
        if (hashType != 'Unknown') {
            chrome.runtime.sendMessage({ hash: text.trim(), type: "search-hash" }, function(response) {
                console.log("Response Received")
                displayResults(response);
            });
        } else {
            document.getElementById('results').textContent = 'No valid Hash address found in clipboard.';
        }
    } catch (error) {
        document.getElementById('results').textContent = 'Failed to access clipboard.';
    }
});
defangUrlButton.addEventListener('click', async () => {
    setLoading();
    try {
        const text = await navigator.clipboard.readText();
        const defangedText = text.replace(/(https?):\/\/(?!.*(virustotal\.com|scamalytics\.com|abuseipdb\.com|spur\.us|urlscan\.io|portal\.azure\.com|exchange\.xforce\.ibmcloud\.com))([\w-]+(\.[\w-]+)+)/gi, (match, p1, p2, p3) => {
            return p1.replace(/^https?/, 'hxxps') + '[:]//' + p3.replace(/\./g, '[.]');
        });
        navigator.clipboard.writeText(defangedText);
        document.getElementById('results').textContent = 'Clipboard defanged!';
    } catch (error) {
        document.getElementById('results').textContent = 'Failed to access clipboard.';
    }
});

startQueueButton.addEventListener('click', () => {
    setLoading();
    chrome.runtime.sendMessage({ type: 'toggle-queue-filtering' }, function(response) {
        if (response) {
            if (response.active == true) {
                startQueueButton.setText('Queue Filtering: On');
                startQueueButton.setColor('#107C10');
                document.getElementById('results').textContent = 'Queue filtering started.';
            } else {
                startQueueButton.setText('Queue Filtering: Off');
                startQueueButton.setColor('#D83B01');
                document.getElementById('results').textContent = 'Queue filtering stopped.';
            }
        } else {
            document.getElementById('results').textContent = 'Failed to start queue filtering.';
        }
    });
});

if (timerToggleButton) {
    timerToggleButton.addEventListener('click', () => {
        chrome.storage.local.get({ timerCountVisible: true }, (result) => {
            const newVisible = !result.timerCountVisible;
            chrome.storage.local.set({ timerCountVisible: newVisible }, () => {
                updateTimerCountButton(newVisible);
                updateTimerCountInAllTabs(newVisible);
            });
        });
    });
}


function updateTimerCountButton(visible) {
    if (!timerToggleButton) return;
    if (visible) {
        timerToggleButton.setText('Timer/Count: On');
        timerToggleButton.setColor('#107C10');
    } else {
        timerToggleButton.setText('Timer/Count: Off');
        timerToggleButton.setColor('#D83B01');
    }
}
function updateTimerCountInAllTabs(visible) {
    chrome.tabs.query({}, (tabs) => {
        if (!tabs || !tabs.length) return;

        tabs.forEach((tab) => {
            if (!tab.id) return;

            chrome.tabs.sendMessage(
                tab.id,
                { type: 'set-timer-count-visible', visible },
                () => {
                    // Ignore tabs without our content script
                    if (chrome.runtime.lastError) {
                        // console.debug('No receiver in tab', tab.id, chrome.runtime.lastError.message);
                    }
                }
            );
        });
    });
}



function getScoreClass(score) {
    if (score > 75) {
        return 'score-red';
    } else if (score > 25) {
        return 'score-orange';
    } else if (score > 0) {
        return 'score-yellow';
    } else {
        return 'score-green';
    }
}

function toggleVisibility(elementId) {
    var element = document.getElementById(elementId);
    element.classList.toggle('visible');
}

function updateProgress(malicious, total) {
    const circle = document.querySelector('.progress-circle');
    const text = document.querySelector('.progress-text');
    const radius = circle.r.baseVal.value;
    const circumference = 2 * Math.PI * radius;
    const percent = malicious / total;

    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = `${(1 - percent) * circumference}`;

    text.textContent = `${malicious} / ${total}`;

    // Determine color based on the number of reports
    if (malicious === 0) {
        circle.style.strokeDashoffset = `${0}`;
        circle.style.stroke = '#008000'; // Green for no reports
    } else if (malicious <= 14) {
        circle.style.stroke = '#FFD700'; // Yellow for 2-14 reports
    } else {
        circle.style.stroke = '#FF0000'; // Red for more than 14 reports
    }
}

function displayResults(response) {
    console.log("Display Results")
    if (response.error) {
        console.log(response)
        document.getElementById('results').textContent = 'Error fetching data: ' + response.error;
    } else if(response.errors) {
        var text = ""
        console.log(response)
        for (error of response.errors) {
            text = text + error.status + ": " + error.detail + "\n"
        }
        document.getElementById('results').textContent = 'Error fetching data: ' + text;
    } else { 
        console.log("Oh yeah", response)
        // Check if we're doing OSINT on an IP
        if (response.ip) {
            if (response.abuseIPDB) {
                // Check if domain exists and use a default value if it doesn't
                const domain = response.abuseIPDB.domain ? response.abuseIPDB.domain.replace('.', '[.]') : 'No domain available';

                // Safely access hostnames array and join, provide default if undefined
                const hostnames = response.abuseIPDB.hostnames?.join(', ') || 'No hostnames available';
                const scoreClass = getScoreClass(response.abuseIPDB.abuseConfidenceScore);
                const progressBarWidth = response.abuseIPDB.abuseConfidenceScore == 0 ? 100 : response.abuseIPDB.abuseConfidenceScore;
                const geoLocation = (response.IPInfo && response.IPInfo.city && response.IPInfo.region) ?
                `${response.IPInfo.city}, ${response.IPInfo.region}, ${response.IPInfo.country}` :
                (response.abuseIPDB && response.abuseIPDB.countryName) ?
                response.abuseIPDB.countryName :
                "No GeoLocation data available";

                const riskData = (response.Scamalytics.risk) ?
                ` ${response.Scamalytics.risk.toUpperCase()} - ${response.Scamalytics.score}` : 'No Risk Data Available';
                // Build the results HTML
                const body = document.querySelector('body');
                body.style.minWidth = '320px'; // Slimmer for IPs
                document.getElementById('results').innerHTML = `
                    <div style="width: 100%; font-weight: bold; margin-bottom: 4px; color: #2d3748; display: flex; justify-content: space-between; align-items: center;">
                    <h1>📊 OSINT Results</h1>
                    <button id="copyAnalysisBtn" style="padding: 4px 8px; background: #ff9a9e; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 12px;">Copy</button>
                  </div>
                    <h2><span class="key">IP:</span> ${response.abuseIPDB.ipAddress}</h2>
                    <div class="content"><span class="key">Reports:</span> ${response.abuseIPDB.totalReports || 0} reports with a <span class="${scoreClass}">${response.abuseIPDB.abuseConfidenceScore || 0}%</span> Confidence of abuse.</div>
                    <div class="progress-container">
                        <div class="progress-bar ${scoreClass}" style="width: ${progressBarWidth}%;">${response.abuseIPDB.abuseConfidenceScore}%</div>
                    </div>
                    <div class="content"><span class="key">Scamalytics Risk:</span> ${riskData}</div>
                    <div class="content"><span class="key">isTor:</span> ${response.abuseIPDB.isTor ? 'Yes' : 'No'}</div>
                    <div class="content"><span class="key">ISP:</span> ${response.abuseIPDB.isp} (${domain})</div>
                    <div class="content"><span class="key">GeoLocation:</span> ${geoLocation}</div>
                    <div class="content"><span class="key">UsageType:</span> ${response.abuseIPDB.usageType || 'No usage type available'}</div>
                    <div class="content"><span class="key">Host:</span> ${hostnames}</div>
                `;
                analysisText = document.getElementById('results').textContent
                displayReferenceLinks(response.abuseIPDB.ipAddress)
                
            } else {
                document.getElementById('results').innerHTML = `Error fetching data from AbuseIPDB`;        
            }
        // Otherwise we're dealing with a hash.
        } else {
            if (response.VT.error) {
                if (response.VT.error.code == "NotFoundError") {
                    document.getElementById('results').textContent = response.VT.error.message        
                } else {
                    document.getElementById('results').textContent = 'Error fetching data: ' + response.VT.error;        
                }
            } else {
                // Build the results HTML
                const body = document.querySelector('body');
                body.style.minWidth = '420px'; // Wider for hashes
                // Extract data from the response
                const vtData = response.VT.data.attributes;
                const typeUnsupported = vtData.last_analysis_stats['type-unsupported'];
                const threatLabel = (vtData.popular_threat_classification && vtData.popular_threat_classification.suggested_threat_label) ? vtData.popular_threat_classification.suggested_threat_label : "No Threat Label Available";
                const signature = (vtData.signature_info && vtData.signature_info.verified) || "Not Signed"
                const description = vtData.description || (vtData.signature_info && vtData.signature_info.description) || "No Description Available"
                const signDate =  (vtData.signature_info && vtData.signature_info["signing date"]) || "N/A"
                const product =  (vtData.signature_info && vtData.signature_info.product) || "N/A"
                const copyright = (vtData.signature_info && vtData.signature_info.copyright) || "N/A"
                const comments =  (vtData.signature_info && vtData.signature_info.comments) || "No Comments"
                const signers =  (vtData.signature_info && vtData.signature_info.signers) ? vtData.signature_info.signers.split(';') : ["N/A"]
                document.getElementById('results').innerHTML  = `
                    <div style="width: 100%; font-weight: bold; margin-bottom: 4px; color: #2d3748; display: flex; justify-content: space-between; align-items: center;">
                    <h1>📊 OSINT Results</h1>
                    <button id="copyAnalysisBtn" style="padding: 4px 8px; background: #ff9a9e; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 12px;">Copy</button>
                  </div>
                    <h1>OSINT Results</h1>
                    <p><strong>Security Vendors:</strong> ${vtData.last_analysis_stats.malicious} out of ${vtData.last_analysis_stats.undetected + vtData.last_analysis_stats.malicious} security vendors and ${typeUnsupported} sandboxes flagged this file as malicious</p>
                    <div class="circle-container">
                    <svg width="120" height="120" viewBox="0 0 120 120">
                        <circle cx="60" cy="60" r="54" fill="#FFFF" stroke="#ccc" stroke-width="1"/>
                        <circle cx="60" cy="60" r="54" fill="none" stroke="#ccc" stroke-width="12"/>
                        <circle cx="60" cy="60" r="54" fill="none" stroke="#f00" stroke-width="12" stroke-dasharray="339.292" stroke-dashoffset="339.292" class="progress-circle"/>
                        <text x="60" y="65" text-anchor="middle" fill="#333" font-size="20" class="progress-text"></text>
                    </svg>
                    </div>
                    <p><strong>Name:</strong> ${vtData.meaningful_name}</p>
                    
                    <button class="toggle-button" id="toggleOtherNames">Other Names</button>
                    <ul id="otherNames" class="collapse">
                        ${vtData.names.map(name => `<li>${name}</li>`).join('')}
                    </ul>
                    
                    <button class="toggle-button" id="toggleHashes">Hashes</button>
                    <div id="hashes" class="collapse">
                        <p><strong>MD5</strong>: ${vtData.md5}</p>
                        <p><strong>SHA1</strong>: ${vtData.sha1}</p>
                        <p><strong>SHA256</strong>: ${vtData.sha256}</p>
                    </div>
                    <button class="toggle-button" id="toggleSignatureInfo">Signature Info</button>
                    <ul id="signatures" class="collapse">
                        <p><strong>Comments:</strong> ${comments}</p>
                        <p><strong>Signed:</strong> ${signature}</p>
                        <p><strong>Signing Date:</strong> ${signDate}</p>
                        <p><strong>Product:</strong> ${product}</p>
                        <p><strong>Copyright:</strong> ${copyright}</p>
                        <strong>Signers: </strong>${Object.entries(signers).map(([index, sig]) => `<li><strong>${(parseInt(index)+1)}:</strong> ${sig}</li>`).join('')}
                    </ul>
                    <p><strong>Description:</strong> ${description}</p>
                    <p><strong>FileType:</strong> ${vtData.type_description}</p>
                    <p><strong>File Size:</strong> ${vtData.size} bytes</p>
                    <p><strong>First Submitted:</strong> ${new Date(vtData.first_submission_date * 1000).toLocaleDateString('en-US')}</p>
                    <p><strong>Popular Threat Label:</strong> ${threatLabel}</p>
                    <p><strong>Popular Threat Category:</strong> ${vtData.type_tag || "No Threat Category Available"}</p>
                    
                    <button class="toggle-button" id="toggleVendorLabels">Vendor Labels</button>
                    <ul id="vendorLabels" class="collapse">
                        ${Object.entries(vtData.last_analysis_results).map(([vendor, result]) => `<li><strong>${vendor}</strong>: ${result.result}</li>`).join('')}
                    </ul>
                    <p><strong>Tags:</strong> ${vtData.tags.join(', ')}</p>
                    <a href="${response.VT.data.links.self}" target="_blank">View on VirusTotal</a>
                `;
                
                // Example usage:
                updateProgress(vtData.last_analysis_stats.malicious, vtData.last_analysis_stats.undetected + vtData.last_analysis_stats.malicious); // You would replace these numbers with your actual data
                

                // Event listeners for toggling visibility
                document.getElementById('toggleOtherNames').addEventListener('click', () => toggleVisibility('otherNames'));
                document.getElementById('toggleHashes').addEventListener('click', () => toggleVisibility('hashes'));
                document.getElementById('toggleSignatureInfo').addEventListener('click', () => toggleVisibility('signatures'));
                document.getElementById('toggleVendorLabels').addEventListener('click', () => toggleVisibility('vendorLabels'));
                analysisText = document.getElementById('results').textContent
                  
            }       
        }
                 // Add click event listener to the copy button
        document.getElementById('copyAnalysisBtn').addEventListener('click', function() {
          navigator.clipboard.writeText(analysisText).then(() => {
            const originalText = this.textContent;
            this.textContent = "Copied!";
            setTimeout(() => this.textContent = originalText, 1000);
          }).catch(err => {
            console.error('Failed to copy text: ', err);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = analysisText;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            const originalText = this.textContent;
            this.textContent = "Copied!";
            setTimeout(() => this.textContent = originalText, 1000);
          });
        });
    }
}