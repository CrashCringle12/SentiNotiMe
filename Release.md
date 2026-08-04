# SentiBuddy v4.0.0

# ✨ New Features

### Central Configuration

-   Added support for loading configuration from an External **JSON ** via URL
-   Allows teams to distribute shared:
    -   queue filters
    -   dashboard links
    -   API Keys
    -   client reference tables
-   Config values originating from the central config display a **lock icon** in the UI

### Client / Development Reference Tabs

-   Added **Client Info** and **Development** tabs
-   Tables in these tabs are generated from config:
    -   `tableData.data` → **Client Info tab**
    -   `tableData.devData` → **Development tab**
-   Tables are **not stored locally** and must come from the central
    config

### Manual OSINT Input

-   OSINT queries can now be run by **typing IPs or hashes directly**
-   Clipboard detection still supported

### Dashboard Button

-   Added configurable **dashboard button**
-   `dashboardTitle` → button label
-   `dashboardLink` → destination URL

------------------------------------------------------------------------

# 🔐 Security

-   Added stricter **input validation and sanitization**
-   Restricted external URLs to trusted Microsoft domains
-   Various internal security hardening fixes

------------------------------------------------------------------------

# ⚙ Improvements

### UI

-   Rebuilt SentiBuddy menu from ground up with new **tab layout**
    -   **Operations** -- existing SentiBuddy tools
    -   **Client Info** -- client reference table
    -   **Development** -- infrastructure reference table
-   Redesigned **Options panel**
-   Added **Light Mode / Dark Mode**
-   Added Logo to main page
-   Colors and Emojis!
-   Added **hover descriptions** to all buttons to give better clarity on what they can do.

### Queue Safety

-   Sentinel **"Select All" checkbox** is hidden while queue filtering
    is enabled\
    Prevents accidental bulk selection when filters are active.

### Timer / Incident Counter

-   Timer and incident counter can now be **enabled or disabled from the
    menu**

------------------------------------------------------------------------
## ⚠ Breaking Changes

-   API keys are **no longer included when exporting configuration**
-   External URL validation now restricts links to
    **Microsoft/Azure/SharePoint domains**
-   Experimental **note-taking feature removed**

------------------------------------------------------------------------
# ❌ Removed

-   Experimental **note-taking functionality**

------------------------------------------------------------------------

# Example: Custom Tables (Client Info / Development Tabs)

The `tableData` object allows teams to define **custom tables** that
appear in the SentiBuddy interface.

-   `tableData.data` → displayed in the **Client Info tab**
-   `tableData.devData` → displayed in the **Development tab**
-   `tableData.schemas` → optional column and hyperlink definitions

Each object in the array becomes **one row in the table**.

Columns are rendered dynamically.

-   If `tableData.schemas` is provided, its column definitions control:
    -   display names
    -   column order
    -   hyperlink behavior
-   If `tableData.schemas` is not provided, the extension falls back to
    its built-in default layout.

### Example: Client Info Table

``` json
"tableData": {
  "schemas": {
    "data": {
      "columns": {
        "code": { "displayName": "Code" },
        "client": { "displayName": "Client" },
        "department": { "displayName": "Department" },
        "lead": { "displayName": "Client Lead" },
        "edr": {
          "displayName": "EDR",
          "hyperLink": { "urlField": "edrLink" }
        },
        "contact": {
          "displayName": "Contacts",
          "hyperLink": { "text": "Info" }
        }
      }
    }
  },
  "data": [
    {
      "code": "AppB2",
      "client": "Apple Bank",
      "department": "Banking",
      "lead": "Jimbo",
      "edr": "CrowdStrike",
      "edrLink": "https://example.com",
      "contact": "https://example.com/contact"
    },
    {
      "code": "FinX",
      "client": "FinTech Corp",
      "department": "Finance",
      "lead": "Sarah",
      "edr": "SentinelOne",
      "edrLink": "https://example.com",
      "contact": "https://example.com/contact"
    }
  ]
}
```

This renders as:

    Code | Client | Department | Client Lead | EDR | Contacts

With this behavior:

-   The **EDR** cell displays `edr` text and links to `edrLink`
-   The **Contacts** cell displays `Info` and links to `contact`
-   `edrLink` is used as a link source and is **not shown as its own
    column**

### Example: Development Table

``` json
"tableData": {
  "schemas": {
    "devData": {
      "columns": {
        "client": { "displayName": "Client" },
        "sentinelName": {
          "displayName": "Sentinel Instance",
          "hyperLink": { "urlField": "sentinelLink" }
        },
        "rgName": {
          "displayName": "Resource Group",
          "hyperLink": { "urlField": "rgLink" }
        },
        "subscriptionName": {
          "displayName": "Subscription",
          "hyperLink": { "urlField": "subscriptionLink" }
        },
        "location": { "displayName": "Location" }
      }
    }
  },
  "devData": [
    {
      "client": "Apple Bank",
      "sentinelName": "apple-prod",
      "sentinelLink": "https://portal.azure.com/",
      "rgName": "apple-security-rg",
      "rgLink": "https://portal.azure.com/",
      "subscriptionName": "Apple Security",
      "subscriptionLink": "https://portal.azure.com/",
      "location": "eastus"
    }
  ]
}
```

This renders as:

    Client | Sentinel Instance | Resource Group | Subscription | Location

### Recommendations

-   Limit tables to **\~6--7 columns** for readability in the extension
    popup
-   Use `schemas` when you want explicit column labels and ordering
-   Use `hyperLink.urlField` (or `hyperlink.urlField`) to map a display
    field to a URL field
-   URLs can be used for quick navigation to dashboards or portals

------------------------------------------------------------------------

# Central Config Schema

All fields are optional. Missing values fall back to local
configuration.

``` json
{
  "type": "object",
  "properties": {
    "desktopNotifications": { "type": "boolean" },
    "abuseipdbAPIkey": { "type": "string" },
    "ipInfoKey": { "type": "string" },
    "scamalyticsURL": { "type": "string" },
    "vtkey": { "type": "string" },
    "configDataURL": { "type": "string" },
    "doRemoveFromFilteredFromQueue": { "type": "boolean" },
    "filterOwnerRegexPatterns": { "type": "array" },
    "filterTagsRegexPatterns": { "type": "array", "items": { "type": "string" } },
    "filterTitleRegexPatterns": { "type": "array", "items": { "type": "string" } },
    "onlyAlertOnLatest": { "type": "boolean" },
    "dashboardTitle": { "type": "string" },
    "dashboardLink": { "type": "string" },
    "incidentLookbackEndpoint": { "type": "string" },
    "tableData": {
      "type": "object",
      "properties": {
        "schemas": { "type": "object" },
        "data": { "type": "array" },
        "devData": { "type": "array" }
      }
    }
  }
}
```


**Full Changelog**: https://github.com/CrashCringle12/SentiBuddy/compare/3.0.1...4.0.0