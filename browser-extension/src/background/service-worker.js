/**
 * True Protection by Jag - Background Service Worker
 * Handles URL reputation checking, download scanning, phishing detection,
 * cryptojacking blocking, audit logging, and communication with the
 * True Protection daemon.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

import { BlocklistManager } from "./blocklist.js";
import { PhishingDetector } from "../utils/phishing-detector.js";
import {
  initPasswordManager,
  handlePasswordManagerMessage,
  handleAlarm as handlePmAlarm,
  handleTabUpdated as handlePmTabUpdated,
  handleTabRemoved as handlePmTabRemoved,
} from "./password-manager.js";

// ---- State ----------------------------------------------------------------

const blocklist = new BlocklistManager();
const phishingDetector = new PhishingDetector();

let protectionEnabled = true;
let protectionLevel = "balanced"; // strict | balanced | minimal
let jagaiCloudEnabled = false;
let nativePort = null;
let daemonConnected = false;

// Per-tab threat tracking
const tabThreats = new Map();

// Daily stats
let stats = {
  pagesScanned: 0,
  threatsBlocked: 0,
  phishingDetected: 0,
  miningBlocked: 0,
  downloadsScanned: 0,
  date: new Date().toDateString(),
};

// Browsing history for scans and threats (persisted, max 200 entries)
const MAX_HISTORY = 200;
let scanHistory = [];

// ---- API Configuration ----------------------------------------------------

const API_BASE = "https://tpjsecurity.com/api/v1";

// ---- Audit Log Queue ------------------------------------------------------

const AUDIT_FLUSH_INTERVAL_MS = 30000; // 30 seconds
let auditQueue = [];
let auditFlushTimer = null;

/**
 * Queue an audit log entry. Logs are batched and flushed every 30 seconds
 * or when the queue reaches 50 entries - whichever comes first.
 * Logs are persisted to storage so they survive service worker restarts.
 * If the user is not authenticated the entry is silently dropped.
 */
async function sendAuditLog(action, details = {}) {
  try {
    const stored = await chrome.storage.local.get("tpj_account");
    const token = stored.tpj_account?.auth_token;
    if (!token) return; // not logged in - skip

    const entry = {
      action,
      details,
      timestamp: new Date().toISOString(),
      browser: getBrowserInfo(),
    };

    auditQueue.push(entry);

    // Persist queue in case the service worker is terminated
    await chrome.storage.local.set({ tpj_audit_queue: auditQueue });

    // Flush immediately if queue is large
    if (auditQueue.length >= 50) {
      await flushAuditQueue();
    }
  } catch {
    // Never let audit logging break protection
  }
}

/**
 * Flush all queued audit log entries to the API in a single batch request.
 */
async function flushAuditQueue() {
  if (auditQueue.length === 0) return;

  const account = await getAuthAccount();
  if (!account) {
    // Not authenticated - clear the queue
    auditQueue = [];
    await chrome.storage.local.remove("tpj_audit_queue");
    return;
  }

  try {
    const batch = [...auditQueue];
    auditQueue = [];
    await chrome.storage.local.remove("tpj_audit_queue");

    const info = getBrowserInfo();
    const resp = await authenticatedFetch(`${API_BASE}/audit/log`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Browser-Name": info.browserName,
      },
      body: JSON.stringify({ entries: batch }),
    });

    if (!resp || !resp.ok) {
      // Put entries back so they can be retried (unless session expired)
      if (resp) {
        auditQueue = [...batch, ...auditQueue];
        await chrome.storage.local.set({ tpj_audit_queue: auditQueue });
      }
    }
  } catch {
    // Network error - entries remain in storage for next flush
  }
}

/**
 * Restore any queued audit entries that were persisted before the service
 * worker was terminated.
 */
async function restoreAuditQueue() {
  try {
    const stored = await chrome.storage.local.get("tpj_audit_queue");
    if (stored.tpj_audit_queue && Array.isArray(stored.tpj_audit_queue)) {
      auditQueue = stored.tpj_audit_queue;
    }
  } catch {
    // Ignore
  }
}

/**
 * Record a scan or threat event to the browsable history.
 * Keeps the most recent MAX_HISTORY entries.
 */
async function recordHistory(type, url, details = {}) {
  try {
    const entry = {
      type, // "scan", "threat", "blocked", "phishing", "mining"
      url,
      title: details.title || "",
      message: details.message || "",
      severity: details.severity || "",
      reason: details.reason || "", // "phishing", "malware", "mining", "blocklist", "custom", "download"
      timestamp: Date.now(),
    };

    scanHistory.unshift(entry);
    if (scanHistory.length > MAX_HISTORY) {
      scanHistory = scanHistory.slice(0, MAX_HISTORY);
    }

    await chrome.storage.local.set({ tpj_scan_history: scanHistory });
  } catch {
    // Never break protection over history logging
  }
}

/**
 * Restore scan history from storage on service worker start.
 */
async function restoreScanHistory() {
  try {
    const stored = await chrome.storage.local.get("tpj_scan_history");
    if (stored.tpj_scan_history && Array.isArray(stored.tpj_scan_history)) {
      scanHistory = stored.tpj_scan_history;
    }
  } catch {
    // Ignore
  }
}

function startAuditFlushTimer() {
  if (auditFlushTimer) return;
  auditFlushTimer = setInterval(flushAuditQueue, AUDIT_FLUSH_INTERVAL_MS);
}

function getBrowserInfo() {
  const ua = navigator.userAgent || "";
  const version = chrome.runtime.getManifest().version;

  // Detect browser name from UA
  let browserName = "Unknown";
  let browserVersion = "";

  // Brave doesn't identify itself in UA but we can detect it
  if (typeof navigator.brave !== "undefined") {
    browserName = "Brave";
  } else if (ua.includes("Edg/")) {
    browserName = "Edge";
  } else if (ua.includes("OPR/")) {
    browserName = "Opera";
  } else if (ua.includes("Firefox/")) {
    browserName = "Firefox";
  } else if (ua.includes("Chrome/")) {
    browserName = "Chrome";
  }

  const versionMatch = ua.match(/(?:Chrome|Firefox|Edg|OPR|Version)\/([\d.]+)/);
  if (versionMatch) {
    browserVersion = versionMatch[1];
  }

  // Detect OS
  let osName = "Unknown";
  if (ua.includes("Windows")) osName = "Windows";
  else if (ua.includes("Mac OS X")) osName = "macOS";
  else if (ua.includes("Linux")) osName = "Linux";
  else if (ua.includes("Android")) osName = "Android";

  return {
    userAgent: ua,
    extensionVersion: version,
    browserName,
    browserVersion,
    osName,
  };
}

// ---- Auth Helpers ----------------------------------------------------------

const MAX_SESSION_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * Check whether the user is currently authenticated.
 * Returns the account object or null.
 * Clears stale sessions older than 30 days as a client-side safety net.
 */
async function getAuthAccount() {
  try {
    const stored = await chrome.storage.local.get("tpj_account");
    const account = stored.tpj_account;
    if (!account || !account.auth_token) return null;

    // Client-side session expiry - server may revoke sooner
    if (account.logged_in_at && Date.now() - account.logged_in_at > MAX_SESSION_AGE_MS) {
      await clearSession();
      return null;
    }

    return account;
  } catch {
    return null;
  }
}

/**
 * Returns true if the user is logged in.
 */
async function isAuthenticated() {
  return (await getAuthAccount()) !== null;
}

/**
 * Clear the stored auth session. Called on logout, token expiry, or 401.
 */
async function clearSession() {
  await chrome.storage.local.remove("tpj_account");
  jagaiCloudEnabled = false;
  await chrome.storage.local.set({ jagai_cloud_enabled: false });
}

/**
 * Make an authenticated API request. Returns the Response on success.
 * On 401/403 (expired/revoked token), clears the session and returns null.
 * Returns null if no auth token is available.
 */
async function authenticatedFetch(url, options = {}) {
  const account = await getAuthAccount();
  if (!account) return null;

  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
    Authorization: `Bearer ${account.auth_token}`,
  };

  try {
    const resp = await fetch(url, { ...options, headers });

    if (resp.status === 401 || resp.status === 403) {
      console.warn("[TrueProtect] Auth token expired or revoked, clearing session");
      await clearSession();
      return null;
    }

    return resp;
  } catch (err) {
    // Network error - don't clear session, just propagate
    throw err;
  }
}

// ---- Initialization -------------------------------------------------------

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("[TrueProtect] Extension installed/updated:", details.reason);

  await blocklist.init();
  await loadSettings();
  await resetDailyStatsIfNeeded();
  await restoreAuditQueue();
  await restoreScanHistory();
  startAuditFlushTimer();

  // Set up periodic alarms
  chrome.alarms.create("blocklist-update", { periodInMinutes: 30 });
  chrome.alarms.create("stats-reset-check", { periodInMinutes: 60 });
  chrome.alarms.create("daemon-heartbeat", { periodInMinutes: 5 });
  chrome.alarms.create("audit-flush", { periodInMinutes: 1 });

  if (details.reason === "install") {
    await chrome.storage.local.set({
      protection_enabled: true,
      protection_level: "balanced",
      jagai_cloud_enabled: false,
      notification_prefs: {
        showBlocked: true,
        showPhishing: true,
        showMining: true,
        showDownload: true,
      },
    });

    chrome.notifications.create("welcome", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
      title: "True Protection by Jag",
      message: "Web protection is now active. Log in at the popup to enable full protection.",
    });
  }

  // Create context menus (inside onInstalled so they are only registered once)
  chrome.contextMenus.create({
    id: "scan-link",
    title: "Scan link with True Protection",
    contexts: ["link"],
  });

  chrome.contextMenus.create({
    id: "scan-page",
    title: "Scan this page with True Protection",
    contexts: ["page"],
  });

  updateBadge();
  connectToDaemon();
  initPasswordManager();

  // Seed declarativeNetRequest dynamic rules from the current blocklist
  await syncDynamicBlockRules();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log("[TrueProtect] Browser started");
  await blocklist.init();
  await loadSettings();
  await resetDailyStatsIfNeeded();
  await restoreAuditQueue();
  await restoreScanHistory();
  startAuditFlushTimer();
  updateBadge();
  connectToDaemon();
  initPasswordManager();
});

// ---- Settings -------------------------------------------------------------

async function loadSettings() {
  try {
    const stored = await chrome.storage.local.get([
      "protection_enabled",
      "protection_level",
      "jagai_cloud_enabled",
      "daily_stats",
    ]);

    protectionEnabled = stored.protection_enabled !== false;
    protectionLevel = stored.protection_level || "balanced";
    jagaiCloudEnabled = stored.jagai_cloud_enabled || false;

    if (stored.daily_stats) {
      stats = stored.daily_stats;
    }
  } catch (err) {
    console.error("[TrueProtect] Failed to load settings:", err);
  }
}

async function saveStats() {
  try {
    await chrome.storage.local.set({ daily_stats: stats });
  } catch (err) {
    console.error("[TrueProtect] Failed to save stats:", err);
  }
}

async function resetDailyStatsIfNeeded() {
  const today = new Date().toDateString();
  if (stats.date !== today) {
    stats = {
      pagesScanned: 0,
      threatsBlocked: 0,
      phishingDetected: 0,
      miningBlocked: 0,
      downloadsScanned: 0,
      date: today,
    };
    await saveStats();
  }
}

// ---- declarativeNetRequest Dynamic Rules ----------------------------------

/**
 * Build dynamic declarativeNetRequest rules from the current blocklist
 * domains. These rules actually block network requests in MV3 (replacing
 * the MV2 webRequest blocking model).
 */
async function syncDynamicBlockRules() {
  try {
    // Remove all existing dynamic rules first
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeIds = existingRules.map((r) => r.id);

    // Build new rules from blocklist domains (cap at 4990 to stay within quota)
    const domains = Array.from(blocklist.domainSet).slice(0, 4990);
    const addRules = domains.map((domain, index) => ({
      id: index + 1,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `||${domain}`,
        resourceTypes: [
          "script", "sub_frame", "xmlhttprequest", "image",
          "stylesheet", "font", "media", "websocket", "other",
        ],
      },
    }));

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules: addRules,
    });

    console.log(`[TrueProtect] Synced ${addRules.length} dynamic block rules`);
  } catch (err) {
    console.error("[TrueProtect] Failed to sync dynamic block rules:", err);
  }
}

// ---- URL Reputation Checking ----------------------------------------------

/**
 * Analyze a URL for threats. Returns threat info or null if clean.
 */
function checkUrl(url) {
  if (!protectionEnabled) return null;
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
      url.startsWith("about:") || url.startsWith("moz-extension://") ||
      url.startsWith("edge://") || url.startsWith("brave://")) {
    return null;
  }

  const threats = [];

  // 1. Blocklist check
  if (blocklist.isUrlBlocked(url)) {
    threats.push({
      type: "blocklist",
      severity: "high",
      message: "This URL is on the threat blocklist",
    });
  }

  // 2. Mining script check
  if (blocklist.isMiningScript(url)) {
    threats.push({
      type: "cryptojacking",
      severity: "high",
      message: "Known cryptocurrency mining script detected",
    });
  }

  // 3. Phishing heuristics (minimal mode skips these)
  if (protectionLevel !== "minimal") {
    const phishResult = phishingDetector.analyzeUrl(url);
    if (phishResult.isPhishing) {
      threats.push({
        type: "phishing",
        severity: phishResult.confidence >= 70 ? "high" : "medium",
        message: phishResult.reasons.join("; "),
        confidence: phishResult.confidence,
      });
    }
  }

  return threats.length > 0 ? threats : null;
}

// ---- Web Request Monitoring -----------------------------------------------

// Monitor navigation events for page-level blocking
chrome.webNavigation?.onBeforeNavigate?.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  if (!protectionEnabled) return;
  if (!(await isAuthenticated())) return; // Require login

  const threats = checkUrl(details.url);
  if (threats && threats.some((t) => t.severity === "high")) {
    // Update tab threat data
    tabThreats.set(details.tabId, {
      url: details.url,
      threats: threats,
      timestamp: Date.now(),
    });

    stats.threatsBlocked++;
    threats.forEach((t) => {
      if (t.type === "phishing") stats.phishingDetected++;
      if (t.type === "cryptojacking") stats.miningBlocked++;
    });
    await saveStats();
    updateBadge();

    // Audit log threats and record in browsable block history
    for (const t of threats) {
      const reason = t.type === "phishing" ? "phishing"
        : t.type === "cryptojacking" ? "mining"
        : t.type === "blocklist" ? "blocklist"
        : "malware";

      recordHistory("blocked", details.url, {
        message: t.message,
        severity: t.severity || "high",
        reason,
      });

      if (t.type === "phishing") {
        sendAuditLog("extension.phishing_detected", {
          url: details.url,
          confidence: t.confidence || 0,
          message: t.message,
        });
      } else if (t.type === "cryptojacking") {
        sendAuditLog("extension.mining_blocked", {
          url: details.url,
          message: t.message,
        });
      } else {
        sendAuditLog("extension.threat_blocked", {
          url: details.url,
          threatType: t.type,
          severity: t.severity,
          message: t.message,
        });
      }
    }

    // Show warning notification for high-severity threats
    const prefs = (await chrome.storage.local.get("notification_prefs")).notification_prefs || {};
    if (prefs.showBlocked !== false) {
      chrome.notifications.create(`threat-${details.tabId}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title: "Threat Blocked - True Protection",
        message: `Blocked: ${threats[0].message}`,
      });
    }
  }
});

// Monitor sub-resource requests (scripts, iframes, etc.)
// NOTE: In MV3 webRequest is observational only. Actual blocking is handled
// by declarativeNetRequest (static rules in rules/blocklist-rules.json and
// dynamic rules synced via syncDynamicBlockRules). This listener is kept for
// logging and stat tracking purposes.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!protectionEnabled) return;

    // Check for mining scripts in sub-resources
    if (blocklist.isMiningScript(details.url)) {
      stats.miningBlocked++;
      stats.threatsBlocked++;
      saveStats();
      updateBadge();

      console.log("[TrueProtect] Mining script detected:", details.url);

      recordHistory("blocked", details.url, {
        message: "Cryptocurrency mining script blocked",
        severity: "high",
        reason: "mining",
      });
      sendAuditLog("extension.mining_blocked", {
        url: details.url,
        message: "Mining script blocked (sub-resource)",
      });

      // Notify content script
      if (details.tabId > 0) {
        chrome.tabs.sendMessage(details.tabId, {
          type: "MINING_BLOCKED",
          url: details.url,
        }).catch(() => {});
      }
    }

    // Track blocklist hits in strict mode
    if (protectionLevel === "strict" && blocklist.isUrlBlocked(details.url)) {
      stats.threatsBlocked++;
      saveStats();
      updateBadge();

      recordHistory("blocked", details.url, {
        message: "URL on threat blocklist",
        severity: "high",
        reason: "blocklist",
      });
      sendAuditLog("extension.threat_blocked", {
        url: details.url,
        threatType: "blocklist",
        severity: "high",
        message: "Sub-resource blocked (strict mode)",
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// ---- DNS-over-HTTPS Query Monitoring --------------------------------------

// Monitor requests to known DoH endpoints for logging/analysis
const DOH_ENDPOINTS = [
  "*://cloudflare-dns.com/dns-query*",
  "*://dns.google/resolve*",
  "*://dns.google/dns-query*",
  "*://doh.opendns.com/dns-query*",
  "*://dns.quad9.net/dns-query*",
];

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!protectionEnabled) return;

    // Log DoH queries for analysis but do not block them
    console.log("[TrueProtect] DoH query detected:", details.url);

    // Forward to daemon for analysis if connected
    sendToDaemon({
      type: "DOH_QUERY",
      url: details.url,
      tabId: details.tabId,
      timestamp: Date.now(),
    });
  },
  { urls: DOH_ENDPOINTS },
  []
);

// ---- Download Scanning ----------------------------------------------------

chrome.downloads?.onCreated?.addListener(async (downloadItem) => {
  if (!protectionEnabled) return;

  stats.downloadsScanned++;
  await saveStats();

  const url = downloadItem.url || downloadItem.finalUrl;
  if (!url) return;

  const threats = checkUrl(url);
  if (threats && threats.some((t) => t.severity === "high")) {
    // Cancel the download
    try {
      await chrome.downloads.cancel(downloadItem.id);
      console.log("[TrueProtect] Blocked download from:", url);

      stats.threatsBlocked++;
      await saveStats();
      updateBadge();

      recordHistory("blocked", url, {
        title: downloadItem.filename || "",
        message: `Dangerous download blocked: ${threats[0].message}`,
        severity: "high",
        reason: "download",
      });
      sendAuditLog("extension.threat_blocked", {
        url,
        threatType: "download",
        severity: "high",
        message: threats[0].message,
        filename: downloadItem.filename || "",
      });

      const prefs = (await chrome.storage.local.get("notification_prefs")).notification_prefs || {};
      if (prefs.showDownload !== false) {
        chrome.notifications.create(`download-${downloadItem.id}`, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
          title: "Download Blocked - True Protection",
          message: `A download from a dangerous source was blocked: ${threats[0].message}`,
        });
      }
    } catch (err) {
      console.error("[TrueProtect] Failed to cancel download:", err);
    }
  }

  // Also check file extension for suspicious types
  const dangerousExtensions = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll",
  ];
  const filename = (downloadItem.filename || "").toLowerCase();
  const matchedExt = dangerousExtensions.find((ext) => filename.endsWith(ext));
  if (matchedExt && protectionLevel === "strict") {
    const prefs = (await chrome.storage.local.get("notification_prefs")).notification_prefs || {};
    if (prefs.showDownload !== false) {
      chrome.notifications.create(`download-warn-${downloadItem.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title: "Download Warning - True Protection",
        message: `Downloaded file has a potentially dangerous extension: ${matchedExt}`,
      });
    }
  }
});

// ---- Tab Tracking ---------------------------------------------------------

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Only scan and track if authenticated
    const authed = await isAuthenticated();
    if (!authed) {
      handlePmTabUpdated(tabId, changeInfo, tab);
      return;
    }

    stats.pagesScanned++;
    await saveStats();
    recordHistory("scan", tab.url, { title: tab.title });

    // Run URL analysis on the completed page
    const threats = checkUrl(tab.url);
    const isSafe = !threats || threats.length === 0;

    if (threats) {
      tabThreats.set(tabId, {
        url: tab.url,
        threats: threats,
        timestamp: Date.now(),
      });

      // Record each threat in browsable history
      for (const t of threats) {
        recordHistory("threat", tab.url, {
          title: tab.title,
          message: t.message,
          severity: t.severity || "medium",
        });
      }

      // Audit log each threat type
      for (const threat of threats) {
        if (threat.type === "phishing") {
          sendAuditLog("extension.phishing_detected", {
            url: tab.url,
            confidence: threat.confidence || 0,
            message: threat.message,
          });
        } else if (threat.type === "cryptojacking") {
          sendAuditLog("extension.mining_blocked", {
            url: tab.url,
            message: threat.message,
          });
        } else {
          sendAuditLog("extension.threat_blocked", {
            url: tab.url,
            threatType: threat.type,
            severity: threat.severity,
            message: threat.message,
          });
        }
      }
    } else {
      tabThreats.delete(tabId);
    }

    // Log page scan
    sendAuditLog("extension.page_scanned", {
      url: tab.url,
      result: isSafe ? "safe" : "threats_found",
      threatCount: threats ? threats.length : 0,
    });
  }

  // Delegate to password manager tab tracking
  handlePmTabUpdated(tabId, changeInfo, tab);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabThreats.delete(tabId);
  handlePmTabRemoved(tabId);
});

// ---- Badge Updates --------------------------------------------------------

function updateBadge() {
  const count = stats.threatsBlocked;

  if (!protectionEnabled) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#666666" });
    return;
  }

  if (count > 0) {
    const text = count > 999 ? "999+" : String(count);
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
  } else {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setBadgeBackgroundColor({ color: "#27ae60" });
  }
}

// ---- Native Messaging (Daemon Communication) ------------------------------

function connectToDaemon() {
  try {
    nativePort = chrome.runtime.connectNative("com.jagjourney.trueprotection");

    nativePort.onMessage.addListener((message) => {
      handleDaemonMessage(message);
    });

    nativePort.onDisconnect.addListener(() => {
      console.log("[TrueProtect] Disconnected from daemon:", chrome.runtime.lastError?.message);
      daemonConnected = false;
      nativePort = null;

      // Retry connection in 30 seconds
      setTimeout(connectToDaemon, 30000);
    });

    daemonConnected = true;
    console.log("[TrueProtect] Connected to True Protection daemon");

    // Request blocklist update from daemon
    sendToDaemon({ type: "GET_BLOCKLIST" });
    sendToDaemon({ type: "GET_STATUS" });
  } catch (err) {
    console.log("[TrueProtect] Daemon not available:", err.message);
    daemonConnected = false;
    nativePort = null;
  }
}

function sendToDaemon(message) {
  if (nativePort && daemonConnected) {
    try {
      nativePort.postMessage(message);
    } catch (err) {
      console.error("[TrueProtect] Failed to send to daemon:", err);
      daemonConnected = false;
    }
  }
}

function handleDaemonMessage(message) {
  switch (message.type) {
    case "BLOCKLIST_UPDATE":
      blocklist.mergeFromDaemon(message.data);
      // Re-sync declarativeNetRequest rules after blocklist update
      syncDynamicBlockRules();
      break;

    case "STATUS":
      console.log("[TrueProtect] Daemon status:", message.data);
      break;

    case "SCAN_RESULT":
      // Handle cloud scan results from JagAI
      if (message.data && message.data.tabId) {
        const existing = tabThreats.get(message.data.tabId) || { threats: [] };
        if (message.data.threats) {
          existing.threats = [...existing.threats, ...message.data.threats];
          tabThreats.set(message.data.tabId, existing);
        }
      }
      break;

    case "CONFIG_UPDATE":
      if (message.data.protectionLevel) {
        protectionLevel = message.data.protectionLevel;
        chrome.storage.local.set({ protection_level: protectionLevel });
      }
      break;

    default:
      console.log("[TrueProtect] Unknown daemon message:", message.type);
  }
}

// ---- Alarm Handlers -------------------------------------------------------

chrome.alarms.onAlarm.addListener(async (alarm) => {
  switch (alarm.name) {
    case "blocklist-update":
      sendToDaemon({ type: "GET_BLOCKLIST" });
      break;

    case "stats-reset-check":
      await resetDailyStatsIfNeeded();
      break;

    case "daemon-heartbeat":
      if (!daemonConnected) {
        connectToDaemon();
      } else {
        sendToDaemon({ type: "HEARTBEAT", timestamp: Date.now() });
      }
      break;

    case "audit-flush":
      await flushAuditQueue();
      break;

    default:
      // Delegate password manager alarms
      handlePmAlarm(alarm.name);
      break;
  }
});

// ---- Message Handling (from popup, options, content scripts) ---------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((err) => {
    console.error("[TrueProtect] Message handler error:", err);
    sendResponse({ error: err.message });
  });
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  // Try password manager handler first
  const pmResponse = await handlePasswordManagerMessage(message, sender);
  if (pmResponse !== null && pmResponse !== undefined) {
    return pmResponse;
  }

  switch (message.type) {
    // -- Auth check (used by content scripts) --
    case "CHECK_AUTH": {
      const authed = await isAuthenticated();
      return { authenticated: authed };
    }

    // -- Popup requests --
    case "GET_STATUS": {
      const tabId = message.tabId;
      const threatData = tabId ? tabThreats.get(tabId) : null;
      const authed = await isAuthenticated();
      return {
        protectionEnabled,
        protectionLevel,
        daemonConnected,
        jagaiCloudEnabled,
        authenticated: authed,
        stats: { ...stats },
        currentTab: threatData || null,
        blocklistStats: blocklist.getStats(),
      };
    }

    case "TOGGLE_PROTECTION": {
      // Require auth to toggle protection
      if (!(await isAuthenticated())) {
        return { error: "Login required", protectionEnabled };
      }
      protectionEnabled = !protectionEnabled;
      await chrome.storage.local.set({ protection_enabled: protectionEnabled });
      updateBadge();
      sendAuditLog("extension.protection_toggled", {
        enabled: protectionEnabled,
      });
      return { protectionEnabled };
    }

    case "SET_PROTECTION_LEVEL": {
      protectionLevel = message.level;
      await chrome.storage.local.set({ protection_level: protectionLevel });
      return { protectionLevel };
    }

    case "REPORT_FALSE_POSITIVE": {
      const report = {
        url: message.url,
        reason: message.reason,
        timestamp: Date.now(),
      };
      sendToDaemon({ type: "FALSE_POSITIVE_REPORT", data: report });

      // Add to whitelist
      try {
        const parsed = new URL(message.url);
        blocklist.addWhitelist(parsed.hostname);
        await blocklist.save();
      } catch {}

      return { success: true };
    }

    // -- Account / Auth --
    case "ACCOUNT_LOGIN": {
      return await handleAccountLogin(message.email, message.password);
    }

    case "ACCOUNT_LOGOUT": {
      return await handleAccountLogout();
    }

    case "ACCOUNT_STATUS": {
      return await getAccountStatus();
    }

    case "ACCOUNT_SYNC_BLOCKLIST": {
      return await syncBlocklistFromApi();
    }

    case "SYNC_SETTINGS": {
      await syncSettingsFromAccount();
      return { success: true };
    }

    // -- Content script reports --
    case "PAGE_SCAN_RESULT": {
      if (!sender.tab) return { received: true };

      // Require auth for content script results to be processed
      if (!(await isAuthenticated())) return { received: true };

      const tabId = sender.tab.id;
      const existing = tabThreats.get(tabId) || { url: sender.tab.url, threats: [], timestamp: Date.now() };

      if (message.threats && message.threats.length > 0) {
        existing.threats = [...existing.threats, ...message.threats];
        tabThreats.set(tabId, existing);

        stats.threatsBlocked += message.threats.length;
        message.threats.forEach((t) => {
          const reason = t.type === "phishing" ? "phishing"
            : t.type === "cryptojacking" ? "mining"
            : t.type === "blocklist" ? "blocklist"
            : "malware";

          recordHistory("blocked", sender.tab.url, {
            title: sender.tab.title || "",
            message: t.message,
            severity: t.severity || "high",
            reason,
          });

          if (t.type === "phishing") {
            stats.phishingDetected++;
            sendAuditLog("extension.phishing_detected", {
              url: sender.tab.url,
              confidence: t.confidence || 0,
              message: t.message,
            });
          } else if (t.type === "cryptojacking") {
            stats.miningBlocked++;
            sendAuditLog("extension.mining_blocked", {
              url: sender.tab.url,
              message: t.message,
            });
          } else {
            sendAuditLog("extension.threat_blocked", {
              url: sender.tab.url,
              threatType: t.type,
              severity: t.severity,
              message: t.message,
            });
          }
        });
        await saveStats();
        updateBadge();
      }

      // Forward to daemon for cloud analysis if enabled
      if (jagaiCloudEnabled) {
        sendToDaemon({
          type: "CLOUD_SCAN_REQUEST",
          data: {
            tabId: tabId,
            url: sender.tab.url,
            findings: message.threats,
          },
        });
      }

      return { received: true };
    }

    case "CHECK_URL": {
      const threats = checkUrl(message.url);
      return { threats: threats || [] };
    }

    // -- Options page --
    case "GET_SETTINGS": {
      const stored = await chrome.storage.local.get([
        "protection_level",
        "jagai_cloud_enabled",
        "notification_prefs",
      ]);
      return {
        protectionLevel: stored.protection_level || "balanced",
        jagaiCloudEnabled: stored.jagai_cloud_enabled || false,
        notificationPrefs: stored.notification_prefs || {
          showBlocked: true,
          showPhishing: true,
          showMining: true,
          showDownload: true,
        },
        daemonConnected,
        whitelist: Array.from(blocklist.customWhitelist),
        customBlocklist: blocklist.getCustomBlockedDomains(),
        blocklistStats: blocklist.getStats(),
      };
    }

    case "SAVE_SETTINGS": {
      const changes = {};
      if (message.settings.protectionLevel) {
        protectionLevel = message.settings.protectionLevel;
        await chrome.storage.local.set({ protection_level: protectionLevel });
        changes.protectionLevel = protectionLevel;
      }
      if (typeof message.settings.jagaiCloudEnabled === "boolean") {
        jagaiCloudEnabled = message.settings.jagaiCloudEnabled;
        await chrome.storage.local.set({ jagai_cloud_enabled: jagaiCloudEnabled });
        changes.jagaiCloudEnabled = jagaiCloudEnabled;
      }
      if (message.settings.notificationPrefs) {
        await chrome.storage.local.set({ notification_prefs: message.settings.notificationPrefs });
        changes.notificationPrefs = message.settings.notificationPrefs;
      }
      sendAuditLog("extension.settings_changed", changes);
      return { success: true };
    }

    case "ADD_WHITELIST": {
      blocklist.addWhitelist(message.domain);
      await blocklist.save();
      return { success: true, whitelist: Array.from(blocklist.customWhitelist) };
    }

    case "REMOVE_WHITELIST": {
      blocklist.removeWhitelist(message.domain);
      await blocklist.save();
      return { success: true, whitelist: Array.from(blocklist.customWhitelist) };
    }

    case "GET_WHITELIST": {
      return { whitelist: Array.from(blocklist.customWhitelist) };
    }

    case "ADD_BLOCKLIST": {
      await blocklist.addCustomBlockedDomain(message.domain);
      return { success: true, customBlocklist: blocklist.getCustomBlockedDomains() };
    }

    case "REMOVE_BLOCKLIST": {
      await blocklist.removeCustomBlockedDomain(message.domain);
      return { success: true, customBlocklist: blocklist.getCustomBlockedDomains() };
    }

    case "GET_BLOCKLIST": {
      return { customBlocklist: blocklist.getCustomBlockedDomains() };
    }

    case "GET_HISTORY": {
      const filter = message.filter || "all"; // "all", "scans", "threats", "blocked", "phishing"
      let history = [...scanHistory];
      if (filter === "scans") {
        history = history.filter((h) => h.type === "scan");
      } else if (filter === "threats") {
        history = history.filter((h) => h.type !== "scan");
      } else if (filter === "blocked") {
        history = history.filter((h) => h.type === "blocked");
      } else if (filter === "phishing") {
        history = history.filter((h) => h.type === "blocked" && h.reason === "phishing");
      }
      return { history: history.slice(0, message.limit || 100) };
    }

    case "CLEAR_HISTORY": {
      scanHistory = [];
      await chrome.storage.local.remove("tpj_scan_history");
      return { success: true };
    }

    default:
      console.warn("[TrueProtect] Unknown message type:", message.type);
      return { error: "Unknown message type" };
  }
}

// ---- Account / Auth (tpjsecurity.com Sanctum) -----------------------------

/**
 * Authenticate against tpjsecurity.com Sanctum API.
 * Stores the Bearer token and user info in chrome.storage.local.
 *
 * Expected API response:
 * { token, user: { id, name, email, subscription: { tier, status } } }
 */
async function handleAccountLogin(email, password) {
  try {
    const resp = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
        device_name: "browser-extension",
        extension_version: chrome.runtime.getManifest().version,
        browser_name: getBrowserInfo().browserName,
        browser_version: getBrowserInfo().browserVersion,
      }),
    });

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { success: false, error: body.message || "Login failed" };
    }

    const data = await resp.json();
    const token = data.token || data.access_token;
    if (!token) {
      return { success: false, error: "No token received from server" };
    }

    // Normalize subscription tier from nested or flat response
    const subscription = data.user?.subscription || {};
    const tier = subscription.tier
      || data.user?.license_tier
      || data.license_tier
      || "free";

    const accountData = {
      auth_token: token,
      user: data.user || {},
      license_tier: tier,
      subscription_status: subscription.status || "active",
      logged_in_at: Date.now(),
    };

    await chrome.storage.local.set({ tpj_account: accountData });

    // Gate JagAI features behind pro/enterprise tiers
    const isPaid = tier === "pro" || tier === "enterprise";
    if (isPaid) {
      jagaiCloudEnabled = true;
      await chrome.storage.local.set({ jagai_cloud_enabled: true });
    }

    // Audit log the login
    sendAuditLog("extension.login", { email });

    // Sync protection settings from the server account
    await syncSettingsFromAccount();

    return {
      success: true,
      user: accountData.user,
      license_tier: tier,
    };
  } catch (err) {
    console.error("[TrueProtect] Login error:", err);
    return { success: false, error: "Network error - could not reach server" };
  }
}

/**
 * Pull protection settings from the user's account and apply them locally.
 */
async function syncSettingsFromAccount() {
  try {
    const resp = await authenticatedFetch(`${API_BASE}/user/settings`);
    if (!resp || !resp.ok) return;

    const data = await resp.json();

    // Apply server-side settings locally (only if present)
    if (data.protection_level) {
      protectionLevel = data.protection_level;
      await chrome.storage.local.set({ protection_level: protectionLevel });
    }
    if (typeof data.jagai_cloud_enabled === "boolean") {
      jagaiCloudEnabled = data.jagai_cloud_enabled;
      await chrome.storage.local.set({ jagai_cloud_enabled: jagaiCloudEnabled });
    }
    if (data.notification_prefs) {
      await chrome.storage.local.set({ notification_prefs: data.notification_prefs });
    }

    console.log("[TrueProtect] Settings synced from account");
  } catch (err) {
    console.error("[TrueProtect] Settings sync error:", err);
  }
}

/**
 * Log out: clear stored token and user data.
 */
async function handleAccountLogout() {
  // Flush any remaining audit logs before clearing the token
  await flushAuditQueue();

  try {
    const stored = await chrome.storage.local.get("tpj_account");
    const token = stored.tpj_account?.auth_token;

    // Audit log the logout while we still have the token
    if (token) {
      // Send logout audit directly (not queued) since we are about to clear
      fetch(`${API_BASE}/audit/log`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
        body: JSON.stringify({
          entries: [{
            action: "extension.logout",
            details: {},
            timestamp: new Date().toISOString(),
            browser: getBrowserInfo(),
          }],
        }),
      }).catch(() => {});

      // Attempt server-side logout (best-effort)
      fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      }).catch(() => {});
    }
  } catch {}

  await chrome.storage.local.remove("tpj_account");
  auditQueue = [];
  await chrome.storage.local.remove("tpj_audit_queue");
  return { success: true };
}

/**
 * Return current account status from storage.
 */
async function getAccountStatus() {
  try {
    const stored = await chrome.storage.local.get("tpj_account");
    const account = stored.tpj_account;

    if (!account || !account.auth_token) {
      return { loggedIn: false };
    }

    return {
      loggedIn: true,
      user: account.user || {},
      license_tier: account.license_tier || "free",
    };
  } catch {
    return { loggedIn: false };
  }
}

/**
 * Pull latest blocklist/signature updates from the API.
 * Requires a valid auth token.
 */
async function syncBlocklistFromApi() {
  try {
    const resp = await authenticatedFetch(`${API_BASE}/signatures/latest`);
    if (!resp) {
      return { success: false, error: "Session expired, please log in again" };
    }
    if (!resp.ok) {
      return { success: false, error: "Failed to fetch signatures" };
    }

    const data = await resp.json();
    if (data.domains || data.urls || data.wildcards || data.mining) {
      await blocklist.mergeFromDaemon(data);
      await syncDynamicBlockRules();
    }

    return { success: true, stats: blocklist.getStats() };
  } catch (err) {
    console.error("[TrueProtect] Blocklist sync error:", err);
    return { success: false, error: "Network error" };
  }
}

// ---- Context Menu ---------------------------------------------------------

chrome.contextMenus?.onClicked?.addListener(async (info, tab) => {
  if (info.menuItemId === "scan-link") {
    const url = info.linkUrl;
    const threats = checkUrl(url);
    const message = threats
      ? `Warning: ${threats.map((t) => t.message).join("; ")}`
      : "This link appears safe.";

    chrome.notifications.create(`scan-${Date.now()}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
      title: "Link Scan Result - True Protection",
      message: message,
    });
  }

  if (info.menuItemId === "scan-page" && tab) {
    const threats = checkUrl(tab.url);
    const message = threats
      ? `Warning: ${threats.map((t) => t.message).join("; ")}`
      : "This page appears safe.";

    chrome.notifications.create(`scan-${Date.now()}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
      title: "Page Scan Result - True Protection",
      message: message,
    });
  }
});

console.log("[TrueProtect] Service worker initialized");
