/**
 * True Protection by Jag - Background Service Worker
 * Handles URL reputation checking, download scanning, phishing detection,
 * cryptojacking blocking, and communication with the True Protection daemon.
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

// ---- Initialization -------------------------------------------------------

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("[TrueProtect] Extension installed/updated:", details.reason);

  await blocklist.init();
  await loadSettings();
  await resetDailyStatsIfNeeded();

  // Set up periodic alarms
  chrome.alarms.create("blocklist-update", { periodInMinutes: 30 });
  chrome.alarms.create("stats-reset-check", { periodInMinutes: 60 });
  chrome.alarms.create("daemon-heartbeat", { periodInMinutes: 5 });

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
      message: "Web protection is now active. You are protected against phishing, malware, and cryptojacking.",
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
    stats.pagesScanned++;
    await saveStats();

    // Run URL analysis on the completed page
    const threats = checkUrl(tab.url);
    if (threats) {
      tabThreats.set(tabId, {
        url: tab.url,
        threats: threats,
        timestamp: Date.now(),
      });
    } else {
      tabThreats.delete(tabId);
    }
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
    // -- Popup requests --
    case "GET_STATUS": {
      const tabId = message.tabId;
      const threatData = tabId ? tabThreats.get(tabId) : null;
      return {
        protectionEnabled,
        protectionLevel,
        daemonConnected,
        jagaiCloudEnabled,
        stats: { ...stats },
        currentTab: threatData || null,
        blocklistStats: blocklist.getStats(),
      };
    }

    case "TOGGLE_PROTECTION": {
      protectionEnabled = !protectionEnabled;
      await chrome.storage.local.set({ protection_enabled: protectionEnabled });
      updateBadge();
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

    // -- Content script reports --
    case "PAGE_SCAN_RESULT": {
      if (!sender.tab) return { received: true };

      const tabId = sender.tab.id;
      const existing = tabThreats.get(tabId) || { url: sender.tab.url, threats: [], timestamp: Date.now() };

      if (message.threats && message.threats.length > 0) {
        existing.threats = [...existing.threats, ...message.threats];
        tabThreats.set(tabId, existing);

        stats.threatsBlocked += message.threats.length;
        message.threats.forEach((t) => {
          if (t.type === "phishing") stats.phishingDetected++;
          if (t.type === "cryptojacking") stats.miningBlocked++;
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
        blocklistStats: blocklist.getStats(),
      };
    }

    case "SAVE_SETTINGS": {
      if (message.settings.protectionLevel) {
        protectionLevel = message.settings.protectionLevel;
        await chrome.storage.local.set({ protection_level: protectionLevel });
      }
      if (typeof message.settings.jagaiCloudEnabled === "boolean") {
        jagaiCloudEnabled = message.settings.jagaiCloudEnabled;
        await chrome.storage.local.set({ jagai_cloud_enabled: jagaiCloudEnabled });
      }
      if (message.settings.notificationPrefs) {
        await chrome.storage.local.set({ notification_prefs: message.settings.notificationPrefs });
      }
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

    default:
      console.warn("[TrueProtect] Unknown message type:", message.type);
      return { error: "Unknown message type" };
  }
}

// ---- Account / Auth (tpjsecurity.com Sanctum) -----------------------------

const API_BASE = "https://tpjsecurity.com/api/v1";

/**
 * Authenticate against tpjsecurity.com Sanctum API.
 * Stores the Bearer token and user info in chrome.storage.local.
 */
async function handleAccountLogin(email, password) {
  try {
    const resp = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({ email, password }),
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

    const accountData = {
      auth_token: token,
      user: data.user || {},
      license_tier: data.user?.license_tier || data.license_tier || "free",
      logged_in_at: Date.now(),
    };

    await chrome.storage.local.set({ tpj_account: accountData });

    // Gate JagAI features behind Pro
    if (accountData.license_tier === "pro") {
      jagaiCloudEnabled = true;
      await chrome.storage.local.set({ jagai_cloud_enabled: true });
    }

    return {
      success: true,
      user: accountData.user,
      license_tier: accountData.license_tier,
    };
  } catch (err) {
    console.error("[TrueProtect] Login error:", err);
    return { success: false, error: "Network error - could not reach server" };
  }
}

/**
 * Log out: clear stored token and user data.
 */
async function handleAccountLogout() {
  try {
    const stored = await chrome.storage.local.get("tpj_account");
    const token = stored.tpj_account?.auth_token;

    // Attempt server-side logout (best-effort)
    if (token) {
      fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Accept": "application/json",
        },
      }).catch(() => {});
    }
  } catch {}

  await chrome.storage.local.remove("tpj_account");
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
    const stored = await chrome.storage.local.get("tpj_account");
    const token = stored.tpj_account?.auth_token;
    if (!token) {
      return { success: false, error: "Not logged in" };
    }

    const resp = await fetch(`${API_BASE}/signatures/latest`, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/json",
      },
    });

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
