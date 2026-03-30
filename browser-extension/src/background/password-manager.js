/**
 * True Protection by Jag - Browser Extension Password Manager
 * Detects login forms, offers credential saving after login, auto-fills
 * known sites, generates passwords, and communicates with the True
 * Protection daemon for vault access.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 * Powered by JagAI.
 */

// ─── State ──────────────────────────────────────────────────────────────────

/** @type {Map<number, TabCredentialState>} Per-tab credential tracking */
const tabCredentials = new Map();

/** @type {Map<string, CachedCredential[]>} Domain -> cached credentials */
const credentialCache = new Map();

/** @type {boolean} Whether the daemon vault is unlocked */
let vaultUnlocked = false;

/** @type {chrome.runtime.Port|null} Native messaging port to daemon */
let daemonPort = null;

/** @type {boolean} Whether daemon is connected */
let daemonConnected = false;

/** @type {Object} Extension password manager settings */
let pmSettings = {
  autoFillEnabled: true,
  autoSaveEnabled: true,
  showGeneratorPopup: true,
  notifyOnBreach: true,
  clipboardClearSec: 30,
  matchSubdomains: true,
};

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} CachedCredential
 * @property {string} id - Entry UUID from the vault
 * @property {string} title - Display name
 * @property {string} url - Site URL
 * @property {string} username - Login username
 * @property {string} [password] - Password (only populated on fill request)
 * @property {string} [totpCode] - Current TOTP code if available
 * @property {string[]} matchingDomains - Domains this credential matches
 * @property {string} breachStatus - "unknown"|"safe"|"compromised"
 */

/**
 * @typedef {Object} TabCredentialState
 * @property {string} url - Current page URL
 * @property {boolean} hasLoginForm - Whether a login form was detected
 * @property {string[]} detectedFields - Field names found
 * @property {CachedCredential[]} matchedCredentials - Matching vault entries
 * @property {Object|null} pendingSave - Credentials pending save after login
 * @property {number} lastDetection - Timestamp of last form detection
 */

/**
 * @typedef {Object} GeneratedPassword
 * @property {string} password - The generated password
 * @property {number} entropy - Entropy in bits
 * @property {string} strength - "very_weak"|"weak"|"fair"|"strong"|"very_strong"
 */

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize password manager extension module.
 * Called from the main service worker on startup.
 */
export function initPasswordManager() {
  loadSettings();
  connectToDaemon();

  // Set up periodic tasks
  chrome.alarms.create("pm-cache-refresh", { periodInMinutes: 15 });
  chrome.alarms.create("pm-clipboard-check", { periodInMinutes: 1 });

  console.log("[TrueProtect:PM] Password manager module initialized");
}

/**
 * Load password manager settings from storage.
 */
async function loadSettings() {
  try {
    const stored = await chrome.storage.local.get("pm_settings");
    if (stored.pm_settings) {
      pmSettings = { ...pmSettings, ...stored.pm_settings };
    }
  } catch (err) {
    console.error("[TrueProtect:PM] Failed to load settings:", err);
  }
}

/**
 * Save password manager settings to storage.
 */
async function saveSettings() {
  try {
    await chrome.storage.local.set({ pm_settings: pmSettings });
  } catch (err) {
    console.error("[TrueProtect:PM] Failed to save settings:", err);
  }
}

// ─── Daemon Communication ───────────────────────────────────────────────────

/**
 * Connect to the True Protection daemon via native messaging
 * for vault access operations.
 */
function connectToDaemon() {
  try {
    daemonPort = chrome.runtime.connectNative("com.jagjourney.trueprotection");

    daemonPort.onMessage.addListener((message) => {
      handleDaemonMessage(message);
    });

    daemonPort.onDisconnect.addListener(() => {
      console.log(
        "[TrueProtect:PM] Daemon disconnected:",
        chrome.runtime.lastError?.message
      );
      daemonConnected = false;
      vaultUnlocked = false;
      daemonPort = null;
      credentialCache.clear();

      // Retry in 30 seconds
      setTimeout(connectToDaemon, 30000);
    });

    daemonConnected = true;

    // Request vault status
    sendToDaemon({ type: "PM_VAULT_STATUS" });

    console.log("[TrueProtect:PM] Connected to daemon for vault access");
  } catch (err) {
    console.log("[TrueProtect:PM] Daemon not available:", err.message);
    daemonConnected = false;
    daemonPort = null;
  }
}

/**
 * Send a message to the daemon.
 * @param {Object} message
 */
function sendToDaemon(message) {
  if (daemonPort && daemonConnected) {
    try {
      daemonPort.postMessage(message);
    } catch (err) {
      console.error("[TrueProtect:PM] Send to daemon failed:", err);
      daemonConnected = false;
    }
  }
}

/**
 * Handle incoming messages from the daemon.
 * @param {Object} message
 */
function handleDaemonMessage(message) {
  switch (message.type) {
    case "PM_VAULT_STATUS": {
      vaultUnlocked = message.data?.unlocked ?? false;
      if (vaultUnlocked) {
        // Pre-cache credentials for fast auto-fill
        sendToDaemon({ type: "PM_LIST_CREDENTIALS" });
      }
      break;
    }

    case "PM_CREDENTIALS_LIST": {
      // Populate credential cache from daemon response
      credentialCache.clear();
      const entries = message.data?.entries ?? [];

      for (const entry of entries) {
        const domains = entry.matchingDomains || [];
        for (const domain of domains) {
          const baseDomain = extractBaseDomain(domain.replace("*.", ""));
          if (!credentialCache.has(baseDomain)) {
            credentialCache.set(baseDomain, []);
          }
          credentialCache.get(baseDomain).push({
            id: entry.id,
            title: entry.title,
            url: entry.url,
            username: entry.username,
            matchingDomains: entry.matchingDomains,
            breachStatus: entry.breachStatus || "unknown",
          });
        }
      }

      console.log(
        `[TrueProtect:PM] Cached credentials for ${credentialCache.size} domains`
      );
      break;
    }

    case "PM_FILL_RESPONSE": {
      // Daemon responded with decrypted credential for auto-fill
      const { tabId, entryId, username, password, totpCode } =
        message.data || {};
      if (tabId && username !== undefined) {
        chrome.tabs.sendMessage(tabId, {
          type: "PM_DO_FILL",
          username,
          password,
          totpCode,
          entryId,
        }).catch(() => {});
      }
      break;
    }

    case "PM_SAVE_RESULT": {
      const { success, entryId, tabId } = message.data || {};
      if (success && tabId) {
        chrome.notifications.create(`pm-save-${Date.now()}`, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
          title: "Password Saved - True Protection",
          message: "Your credentials have been securely saved to the vault.",
        });

        // Refresh credential cache
        sendToDaemon({ type: "PM_LIST_CREDENTIALS" });
      }
      break;
    }

    case "PM_GENERATED_PASSWORD": {
      // Forward generated password to the requesting tab
      const { tabId: genTabId, password: genPassword, entropy } =
        message.data || {};
      if (genTabId) {
        chrome.tabs.sendMessage(genTabId, {
          type: "PM_GENERATED_PASSWORD",
          password: genPassword,
          entropy,
        }).catch(() => {});
      }
      break;
    }

    case "PM_BREACH_ALERT": {
      // Daemon detected a breached credential for the current site
      if (pmSettings.notifyOnBreach && message.data) {
        chrome.notifications.create(`pm-breach-${Date.now()}`, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
          title: "Breached Password Detected - True Protection",
          message: `Your password for ${message.data.site} was found in a data breach. Change it immediately.`,
        });
      }
      break;
    }

    default:
      // Unknown PM message type - ignore
      break;
  }
}

// ─── Login Form Detection ───────────────────────────────────────────────────

/**
 * Handle form detection reports from the content script.
 * Called when the content script detects a login form on a page.
 *
 * @param {Object} data - Detection report from content script
 * @param {number} tabId - Tab ID where the form was detected
 */
export function handleFormDetected(data, tabId) {
  if (!pmSettings.autoFillEnabled) return;

  const { url, fields, formId, hasPasswordField, hasUsernameField } = data;
  if (!hasPasswordField) return; // Not a login form

  // Find matching credentials
  const matches = findMatchingCredentials(url);

  // Update tab state
  tabCredentials.set(tabId, {
    url,
    hasLoginForm: true,
    detectedFields: fields || [],
    matchedCredentials: matches,
    pendingSave: null,
    lastDetection: Date.now(),
  });

  // Notify the content script about available credentials
  if (matches.length > 0) {
    chrome.tabs
      .sendMessage(tabId, {
        type: "PM_CREDENTIALS_AVAILABLE",
        count: matches.length,
        entries: matches.map((m) => ({
          id: m.id,
          username: m.username,
          title: m.title,
        })),
        hasMultiple: matches.length > 1,
      })
      .catch(() => {});
  }

  // Check for breach alerts
  if (pmSettings.notifyOnBreach) {
    const breached = matches.filter((m) => m.breachStatus === "compromised");
    if (breached.length > 0) {
      chrome.tabs
        .sendMessage(tabId, {
          type: "PM_BREACH_WARNING",
          entries: breached.map((m) => ({
            id: m.id,
            username: m.username,
            title: m.title,
          })),
        })
        .catch(() => {});
    }
  }
}

/**
 * Handle login submission reports from the content script.
 * Called after the user submits a login form, offering to save credentials.
 *
 * @param {Object} data - Submission data from content script
 * @param {number} tabId - Tab ID where the login was submitted
 */
export function handleLoginSubmitted(data, tabId) {
  if (!pmSettings.autoSaveEnabled) return;

  const { url, username, password, formAction } = data;
  if (!username || !password) return;

  // Check if credentials already exist in vault
  const existing = findMatchingCredentials(url);
  const alreadySaved = existing.some(
    (cred) =>
      cred.username === username
  );

  if (alreadySaved) {
    // Check if password changed (would need to compare with daemon)
    sendToDaemon({
      type: "PM_CHECK_PASSWORD_CHANGE",
      data: { url, username, tabId },
    });
    return;
  }

  // Store pending save and prompt user
  const tabState = tabCredentials.get(tabId) || {};
  tabState.pendingSave = { url, username, password, formAction };
  tabCredentials.set(tabId, tabState);

  // Show save prompt via content script
  const domain = extractDomain(url);
  chrome.tabs
    .sendMessage(tabId, {
      type: "PM_OFFER_SAVE",
      domain,
      username,
    })
    .catch(() => {});
}

// ─── Auto-fill ──────────────────────────────────────────────────────────────

/**
 * Request auto-fill for a specific tab.
 * Asks the daemon to decrypt the credential and sends it to the content script.
 *
 * @param {number} tabId - Tab to fill
 * @param {string} entryId - Vault entry ID to fill
 */
export function requestAutoFill(tabId, entryId) {
  if (!vaultUnlocked || !daemonConnected) {
    // Prompt user to unlock vault
    chrome.tabs
      .sendMessage(tabId, {
        type: "PM_VAULT_LOCKED",
        message: "Unlock your vault to auto-fill credentials.",
      })
      .catch(() => {});
    return;
  }

  // Request decrypted credentials from daemon
  sendToDaemon({
    type: "PM_FILL_REQUEST",
    data: { tabId, entryId },
  });

  // Record usage
  sendToDaemon({
    type: "PM_RECORD_USAGE",
    data: { entryId },
  });
}

/**
 * Auto-fill the best matching credential for a URL.
 *
 * @param {number} tabId - Tab to fill
 * @param {string} url - Page URL
 */
export function autoFillBestMatch(tabId, url) {
  const matches = findMatchingCredentials(url);
  if (matches.length === 0) return;

  // Use the first (best scored) match
  requestAutoFill(tabId, matches[0].id);
}

// ─── Credential Matching ────────────────────────────────────────────────────

/**
 * Find credentials matching a given URL using domain and subdomain matching.
 *
 * @param {string} url - Page URL to match against
 * @returns {CachedCredential[]} Matching credentials sorted by relevance
 */
function findMatchingCredentials(url) {
  if (!url) return [];

  const domain = extractDomain(url);
  const baseDomain = extractBaseDomain(domain);
  if (!baseDomain) return [];

  /** @type {Array<{cred: CachedCredential, score: number}>} */
  const scored = [];

  // Check exact domain match
  const exact = credentialCache.get(domain) || [];
  for (const cred of exact) {
    scored.push({ cred, score: 100 });
  }

  // Check base domain match (subdomain support)
  if (pmSettings.matchSubdomains && baseDomain !== domain) {
    const base = credentialCache.get(baseDomain) || [];
    for (const cred of base) {
      // Avoid duplicates
      if (!scored.some((s) => s.cred.id === cred.id)) {
        scored.push({ cred, score: 70 });
      }
    }
  }

  // Check wildcard entries from all cached domains
  for (const [cachedDomain, creds] of credentialCache) {
    if (cachedDomain === domain || cachedDomain === baseDomain) continue;

    for (const cred of creds) {
      if (scored.some((s) => s.cred.id === cred.id)) continue;

      // Check if any matching domain pattern matches the page
      for (const pattern of cred.matchingDomains || []) {
        if (domainMatchesPattern(domain, pattern)) {
          scored.push({ cred, score: 50 });
          break;
        }
      }
    }
  }

  // Sort by score descending
  scored.sort((a, b) => b.score - a.score);
  return scored.map((s) => s.cred);
}

/**
 * Check if a domain matches a pattern (supports wildcard *.example.com).
 *
 * @param {string} domain - Page domain to check
 * @param {string} pattern - Pattern to match against
 * @returns {boolean}
 */
function domainMatchesPattern(domain, pattern) {
  if (domain === pattern) return true;

  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }

  return false;
}

// ─── Password Generation ────────────────────────────────────────────────────

/**
 * Generate a password and send it to the requesting tab.
 *
 * @param {number} tabId - Tab requesting the password
 * @param {Object} [options] - Generation options
 * @param {number} [options.length=20] - Password length
 * @param {boolean} [options.uppercase=true] - Include uppercase
 * @param {boolean} [options.lowercase=true] - Include lowercase
 * @param {boolean} [options.digits=true] - Include digits
 * @param {boolean} [options.symbols=true] - Include symbols
 */
export function generatePassword(tabId, options = {}) {
  if (daemonConnected) {
    // Request generation from daemon (uses CSPRNG)
    sendToDaemon({
      type: "PM_GENERATE_PASSWORD",
      data: { tabId, ...options },
    });
  } else {
    // Fallback: generate locally using Web Crypto API
    const generated = generatePasswordLocal(options);

    chrome.tabs
      .sendMessage(tabId, {
        type: "PM_GENERATED_PASSWORD",
        ...generated,
      })
      .catch(() => {});
  }
}

/**
 * Generate a password locally as a fallback when daemon is unavailable.
 * Uses crypto.getRandomValues() for cryptographic security.
 *
 * @param {Object} options - Generation options
 * @returns {GeneratedPassword}
 */
function generatePasswordLocal(options = {}) {
  const length = options.length || 20;
  const useUpper = options.uppercase !== false;
  const useLower = options.lowercase !== false;
  const useDigits = options.digits !== false;
  const useSymbols = options.symbols !== false;

  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`";

  let pool = "";
  if (useUpper) pool += uppercase;
  if (useLower) pool += lowercase;
  if (useDigits) pool += digits;
  if (useSymbols) pool += symbols;
  if (!pool) pool = lowercase + digits;

  // Generate random bytes
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);

  let password = "";
  for (let i = 0; i < length; i++) {
    password += pool[randomBytes[i] % pool.length];
  }

  // Ensure at least one of each requested type
  const ensureChar = (charset) => {
    if (!charset) return;
    const hasChar = [...password].some((c) => charset.includes(c));
    if (!hasChar) {
      const posBytes = new Uint8Array(2);
      crypto.getRandomValues(posBytes);
      const pos = posBytes[0] % password.length;
      const charIdx = posBytes[1] % charset.length;
      password =
        password.substring(0, pos) +
        charset[charIdx] +
        password.substring(pos + 1);
    }
  };

  if (useUpper) ensureChar(uppercase);
  if (useLower) ensureChar(lowercase);
  if (useDigits) ensureChar(digits);
  if (useSymbols) ensureChar(symbols);

  // Calculate entropy
  const poolSize = pool.length;
  const entropy = Math.log2(poolSize) * length;

  let strength;
  if (entropy < 28) strength = "very_weak";
  else if (entropy < 36) strength = "weak";
  else if (entropy < 60) strength = "fair";
  else if (entropy < 128) strength = "strong";
  else strength = "very_strong";

  return { password, entropy: Math.round(entropy), strength };
}

// ─── Credential Save ────────────────────────────────────────────────────────

/**
 * Save pending credentials to the vault via the daemon.
 *
 * @param {number} tabId - Tab with the pending save
 */
export function savePendingCredentials(tabId) {
  const tabState = tabCredentials.get(tabId);
  if (!tabState?.pendingSave) return;

  const { url, username, password, formAction } = tabState.pendingSave;

  if (!vaultUnlocked || !daemonConnected) {
    // Notify user to unlock vault first
    chrome.tabs
      .sendMessage(tabId, {
        type: "PM_VAULT_LOCKED",
        message: "Unlock your vault to save credentials.",
      })
      .catch(() => {});
    return;
  }

  const domain = extractDomain(url);

  sendToDaemon({
    type: "PM_SAVE_CREDENTIAL",
    data: {
      tabId,
      title: domain,
      url,
      username,
      password,
      matchingDomains: [domain, "*." + extractBaseDomain(domain)],
    },
  });

  // Clear pending save
  tabState.pendingSave = null;
}

/**
 * Dismiss the save prompt for a tab.
 *
 * @param {number} tabId
 */
export function dismissSavePrompt(tabId) {
  const tabState = tabCredentials.get(tabId);
  if (tabState) {
    tabState.pendingSave = null;
  }
}

// ─── Clipboard Management ───────────────────────────────────────────────────

/** @type {number|null} Timer for clipboard clear */
let clipboardClearTimer = null;

/**
 * Copy a value to clipboard and schedule automatic clearing.
 *
 * @param {string} value - Value to copy
 */
export function copyToClipboard(value) {
  // Use offscreen document for clipboard access in MV3
  // The content script handles the actual clipboard operation.

  // Schedule clear
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(() => {
    clearClipboard();
    clipboardClearTimer = null;
  }, pmSettings.clipboardClearSec * 1000);
}

/**
 * Clear the clipboard by writing an empty string.
 */
function clearClipboard() {
  // Send to all active tabs to clear clipboard
  chrome.tabs.query({ active: true }, (tabs) => {
    for (const tab of tabs) {
      chrome.tabs
        .sendMessage(tab.id, { type: "PM_CLEAR_CLIPBOARD" })
        .catch(() => {});
    }
  });
}

// ─── Domain Utilities ───────────────────────────────────────────────────────

/**
 * Extract the hostname from a URL.
 *
 * @param {string} url - Full URL
 * @returns {string} Hostname (e.g., "www.example.com")
 */
function extractDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * Extract the base (registrable) domain from a hostname.
 * Simple implementation - in production use a public suffix list.
 *
 * @param {string} domain - Hostname (e.g., "sub.example.com")
 * @returns {string} Base domain (e.g., "example.com")
 */
function extractBaseDomain(domain) {
  const parts = domain.split(".");
  if (parts.length <= 2) return domain;

  // Handle common multi-part TLDs
  const multiPartTlds = [
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
    "com.au", "com.br", "com.cn", "com.mx", "com.tw",
    "org.uk", "net.au", "ac.uk", "gov.uk",
  ];

  const lastTwo = parts.slice(-2).join(".");
  if (multiPartTlds.includes(lastTwo)) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

// ─── Message Handling ───────────────────────────────────────────────────────

/**
 * Handle messages from popup, content scripts, and options page.
 * Exported to be registered in the main service worker.
 *
 * @param {Object} message
 * @param {chrome.runtime.MessageSender} sender
 * @returns {Promise<Object>} Response
 */
export async function handlePasswordManagerMessage(message, sender) {
  switch (message.type) {
    // ── Content script messages ──

    case "PM_FORM_DETECTED": {
      if (sender.tab) {
        handleFormDetected(message.data, sender.tab.id);
      }
      return { received: true };
    }

    case "PM_LOGIN_SUBMITTED": {
      if (sender.tab) {
        handleLoginSubmitted(message.data, sender.tab.id);
      }
      return { received: true };
    }

    case "PM_ACCEPT_SAVE": {
      if (sender.tab) {
        savePendingCredentials(sender.tab.id);
      }
      return { received: true };
    }

    case "PM_DISMISS_SAVE": {
      if (sender.tab) {
        dismissSavePrompt(sender.tab.id);
      }
      return { received: true };
    }

    case "PM_REQUEST_FILL": {
      const tabId = message.tabId || sender.tab?.id;
      if (tabId && message.entryId) {
        requestAutoFill(tabId, message.entryId);
      }
      return { received: true };
    }

    case "PM_REQUEST_AUTOFILL": {
      const tabId = message.tabId || sender.tab?.id;
      if (tabId) {
        const tab = await chrome.tabs.get(tabId);
        autoFillBestMatch(tabId, tab.url);
      }
      return { received: true };
    }

    // ── Popup messages ──

    case "PM_GET_STATUS": {
      const tabId = message.tabId;
      const tabState = tabId ? tabCredentials.get(tabId) : null;
      return {
        vaultUnlocked,
        daemonConnected,
        settings: { ...pmSettings },
        currentTab: tabState
          ? {
              hasLoginForm: tabState.hasLoginForm,
              matchCount: tabState.matchedCredentials?.length || 0,
              hasPendingSave: !!tabState.pendingSave,
              credentials: (tabState.matchedCredentials || []).map((c) => ({
                id: c.id,
                username: c.username,
                title: c.title,
                breachStatus: c.breachStatus,
              })),
            }
          : null,
      };
    }

    case "PM_SEARCH_CREDENTIALS": {
      const query = (message.query || "").toLowerCase();
      if (!query) return { results: [] };

      const results = [];
      for (const [domain, creds] of credentialCache) {
        for (const cred of creds) {
          if (
            cred.title?.toLowerCase().includes(query) ||
            cred.username?.toLowerCase().includes(query) ||
            cred.url?.toLowerCase().includes(query) ||
            domain.includes(query)
          ) {
            if (!results.some((r) => r.id === cred.id)) {
              results.push({
                id: cred.id,
                title: cred.title,
                username: cred.username,
                url: cred.url,
                breachStatus: cred.breachStatus,
              });
            }
          }
        }
      }
      return { results: results.slice(0, 20) };
    }

    case "PM_GENERATE": {
      const generated = generatePasswordLocal(message.options || {});
      return generated;
    }

    case "PM_GENERATE_FOR_TAB": {
      const tabId = message.tabId || sender.tab?.id;
      if (tabId) {
        generatePassword(tabId, message.options || {});
      }
      return { received: true };
    }

    case "PM_COPY_PASSWORD": {
      if (message.entryId && daemonConnected) {
        sendToDaemon({
          type: "PM_GET_PASSWORD",
          data: {
            entryId: message.entryId,
            action: "copy",
          },
        });
      }
      return { received: true };
    }

    case "PM_COPY_USERNAME": {
      // Username is in the cache, no daemon call needed
      for (const [, creds] of credentialCache) {
        for (const cred of creds) {
          if (cred.id === message.entryId) {
            return { value: cred.username };
          }
        }
      }
      return { value: null };
    }

    case "PM_UNLOCK_VAULT": {
      if (daemonConnected) {
        sendToDaemon({
          type: "PM_UNLOCK_VAULT",
          data: { password: message.password },
        });
      }
      return { sent: daemonConnected };
    }

    case "PM_LOCK_VAULT": {
      if (daemonConnected) {
        sendToDaemon({ type: "PM_LOCK_VAULT" });
        vaultUnlocked = false;
        credentialCache.clear();
      }
      return { locked: true };
    }

    // ── Settings ──

    case "PM_GET_SETTINGS": {
      return { settings: { ...pmSettings } };
    }

    case "PM_SAVE_SETTINGS": {
      pmSettings = { ...pmSettings, ...message.settings };
      await saveSettings();
      return { success: true };
    }

    default:
      return null; // Not a PM message
  }
}

// ─── Alarm Handling ─────────────────────────────────────────────────────────

/**
 * Handle alarms for periodic tasks.
 * Called from the main service worker alarm handler.
 *
 * @param {string} alarmName
 */
export function handleAlarm(alarmName) {
  switch (alarmName) {
    case "pm-cache-refresh":
      if (vaultUnlocked && daemonConnected) {
        sendToDaemon({ type: "PM_LIST_CREDENTIALS" });
      }
      break;

    case "pm-clipboard-check":
      // Handled by timeout in copyToClipboard
      break;
  }
}

// ─── Tab Lifecycle ──────────────────────────────────────────────────────────

/**
 * Handle tab updates (navigation, etc.).
 *
 * @param {number} tabId
 * @param {Object} changeInfo
 * @param {chrome.tabs.Tab} tab
 */
export function handleTabUpdated(tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" && tab.url) {
    // Reset tab state on navigation
    const oldState = tabCredentials.get(tabId);
    if (oldState && oldState.url !== tab.url) {
      tabCredentials.delete(tabId);
    }

    // Pre-check for matching credentials for this URL
    if (pmSettings.autoFillEnabled) {
      const matches = findMatchingCredentials(tab.url);
      if (matches.length > 0) {
        tabCredentials.set(tabId, {
          url: tab.url,
          hasLoginForm: false, // Will be updated by content script
          detectedFields: [],
          matchedCredentials: matches,
          pendingSave: null,
          lastDetection: 0,
        });
      }
    }
  }
}

/**
 * Handle tab removal (cleanup).
 *
 * @param {number} tabId
 */
export function handleTabRemoved(tabId) {
  tabCredentials.delete(tabId);
}

// ─── Content Script: Login Form Detection Logic ─────────────────────────────
//
// The following functions are designed to be injected into web pages to detect
// login forms. In the extension, these are in the content script
// (page-scanner.js), but the detection logic is documented here.
//
// Detection heuristics:
//   1. Find all <input type="password"> elements on the page
//   2. For each password field, traverse up to find the containing <form>
//   3. Within that form, identify username/email fields by:
//      - Input type: email, text
//      - Name attributes: user, email, login, account, name
//      - ID attributes: user, email, login, account
//      - Autocomplete attributes: username, email
//      - Aria-label containing: email, user, account
//   4. Report the form structure to the background script
//   5. Monitor form submission events to capture credentials
//
// Anti-detection measures:
//   - Only activate on HTTPS pages (never HTTP for security)
//   - Do not read password values until form submission
//   - Use MutationObserver for dynamic forms (SPA login pages)
//   - Respect CSP headers
//

/**
 * Content script injection helper - detect login forms on the current page.
 * This code runs in the content script context.
 *
 * @returns {Object|null} Detection result or null if no login form found
 */
export function detectLoginForms() {
  // Only operate on HTTPS pages
  if (location.protocol !== "https:") return null;

  const passwordFields = document.querySelectorAll('input[type="password"]');
  if (passwordFields.length === 0) return null;

  const results = [];

  for (const pwField of passwordFields) {
    // Find containing form or closest parent with input fields
    const form = pwField.closest("form") || pwField.parentElement;
    if (!form) continue;

    // Find username/email field
    const usernameSelectors = [
      'input[type="email"]',
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[name*="user" i]',
      'input[name*="email" i]',
      'input[name*="login" i]',
      'input[name*="account" i]',
      'input[id*="user" i]',
      'input[id*="email" i]',
      'input[id*="login" i]',
      'input[type="text"]', // Fallback: first text input
    ];

    let usernameField = null;
    for (const selector of usernameSelectors) {
      usernameField = form.querySelector(selector);
      if (usernameField && usernameField !== pwField) break;
    }

    // Collect field info (names only, not values)
    const fields = [];
    const allInputs = form.querySelectorAll("input");
    for (const input of allInputs) {
      if (input.type === "hidden" || input.type === "submit") continue;
      fields.push({
        type: input.type,
        name: input.name || input.id || "",
        autocomplete: input.autocomplete || "",
      });
    }

    results.push({
      formId: form.id || form.action || `form-${results.length}`,
      hasPasswordField: true,
      hasUsernameField: !!usernameField,
      fields: fields.map((f) => f.name).filter(Boolean),
      fieldCount: fields.length,
    });
  }

  if (results.length === 0) return null;

  return {
    url: location.href,
    forms: results,
    hasPasswordField: true,
    hasUsernameField: results.some((r) => r.hasUsernameField),
    fields: results[0]?.fields || [],
    formId: results[0]?.formId || "",
  };
}

console.log("[TrueProtect:PM] Password manager module loaded");
