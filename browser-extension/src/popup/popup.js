/**
 * True Protection by Jag - Popup Logic
 * Handles popup UI state, user interactions, account login/logout,
 * license tier gating, auth gating, and communication with the
 * background service worker.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // ---- Element References -------------------------------------------------

  const statusBanner = document.getElementById("status-banner");
  const statusLabel = document.getElementById("status-label");
  const statusDetail = document.getElementById("status-detail");
  const iconSafe = document.getElementById("icon-safe");
  const iconWarning = document.getElementById("icon-warning");
  const iconBlocked = document.getElementById("icon-blocked");
  const iconDisabled = document.getElementById("icon-disabled");
  const threatDetails = document.getElementById("threat-details");
  const threatList = document.getElementById("threat-list");
  const daemonDot = document.getElementById("daemon-dot");

  const statScanned = document.getElementById("stat-scanned");
  const statBlocked = document.getElementById("stat-blocked");
  const statPhishing = document.getElementById("stat-phishing");

  const protectionToggle = document.getElementById("protection-toggle");
  const levelBadge = document.getElementById("level-badge");

  const btnReport = document.getElementById("btn-report");
  const btnDashboard = document.getElementById("btn-dashboard");
  const btnOptions = document.getElementById("btn-options");

  // Account elements
  const accountLoggedOut = document.getElementById("account-logged-out");
  const accountLoggedIn = document.getElementById("account-logged-in");
  const loginForm = document.getElementById("login-form");
  const loginEmail = document.getElementById("login-email");
  const loginPassword = document.getElementById("login-password");
  const loginError = document.getElementById("login-error");
  const btnLogin = document.getElementById("btn-login");
  const btnLogout = document.getElementById("btn-logout");
  const accountName = document.getElementById("account-name");
  const accountTier = document.getElementById("account-tier");
  const proSection = document.getElementById("pro-section");

  // Auth-gated sections
  const loginRequiredSection = document.getElementById("login-required-section");
  const pageStatusSection = document.getElementById("page-status-section");
  const statsSection = document.querySelector(".stats-section");
  const toggleSection = document.querySelector(".toggle-section");
  const actionsSection = document.querySelector(".actions-section");
  const linkRegister = document.getElementById("link-register");

  // ---- Fetch Status -------------------------------------------------------

  let currentTabId = null;
  let currentTabUrl = "";

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      currentTabId = tab.id;
      currentTabUrl = tab.url || "";
    }
  } catch (err) {
    console.error("[TrueProtect Popup] Failed to get current tab:", err);
  }

  async function fetchStatus() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "GET_STATUS",
        tabId: currentTabId,
      });

      if (!response) return;

      updateProtectionState(response.protectionEnabled);
      updateDaemonStatus(response.daemonConnected);
      updateStats(response.stats);
      updateProtectionLevel(response.protectionLevel);
      updatePageStatus(response);
    } catch (err) {
      console.error("[TrueProtect Popup] Failed to fetch status:", err);
      setStatus("disabled", "Error", "Could not connect to extension");
    }
  }

  // ---- Account UI ---------------------------------------------------------

  /** Track whether the user is currently authenticated */
  let isLoggedIn = false;

  async function checkAccountStatus() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "ACCOUNT_STATUS" });
      if (response && response.loggedIn) {
        showLoggedInState(response.user, response.license_tier);
      } else {
        showLoggedOutState();
      }
    } catch {
      showLoggedOutState();
    }
  }

  /**
   * Map subscription tier strings to display labels.
   */
  function tierLabel(tier) {
    const labels = {
      free: "Free",
      pro: "Pro",
      enterprise: "Enterprise",
      business: "Business",
    };
    return labels[tier] || "Free";
  }

  function showLoggedInState(user, tier) {
    isLoggedIn = true;
    accountLoggedOut.classList.add("hidden");
    accountLoggedIn.classList.remove("hidden");

    // Show user name with "Welcome, " prefix - fall back to email
    const displayName = user?.name || user?.email || "Account";
    accountName.textContent = "Welcome, " + displayName.split(" ")[0];

    // Tier badge
    accountTier.textContent = tierLabel(tier);
    accountTier.className = "account-tier tier-" + (tier || "free");

    // Show or hide JagAI Pro section for paid tiers
    const isPaid = tier === "pro" || tier === "enterprise";
    if (isPaid) {
      proSection.classList.remove("hidden");
    } else {
      proSection.classList.add("hidden");
    }

    // Show protection features, hide login-required notice
    loginRequiredSection.classList.add("hidden");
    pageStatusSection.classList.remove("hidden");
    if (statsSection) statsSection.classList.remove("hidden");
    if (toggleSection) toggleSection.classList.remove("hidden");
    if (actionsSection) actionsSection.classList.remove("hidden");
    protectionToggle.disabled = false;
  }

  function showLoggedOutState() {
    isLoggedIn = false;
    accountLoggedOut.classList.remove("hidden");
    accountLoggedIn.classList.add("hidden");
    proSection.classList.add("hidden");

    // Hide all protection features, show login-required notice
    loginRequiredSection.classList.remove("hidden");
    pageStatusSection.classList.add("hidden");
    if (statsSection) statsSection.classList.add("hidden");
    if (toggleSection) toggleSection.classList.add("hidden");
    if (actionsSection) actionsSection.classList.add("hidden");
    protectionToggle.disabled = true;
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    loginError.classList.add("hidden");
    btnLogin.disabled = true;
    btnLogin.textContent = "...";

    try {
      const response = await chrome.runtime.sendMessage({
        type: "ACCOUNT_LOGIN",
        email: loginEmail.value.trim(),
        password: loginPassword.value,
      });

      if (response && response.success) {
        loginEmail.value = "";
        loginPassword.value = "";
        showLoggedInState(response.user, response.license_tier);
        // Refresh status now that we are authenticated
        await fetchStatus();
      } else {
        loginError.textContent = response?.error || "Login failed";
        loginError.classList.remove("hidden");
      }
    } catch (err) {
      loginError.textContent = "Could not connect to server";
      loginError.classList.remove("hidden");
    }

    btnLogin.disabled = false;
    btnLogin.textContent = "Log In";
  });

  btnLogout.addEventListener("click", async () => {
    try {
      await chrome.runtime.sendMessage({ type: "ACCOUNT_LOGOUT" });
    } catch {}
    showLoggedOutState();
  });

  linkRegister.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: "https://tpjsecurity.com/register" });
    window.close();
  });

  // ---- UI Update Functions ------------------------------------------------

  function updateProtectionState(enabled) {
    protectionToggle.checked = enabled;
  }

  function updateDaemonStatus(connected) {
    daemonDot.className = "status-dot " + (connected ? "connected" : "disconnected");
    daemonDot.title = connected ? "Daemon connected" : "Daemon not connected";
  }

  function updateStats(stats) {
    if (!stats) return;
    statScanned.textContent = formatNumber(stats.pagesScanned || 0);
    statBlocked.textContent = formatNumber(stats.threatsBlocked || 0);
    statPhishing.textContent = formatNumber(stats.phishingDetected || 0);
  }

  function updateProtectionLevel(level) {
    const labels = {
      strict: "Strict",
      balanced: "Balanced",
      minimal: "Minimal",
    };
    levelBadge.textContent = labels[level] || "Balanced";
    levelBadge.className = "level-badge " + (level || "balanced");
  }

  function updatePageStatus(response) {
    if (!response.protectionEnabled) {
      setStatus("disabled", "Protection Disabled", "Click toggle to re-enable");
      return;
    }

    // Check if current tab is a browser internal page
    if (
      currentTabUrl.startsWith("chrome://") ||
      currentTabUrl.startsWith("chrome-extension://") ||
      currentTabUrl.startsWith("about:") ||
      currentTabUrl.startsWith("edge://") ||
      currentTabUrl.startsWith("brave://") ||
      currentTabUrl.startsWith("moz-extension://")
    ) {
      setStatus("safe", "Browser Page", "Internal pages are not scanned");
      return;
    }

    const tabData = response.currentTab;
    if (!tabData || !tabData.threats || tabData.threats.length === 0) {
      setStatus("safe", "Page is Safe", "No threats detected on this page");
      return;
    }

    const hasHighSeverity = tabData.threats.some((t) => t.severity === "high");
    if (hasHighSeverity) {
      setStatus(
        "blocked",
        "Threats Detected",
        `${tabData.threats.length} threat(s) found`
      );
    } else {
      setStatus(
        "warning",
        "Warnings",
        `${tabData.threats.length} suspicious item(s) found`
      );
    }

    showThreats(tabData.threats);
  }

  function setStatus(type, label, detail) {
    // Reset all icons
    iconSafe.classList.add("hidden");
    iconWarning.classList.add("hidden");
    iconBlocked.classList.add("hidden");
    iconDisabled.classList.add("hidden");

    // Reset banner classes
    statusBanner.className = "status-banner " + type;

    switch (type) {
      case "safe":
        iconSafe.classList.remove("hidden");
        break;
      case "warning":
        iconWarning.classList.remove("hidden");
        break;
      case "blocked":
        iconBlocked.classList.remove("hidden");
        break;
      case "disabled":
        iconDisabled.classList.remove("hidden");
        break;
    }

    statusLabel.textContent = label;
    statusDetail.textContent = detail || "";
  }

  function showThreats(threats) {
    if (!threats || threats.length === 0) {
      threatDetails.classList.add("hidden");
      return;
    }

    threatDetails.classList.remove("hidden");
    threatList.innerHTML = "";

    threats.forEach((threat) => {
      const li = document.createElement("li");
      li.className = threat.severity === "high" ? "" : "medium";
      li.textContent = threat.message;
      threatList.appendChild(li);
    });
  }

  // ---- Event Handlers -----------------------------------------------------

  protectionToggle.addEventListener("change", async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: "TOGGLE_PROTECTION" });
      if (response) {
        updateProtectionState(response.protectionEnabled);
        // Re-fetch full status to update UI
        await fetchStatus();
      }
    } catch (err) {
      console.error("[TrueProtect Popup] Toggle failed:", err);
    }
  });

  btnReport.addEventListener("click", async () => {
    if (!currentTabUrl) return;

    try {
      const response = await chrome.runtime.sendMessage({
        type: "REPORT_FALSE_POSITIVE",
        url: currentTabUrl,
        reason: "User reported via popup",
      });

      if (response && response.success) {
        btnReport.textContent = "Reported!";
        btnReport.disabled = true;
        setTimeout(() => {
          btnReport.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
              <line x1="4" y1="22" x2="4" y2="15"/>
            </svg>
            Report False Positive
          `;
          btnReport.disabled = false;
        }, 2000);
      }
    } catch (err) {
      console.error("[TrueProtect Popup] Report failed:", err);
    }
  });

  btnDashboard.addEventListener("click", () => {
    chrome.tabs.create({ url: "https://tpjsecurity.com/dashboard" });
    window.close();
  });

  btnOptions.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
    window.close();
  });

  // ---- History Panel -------------------------------------------------------

  const statsSection = document.getElementById("stats-section");
  const historySection = document.getElementById("history-section");
  const historyList = document.getElementById("history-list");
  const historyEmpty = document.getElementById("history-empty");
  const historyClose = document.getElementById("history-close");
  const historyTabs = document.querySelectorAll(".history-tab");
  let currentHistoryFilter = "all";

  if (statsSection) {
    statsSection.addEventListener("click", (e) => {
      const filter = e.target.closest("[data-filter]")?.dataset.filter || "all";
      openHistory(filter);
    });
  }

  if (historyClose) {
    historyClose.addEventListener("click", () => {
      historySection.classList.add("hidden");
      statsSection.classList.remove("hidden");
    });
  }

  historyTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      historyTabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      currentHistoryFilter = tab.dataset.filter;
      loadHistory(currentHistoryFilter);
    });
  });

  async function openHistory(filter) {
    currentHistoryFilter = filter;
    historyTabs.forEach((t) => {
      t.classList.toggle("active", t.dataset.filter === filter);
    });
    statsSection.classList.add("hidden");
    historySection.classList.remove("hidden");
    await loadHistory(filter);
  }

  async function loadHistory(filter) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "GET_HISTORY",
        filter: filter,
        limit: 50,
      });

      renderHistory(response.history || []);
    } catch (err) {
      console.error("[TrueProtect Popup] Failed to load history:", err);
    }
  }

  function renderHistory(entries) {
    // Remove old items
    const old = historyList.querySelectorAll(".history-item");
    old.forEach((el) => el.remove());

    if (!entries || entries.length === 0) {
      historyEmpty.classList.remove("hidden");
      return;
    }
    historyEmpty.classList.add("hidden");

    entries.forEach((entry) => {
      const item = document.createElement("div");
      item.className = "history-item";
      if (entry.type !== "scan") item.classList.add("history-threat");

      const dot = document.createElement("span");
      dot.className = "history-dot";
      if (entry.type === "scan") dot.classList.add("dot-safe");
      else if (entry.severity === "high") dot.classList.add("dot-danger");
      else dot.classList.add("dot-warning");

      const info = document.createElement("div");
      info.className = "history-info";

      const urlEl = document.createElement("span");
      urlEl.className = "history-url";
      try {
        const u = new URL(entry.url);
        urlEl.textContent = u.hostname + (u.pathname !== "/" ? u.pathname.slice(0, 40) : "");
      } catch {
        urlEl.textContent = entry.url?.slice(0, 50) || "Unknown";
      }
      urlEl.title = entry.url;

      const meta = document.createElement("span");
      meta.className = "history-meta";
      const ago = formatTimeAgo(entry.timestamp);
      if (entry.type === "scan") {
        meta.textContent = ago;
      } else {
        meta.textContent = (entry.message || entry.type) + " - " + ago;
      }

      info.appendChild(urlEl);
      info.appendChild(meta);

      item.appendChild(dot);
      item.appendChild(info);
      historyList.appendChild(item);
    });
  }

  function formatTimeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    return Math.floor(hrs / 24) + "d ago";
  }

  // ---- Helpers ------------------------------------------------------------

  function formatNumber(num) {
    if (num >= 10000) return (num / 1000).toFixed(1) + "k";
    if (num >= 1000) return num.toLocaleString();
    return String(num);
  }

  // ---- Initialize ---------------------------------------------------------

  statusBanner.parentElement.classList.add("loading");

  // Check account status first to determine auth gating
  await checkAccountStatus();

  // Only fetch protection status if the user is logged in
  if (isLoggedIn) {
    await fetchStatus();
  }

  statusBanner.parentElement.classList.remove("loading");
});
