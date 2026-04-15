/**
 * True Protection by Jag - Options Page Logic
 * Handles settings management, whitelist CRUD, and status display.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // ─── Element References ───────────────────────────────────────────────

  const navLinks = document.querySelectorAll(".nav-link");
  const sections = document.querySelectorAll(".section");

  // Protection level
  const levelRadios = document.querySelectorAll('input[name="protection-level"]');

  // Whitelist
  const whitelistInput = document.getElementById("whitelist-input");
  const btnAddWhitelist = document.getElementById("btn-add-whitelist");
  const whitelistList = document.getElementById("whitelist-list");
  const whitelistEmpty = document.getElementById("whitelist-empty");

  // Custom Blocklist
  const blocklistInput = document.getElementById("blocklist-input");
  const btnAddBlocklist = document.getElementById("btn-add-blocklist");
  const blocklistList = document.getElementById("blocklist-list");
  const blocklistEmpty = document.getElementById("blocklist-empty");

  // Cloud
  const cloudToggle = document.getElementById("cloud-toggle");

  // Notifications
  const notifBlocked = document.getElementById("notif-blocked");
  const notifPhishing = document.getElementById("notif-phishing");
  const notifMining = document.getElementById("notif-mining");
  const notifDownload = document.getElementById("notif-download");

  // Status
  const statusDaemonIndicator = document.getElementById("status-daemon-indicator");
  const statusDaemonText = document.getElementById("status-daemon-text");
  const statusBlocklistText = document.getElementById("status-blocklist-text");
  const statusCloudIndicator = document.getElementById("status-cloud-indicator");
  const statusCloudText = document.getElementById("status-cloud-text");

  const statDomains = document.getElementById("stat-domains");
  const statUrls = document.getElementById("stat-urls");
  const statMining = document.getElementById("stat-mining");
  const statWhitelistCount = document.getElementById("stat-whitelist-count");
  const lastUpdated = document.getElementById("last-updated");

  // Toast
  const toast = document.getElementById("toast");
  const toastMessage = document.getElementById("toast-message");

  // ─── Navigation ───────────────────────────────────────────────────────

  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const sectionId = link.dataset.section;

      navLinks.forEach((l) => l.classList.remove("active"));
      link.classList.add("active");

      sections.forEach((s) => s.classList.remove("active"));
      const target = document.getElementById(`section-${sectionId}`);
      if (target) target.classList.add("active");
    });
  });

  // Handle hash-based navigation
  const hash = window.location.hash.replace("#", "");
  if (hash) {
    const link = document.querySelector(`.nav-link[data-section="${hash}"]`);
    if (link) link.click();
  }

  // ─── Load Settings ────────────────────────────────────────────────────

  async function loadSettings() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
      if (!response) return;

      // Protection level
      const levelRadio = document.querySelector(
        `input[name="protection-level"][value="${response.protectionLevel}"]`
      );
      if (levelRadio) levelRadio.checked = true;

      // Cloud scanning
      cloudToggle.checked = response.jagaiCloudEnabled || false;

      // Notifications
      const prefs = response.notificationPrefs || {};
      notifBlocked.checked = prefs.showBlocked !== false;
      notifPhishing.checked = prefs.showPhishing !== false;
      notifMining.checked = prefs.showMining !== false;
      notifDownload.checked = prefs.showDownload !== false;

      // Daemon status
      updateDaemonStatus(response.daemonConnected);

      // Cloud status
      updateCloudStatus(response.jagaiCloudEnabled);

      // Whitelist
      renderWhitelist(response.whitelist || []);

      // Custom Blocklist
      renderBlocklist(response.customBlocklist || []);

      // Blocklist stats
      updateBlocklistStats(response.blocklistStats);
    } catch (err) {
      console.error("[TrueProtect Options] Failed to load settings:", err);
      showToast("Failed to load settings", "error");
    }
  }

  // ─── Protection Level ─────────────────────────────────────────────────

  levelRadios.forEach((radio) => {
    radio.addEventListener("change", async () => {
      try {
        await chrome.runtime.sendMessage({
          type: "SAVE_SETTINGS",
          settings: { protectionLevel: radio.value },
        });
        showToast(`Protection level set to ${radio.value}`, "success");
      } catch (err) {
        console.error("[TrueProtect Options] Failed to save level:", err);
        showToast("Failed to save protection level", "error");
      }
    });
  });

  // ─── Cloud Toggle ─────────────────────────────────────────────────────

  cloudToggle.addEventListener("change", async () => {
    try {
      await chrome.runtime.sendMessage({
        type: "SAVE_SETTINGS",
        settings: { jagaiCloudEnabled: cloudToggle.checked },
      });
      updateCloudStatus(cloudToggle.checked);
      showToast(
        cloudToggle.checked ? "JagAI cloud scanning enabled" : "JagAI cloud scanning disabled",
        "success"
      );
    } catch (err) {
      console.error("[TrueProtect Options] Failed to save cloud setting:", err);
      showToast("Failed to save cloud setting", "error");
    }
  });

  // ─── Notification Preferences ─────────────────────────────────────────

  const notifToggles = [notifBlocked, notifPhishing, notifMining, notifDownload];
  notifToggles.forEach((toggle) => {
    toggle.addEventListener("change", async () => {
      try {
        await chrome.runtime.sendMessage({
          type: "SAVE_SETTINGS",
          settings: {
            notificationPrefs: {
              showBlocked: notifBlocked.checked,
              showPhishing: notifPhishing.checked,
              showMining: notifMining.checked,
              showDownload: notifDownload.checked,
            },
          },
        });
        showToast("Notification preferences saved", "success");
      } catch (err) {
        console.error("[TrueProtect Options] Failed to save notifications:", err);
        showToast("Failed to save notification preferences", "error");
      }
    });
  });

  // ─── Whitelist Management ─────────────────────────────────────────────

  btnAddWhitelist.addEventListener("click", addWhitelistDomain);
  whitelistInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addWhitelistDomain();
  });

  async function addWhitelistDomain() {
    const domain = whitelistInput.value.trim().toLowerCase();
    if (!domain) return;

    // Basic domain validation
    if (!/^[a-z0-9][a-z0-9\-]*(\.[a-z0-9][a-z0-9\-]*)*\.[a-z]{2,}$/.test(domain)) {
      showToast("Please enter a valid domain name (e.g., example.com)", "error");
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: "ADD_WHITELIST",
        domain: domain,
      });

      if (response && response.success) {
        whitelistInput.value = "";
        renderWhitelist(response.whitelist);
        showToast(`${domain} added to whitelist`, "success");
      }
    } catch (err) {
      console.error("[TrueProtect Options] Failed to add whitelist:", err);
      showToast("Failed to add domain to whitelist", "error");
    }
  }

  async function removeWhitelistDomain(domain) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "REMOVE_WHITELIST",
        domain: domain,
      });

      if (response && response.success) {
        renderWhitelist(response.whitelist);
        showToast(`${domain} removed from whitelist`, "success");
      }
    } catch (err) {
      console.error("[TrueProtect Options] Failed to remove whitelist:", err);
      showToast("Failed to remove domain from whitelist", "error");
    }
  }

  function renderWhitelist(domains) {
    // Remove existing items (keep the empty state element)
    const existingItems = whitelistList.querySelectorAll(".whitelist-item");
    existingItems.forEach((item) => item.remove());

    if (!domains || domains.length === 0) {
      whitelistEmpty.classList.remove("hidden");
      return;
    }

    whitelistEmpty.classList.add("hidden");

    domains.sort().forEach((domain) => {
      const item = document.createElement("div");
      item.className = "whitelist-item";

      const domainSpan = document.createElement("span");
      domainSpan.textContent = domain;

      const removeBtn = document.createElement("button");
      removeBtn.className = "btn btn-danger";
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", () => removeWhitelistDomain(domain));

      item.appendChild(domainSpan);
      item.appendChild(removeBtn);
      whitelistList.appendChild(item);
    });

    // Update stat
    if (statWhitelistCount) {
      statWhitelistCount.textContent = String(domains.length);
    }
  }

  // ─── Custom Blocklist Management ───────────────────────────────────────

  if (btnAddBlocklist) {
    btnAddBlocklist.addEventListener("click", addBlocklistDomain);
  }
  if (blocklistInput) {
    blocklistInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") addBlocklistDomain();
    });
  }

  async function addBlocklistDomain() {
    const domain = blocklistInput.value.trim().toLowerCase();
    if (!domain) return;

    if (!/^[a-z0-9][a-z0-9\-]*(\.[a-z0-9][a-z0-9\-]*)*\.[a-z]{2,}$/.test(domain)) {
      showToast("Please enter a valid domain name (e.g., malicious-site.com)", "error");
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: "ADD_BLOCKLIST",
        domain: domain,
      });

      if (response && response.success) {
        blocklistInput.value = "";
        renderBlocklist(response.customBlocklist);
        showToast(`${domain} added to blocklist`, "success");
      }
    } catch (err) {
      console.error("[TrueProtect Options] Failed to add blocklist:", err);
      showToast("Failed to add domain to blocklist", "error");
    }
  }

  async function removeBlocklistDomain(domain) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "REMOVE_BLOCKLIST",
        domain: domain,
      });

      if (response && response.success) {
        renderBlocklist(response.customBlocklist);
        showToast(`${domain} removed from blocklist`, "success");
      }
    } catch (err) {
      console.error("[TrueProtect Options] Failed to remove blocklist:", err);
      showToast("Failed to remove domain from blocklist", "error");
    }
  }

  function renderBlocklist(domains) {
    if (!blocklistList) return;

    const existingItems = blocklistList.querySelectorAll(".whitelist-item");
    existingItems.forEach((item) => item.remove());

    if (!domains || domains.length === 0) {
      if (blocklistEmpty) blocklistEmpty.classList.remove("hidden");
      return;
    }

    if (blocklistEmpty) blocklistEmpty.classList.add("hidden");

    domains.sort().forEach((domain) => {
      const item = document.createElement("div");
      item.className = "whitelist-item";

      const domainSpan = document.createElement("span");
      domainSpan.textContent = domain;

      const removeBtn = document.createElement("button");
      removeBtn.className = "btn btn-danger";
      removeBtn.textContent = "Unblock";
      removeBtn.addEventListener("click", () => removeBlocklistDomain(domain));

      item.appendChild(domainSpan);
      item.appendChild(removeBtn);
      blocklistList.appendChild(item);
    });
  }

  // ─── Status Updates ───────────────────────────────────────────────────

  function updateDaemonStatus(connected) {
    statusDaemonIndicator.className = "status-indicator " + (connected ? "connected" : "disconnected");
    statusDaemonText.textContent = connected
      ? "Connected and running"
      : "Not connected. Install and start the True Protection daemon for full functionality.";
  }

  function updateCloudStatus(enabled) {
    statusCloudIndicator.className = "status-indicator " + (enabled ? "connected" : "");
    statusCloudText.textContent = enabled
      ? "Enabled - URLs are being analyzed by JagAI"
      : "Disabled - Enable in JagAI Cloud settings";
  }

  function updateBlocklistStats(blocklistStats) {
    if (!blocklistStats) return;

    statDomains.textContent = String(blocklistStats.domainCount || 0);
    statUrls.textContent = String(blocklistStats.urlPatternCount || 0);
    statMining.textContent = String(blocklistStats.miningPatternCount || 0);
    statWhitelistCount.textContent = String(blocklistStats.whitelistCount || 0);

    statusBlocklistText.textContent = `${blocklistStats.domainCount || 0} domains loaded`;

    if (blocklistStats.lastUpdated) {
      const date = new Date(blocklistStats.lastUpdated);
      lastUpdated.textContent = `Last updated: ${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
    } else {
      lastUpdated.textContent = "Last updated: Using default blocklist";
    }
  }

  // ─── Toast ────────────────────────────────────────────────────────────

  let toastTimeout = null;

  function showToast(message, type = "success") {
    if (toastTimeout) clearTimeout(toastTimeout);

    toastMessage.textContent = message;
    toast.className = "toast " + type;

    toastTimeout = setTimeout(() => {
      toast.classList.add("hidden");
    }, 3000);
  }

  // ─── Initialize ───────────────────────────────────────────────────────

  await loadSettings();
});
