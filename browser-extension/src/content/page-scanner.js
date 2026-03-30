/**
 * True Protection by Jag - Content Script (Page Scanner)
 * Scans loaded pages for malicious iframes, suspicious scripts,
 * hidden credential-harvesting forms, and cryptocurrency miners.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

(function () {
  "use strict";

  // Avoid double-injection
  if (window.__trueProtectScanned) return;
  window.__trueProtectScanned = true;

  const SCAN_DELAY_MS = 500;

  // ─── Known Mining Script Signatures ─────────────────────────────────────

  const MINING_SIGNATURES = [
    // Script source patterns
    "coinhive.min.js",
    "coinhive.com/lib",
    "coin-hive.com",
    "authedmine.com",
    "crypto-loot.com",
    "jsecoin.com",
    "monerominer.rocks",
    "coinimp.com",
    "minero.cc",
    "webmr.js",
    "deepMiner.js",
    // Constructor / class patterns in inline scripts
    "CoinHive.Anonymous",
    "CoinHive.User",
    "new CoinHive",
    "CryptoLoot.Anonymous",
    "new CryptoLoot",
    "CRLT.Anonymous",
    "Client.Anonymous",
    "new deepMiner",
    "new CoinImp",
    // WebAssembly mining indicators
    "cryptonight.wasm",
    "cn.wasm",
    // Generic miner patterns
    "startMining(",
    "miner.start(",
    "Miner({",
  ];

  // ─── Suspicious Iframe Patterns ─────────────────────────────────────────

  const SUSPICIOUS_IFRAME_PATTERNS = [
    // Zero-size iframes (often used for clickjacking or tracking)
    { check: "style", pattern: /width\s*:\s*0|height\s*:\s*0/ },
    { check: "style", pattern: /display\s*:\s*none/ },
    { check: "style", pattern: /visibility\s*:\s*hidden/ },
    { check: "style", pattern: /position\s*:\s*absolute.*left\s*:\s*-\d{4,}/ },
  ];

  // ─── Main Scanner ──────────────────────────────────────────────────────

  const threats = [];

  /**
   * Scan the page for all threat types.
   */
  function scanPage() {
    scanForMiningScripts();
    scanForMaliciousIframes();
    scanForHiddenForms();
    scanForSuspiciousScripts();
    scanForKeyloggers();

    // Report findings to the background service worker
    if (threats.length > 0) {
      chrome.runtime.sendMessage({
        type: "PAGE_SCAN_RESULT",
        threats: threats,
        url: window.location.href,
        timestamp: Date.now(),
      }).catch(() => {
        // Extension context may have been invalidated
      });
    }
  }

  // ─── Mining Script Detection ────────────────────────────────────────────

  function scanForMiningScripts() {
    // Check all <script> elements for mining signatures
    const scripts = document.querySelectorAll("script");
    scripts.forEach((script) => {
      // Check script src attributes
      const src = (script.src || "").toLowerCase();
      for (const sig of MINING_SIGNATURES) {
        if (src.includes(sig.toLowerCase())) {
          threats.push({
            type: "cryptojacking",
            severity: "high",
            message: `Cryptocurrency mining script detected: ${sig}`,
            element: describeElement(script),
            url: src,
          });
          // Try to remove it
          try { script.remove(); } catch {}
          return;
        }
      }

      // Check inline script content
      const content = (script.textContent || "").toLowerCase();
      if (content.length > 0) {
        for (const sig of MINING_SIGNATURES) {
          if (content.includes(sig.toLowerCase())) {
            threats.push({
              type: "cryptojacking",
              severity: "high",
              message: `Inline cryptocurrency mining code detected: ${sig}`,
              element: describeElement(script),
            });
            try { script.remove(); } catch {}
            return;
          }
        }
      }
    });

    // Check for WebWorker-based mining (common evasion technique)
    const workerDetected = detectWorkerMining();
    if (workerDetected) {
      threats.push({
        type: "cryptojacking",
        severity: "medium",
        message: "Suspicious WebWorker activity detected (possible hidden mining)",
      });
    }
  }

  /**
   * Detect if the page creates WebWorkers that might be mining.
   */
  function detectWorkerMining() {
    // Check for Blob URLs used for workers (common mining obfuscation)
    const scripts = document.querySelectorAll("script");
    for (const script of scripts) {
      const content = script.textContent || "";
      if (
        content.includes("new Worker") &&
        content.includes("Blob") &&
        (content.includes("hash") || content.includes("nonce") || content.includes("throttle"))
      ) {
        return true;
      }
    }
    return false;
  }

  // ─── Malicious Iframe Detection ─────────────────────────────────────────

  function scanForMaliciousIframes() {
    const iframes = document.querySelectorAll("iframe");

    iframes.forEach((iframe) => {
      const src = iframe.src || "";
      const style = (iframe.getAttribute("style") || "").toLowerCase();
      const computedStyle = window.getComputedStyle(iframe);

      // Check for zero-dimension iframes
      const width = parseInt(computedStyle.width) || iframe.width || 0;
      const height = parseInt(computedStyle.height) || iframe.height || 0;

      if ((width === 0 || height === 0) && src) {
        threats.push({
          type: "suspicious_iframe",
          severity: "medium",
          message: `Hidden iframe detected (0-dimension): ${truncateUrl(src)}`,
          element: describeElement(iframe),
        });
      }

      // Check suspicious style patterns
      for (const pattern of SUSPICIOUS_IFRAME_PATTERNS) {
        if (pattern.pattern.test(style)) {
          threats.push({
            type: "suspicious_iframe",
            severity: "medium",
            message: `Hidden iframe with suspicious styling: ${truncateUrl(src)}`,
            element: describeElement(iframe),
          });
          break;
        }
      }

      // Check for cross-origin iframes loading login pages
      if (src && !src.startsWith("about:") && !src.startsWith("javascript:")) {
        try {
          const iframeUrl = new URL(src, window.location.href);
          if (iframeUrl.origin !== window.location.origin) {
            const path = iframeUrl.pathname.toLowerCase();
            if (
              path.includes("login") ||
              path.includes("signin") ||
              path.includes("auth") ||
              path.includes("password")
            ) {
              threats.push({
                type: "phishing",
                severity: "high",
                message: `Cross-origin iframe loading login page: ${truncateUrl(src)}`,
                element: describeElement(iframe),
              });
            }
          }
        } catch {}
      }
    });
  }

  // ─── Hidden Form Detection (Credential Harvesting) ────────────────────

  function scanForHiddenForms() {
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {
      const action = form.action || "";
      const hasPasswordField = form.querySelector('input[type="password"]') !== null;
      const hasEmailField = form.querySelector('input[type="email"]') !== null ||
                            form.querySelector('input[name*="email"]') !== null ||
                            form.querySelector('input[name*="user"]') !== null;

      if (!hasPasswordField && !hasEmailField) return;

      // Check if form submits to a different domain
      if (action && action !== "#" && action !== "") {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.origin !== window.location.origin) {
            threats.push({
              type: "phishing",
              severity: "high",
              message: `Credential form submits to external domain: ${actionUrl.hostname}`,
              element: describeElement(form),
              details: {
                formAction: action,
                pageDomain: window.location.hostname,
                actionDomain: actionUrl.hostname,
              },
            });
          }
        } catch {}
      }

      // Check for hidden/invisible forms
      const style = window.getComputedStyle(form);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0" ||
        parseInt(style.height) === 0
      ) {
        if (hasPasswordField) {
          threats.push({
            type: "phishing",
            severity: "high",
            message: "Hidden form with password field detected (possible credential harvesting)",
            element: describeElement(form),
          });
        }
      }

      // Check for forms with suspicious autocomplete manipulation
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      passwordInputs.forEach((input) => {
        if (input.getAttribute("autocomplete") === "off" && action) {
          // Many phishing forms disable autocomplete to avoid browser warnings
          try {
            const actionUrl = new URL(action, window.location.href);
            if (actionUrl.origin !== window.location.origin) {
              threats.push({
                type: "phishing",
                severity: "medium",
                message: "Password field with disabled autocomplete submitting to external domain",
                element: describeElement(input),
              });
            }
          } catch {}
        }
      });
    });
  }

  // ─── Suspicious Script Detection ──────────────────────────────────────

  function scanForSuspiciousScripts() {
    const scripts = document.querySelectorAll("script");

    scripts.forEach((script) => {
      const content = script.textContent || "";

      // Detect potential keyloggers
      if (
        content.includes("addEventListener") &&
        content.includes("keypress") &&
        (content.includes("XMLHttpRequest") || content.includes("fetch("))
      ) {
        threats.push({
          type: "keylogger",
          severity: "high",
          message: "Potential keylogger detected (captures keypress and sends data)",
          element: describeElement(script),
        });
      }

      // Detect clipboard hijacking
      if (
        content.includes("clipboardData") ||
        (content.includes("navigator.clipboard") && content.includes("writeText"))
      ) {
        if (content.includes("bitcoin") || content.includes("0x") || content.includes("wallet")) {
          threats.push({
            type: "clipboard_hijack",
            severity: "high",
            message: "Potential clipboard hijacking targeting cryptocurrency addresses",
            element: describeElement(script),
          });
        }
      }

      // Detect eval with obfuscated content (common in exploits)
      const evalMatches = content.match(/eval\s*\(/g);
      if (evalMatches && evalMatches.length > 2) {
        threats.push({
          type: "obfuscated_code",
          severity: "medium",
          message: `Multiple eval() calls detected (${evalMatches.length}x): possible obfuscated malicious code`,
          element: describeElement(script),
        });
      }

      // Detect suspicious data exfiltration patterns
      if (
        (content.includes("document.cookie") || content.includes("localStorage")) &&
        (content.includes("new Image") || content.includes(".src="))
      ) {
        threats.push({
          type: "data_exfiltration",
          severity: "high",
          message: "Potential cookie/storage data exfiltration via image requests",
          element: describeElement(script),
        });
      }
    });
  }

  // ─── Keylogger Detection ──────────────────────────────────────────────

  function scanForKeyloggers() {
    // Check event listeners on document/body for keypress/keydown logging
    // We can detect inline handlers
    const bodyHandlers = [
      document.body?.getAttribute("onkeypress"),
      document.body?.getAttribute("onkeydown"),
      document.body?.getAttribute("onkeyup"),
      document.documentElement?.getAttribute("onkeypress"),
      document.documentElement?.getAttribute("onkeydown"),
      document.documentElement?.getAttribute("onkeyup"),
    ].filter(Boolean);

    for (const handler of bodyHandlers) {
      if (handler.includes("http") || handler.includes("fetch") || handler.includes("XMLHttp")) {
        threats.push({
          type: "keylogger",
          severity: "high",
          message: "Inline keyboard event handler with network request detected",
        });
      }
    }
  }

  // ─── Mutation Observer (detect dynamically injected threats) ──────────

  function startObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;

          // Check dynamically added scripts
          if (node.tagName === "SCRIPT") {
            const src = (node.src || "").toLowerCase();
            for (const sig of MINING_SIGNATURES) {
              if (src.includes(sig.toLowerCase())) {
                threats.push({
                  type: "cryptojacking",
                  severity: "high",
                  message: `Dynamically injected mining script blocked: ${sig}`,
                  element: describeElement(node),
                });
                try { node.remove(); } catch {}

                chrome.runtime.sendMessage({
                  type: "PAGE_SCAN_RESULT",
                  threats: [threats[threats.length - 1]],
                  url: window.location.href,
                  timestamp: Date.now(),
                }).catch(() => {});
                break;
              }
            }
          }

          // Check dynamically added iframes
          if (node.tagName === "IFRAME") {
            const src = node.src || "";
            const style = (node.getAttribute("style") || "").toLowerCase();
            if (
              style.includes("display:none") ||
              style.includes("visibility:hidden") ||
              style.includes("width:0") ||
              style.includes("height:0")
            ) {
              threats.push({
                type: "suspicious_iframe",
                severity: "medium",
                message: `Dynamically injected hidden iframe: ${truncateUrl(src)}`,
                element: describeElement(node),
              });

              chrome.runtime.sendMessage({
                type: "PAGE_SCAN_RESULT",
                threats: [threats[threats.length - 1]],
                url: window.location.href,
                timestamp: Date.now(),
              }).catch(() => {});
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  // ─── Helper Functions ─────────────────────────────────────────────────

  function describeElement(el) {
    if (!el) return "unknown";
    const tag = el.tagName?.toLowerCase() || "unknown";
    const id = el.id ? `#${el.id}` : "";
    const classes = el.className && typeof el.className === "string"
      ? `.${el.className.split(" ").filter(Boolean).join(".")}`
      : "";
    return `${tag}${id}${classes}`;
  }

  function truncateUrl(url, maxLen = 80) {
    if (!url) return "(empty)";
    return url.length > maxLen ? url.substring(0, maxLen) + "..." : url;
  }

  // ─── Listen for messages from background ──────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "MINING_BLOCKED") {
      console.log("[TrueProtect] Mining script blocked by background:", message.url);
    }

    if (message.type === "REQUEST_RESCAN") {
      threats.length = 0;
      scanPage();
      sendResponse({ threats: threats });
    }
  });

  // ─── Auth-Gated Start ─────────────────────────────────────────────────

  /**
   * Only start scanning if the user is authenticated.
   * If not logged in, page scanning is skipped entirely.
   */
  async function startIfAuthenticated() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "CHECK_AUTH" });
      if (!response || !response.authenticated) {
        // Not logged in - skip scanning
        return;
      }
    } catch {
      // Extension context may be invalid - skip
      return;
    }

    // User is authenticated - begin scanning
    setTimeout(scanPage, SCAN_DELAY_MS);
    startObserver();
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    startIfAuthenticated();
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      startIfAuthenticated();
    });
  }
})();
