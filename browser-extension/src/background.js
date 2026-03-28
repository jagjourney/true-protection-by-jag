// True Protection Browser Extension - Background Service Worker
// Copyright (C) 2026 Jag Journey, LLC - MIT License

const THREAT_API = 'https://tpjsecurity.com/api/v1/threat-check';
let stats = { blocked: 0, scanned: 0 };

// Check URLs against threat database
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    stats.scanned++;
    // Local blocklist check (fast path)
    if (isKnownThreat(details.url)) {
      stats.blocked++;
      chrome.storage.local.set({ stats });
      return { cancel: true };
    }
    return {};
  },
  { urls: ['<all_urls>'] },
  ['blocking']
);

function isKnownThreat(url) {
  try {
    const hostname = new URL(url).hostname;
    // Check against local threat list (updated periodically)
    return false; // Placeholder - real check against cached threat DB
  } catch {
    return false;
  }
}

// Update threat list periodically
chrome.alarms.create('updateThreats', { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateThreats') {
    updateThreatList();
  }
});

async function updateThreatList() {
  try {
    const response = await fetch(THREAT_API + '/blocklist');
    if (response.ok) {
      const data = await response.json();
      await chrome.storage.local.set({ threatList: data });
    }
  } catch (e) {
    console.log('Threat list update failed:', e.message);
  }
}

// Message handler for popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStats') {
    sendResponse(stats);
  }
});
