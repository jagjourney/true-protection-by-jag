/**
 * True Protection by Jag - Local Blocklist Manager
 * Efficient domain/URL blocklist with Set-based lookups,
 * wildcard matching, and periodic daemon synchronization.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

const DEFAULT_BLOCKLIST_DOMAINS = [
  // ---- Known cryptojacking domains ----
  "coinhive.com",
  "coin-hive.com",
  "jsecoin.com",
  "crypto-loot.com",
  "monerominer.rocks",
  "minero.cc",
  "authedmine.com",
  "coinimp.com",
  "webminepool.com",
  "papoto.com",
  "ppoi.org",
  "coinlab.biz",
  "gridcash.net",
  "tokyodrift.party",
  "webmine.cz",
  "2giga.link",
  // ---- Known malware distribution ----
  "malware.wicar.org",
  "amtso.org",
  "eicar.org",
  // ---- Known phishing test/real domains ----
  "phishing.database-check.xyz",
  "login-verify-account.com",
  "secure-update-info.com",
  "account-verify-now.com",
  "confirm-identity-online.com",
  // ---- Malvertising / ad-fraud networks ----
  "propellerads.com",
  "adexchangetracker.com",
  "clicktracker.biz",
  "trafficjunky.net",
  // ---- Known scam domains ----
  "tech-support-scam.com",
  "irs-refund-claim.com",
  "free-gift-card-generator.com",
  "antivirus-alert-critical.com",
  "windows-error-support.com",
  // ---- Tracking / fingerprinting ----
  "tracking-pixel-collector.com",
  "browser-fingerprint.net",
  // ---- Typosquatting examples (safe test entries) ----
  "goggle.com",
  "faceboook.com",
  "arnazon.com",
  "mlcrosoft.com",
  "paypa1.com",
  "app1e-id.com",
  "netfliix.com",
  "arnazon-prime.com",
];

const DEFAULT_BLOCKLIST_URL_PATTERNS = [
  // Suspicious URL path patterns
  "/wp-admin/install.php",
  "/phishing/login.html",
  "/.env",
  "/etc/passwd",
  "/admin/config.php",
  "/.git/config",
  "/wp-login.php?action=lostpassword",
  "/cgi-bin/luci",
  "/shell",
  "/.well-known/security.txt",
];

// Known mining script paths
const MINING_SCRIPT_PATTERNS = [
  "coinhive.min.js",
  "cryptonight.wasm",
  "deepMiner.js",
  "miner.js",
  "miner.min.js",
  "webmr.js",
  "monero-miner.js",
  "xmr-miner.js",
  "worker.js?key=",
  "CoinHive.Anonymous",
  "coin-hive.com/lib",
  "coinimp.com/scripts",
  "authedmine.com/lib",
  "jsecoin.com/server",
  "crypto-loot.com/lib",
  "monerominer.rocks/miner",
  "webminepool.com/lib",
  "papoto.com/lib",
  "gridcash.net/lib",
];

class BlocklistManager {
  constructor() {
    this.domainSet = new Set();
    this.wildcardDomains = [];
    this.urlPatternSet = new Set();
    this.miningPatterns = new Set(MINING_SCRIPT_PATTERNS);
    this.customWhitelist = new Set();
    this.lastUpdated = null;
    this.updateInterval = 30 * 60 * 1000; // 30 minutes
  }

  /**
   * Initialize the blocklist from storage or defaults.
   */
  async init() {
    try {
      const stored = await chrome.storage.local.get([
        "blocklist_domains",
        "blocklist_urls",
        "blocklist_wildcards",
        "blocklist_mining",
        "blocklist_whitelist",
        "blocklist_last_updated",
      ]);

      if (stored.blocklist_domains && stored.blocklist_domains.length > 0) {
        this.domainSet = new Set(stored.blocklist_domains);
      } else {
        this.domainSet = new Set(DEFAULT_BLOCKLIST_DOMAINS);
      }

      if (stored.blocklist_urls && stored.blocklist_urls.length > 0) {
        this.urlPatternSet = new Set(stored.blocklist_urls);
      } else {
        this.urlPatternSet = new Set(DEFAULT_BLOCKLIST_URL_PATTERNS);
      }

      if (stored.blocklist_wildcards) {
        this.wildcardDomains = stored.blocklist_wildcards;
      }

      if (stored.blocklist_mining) {
        this.miningPatterns = new Set(stored.blocklist_mining);
      }

      if (stored.blocklist_whitelist) {
        this.customWhitelist = new Set(stored.blocklist_whitelist);
      }

      this.lastUpdated = stored.blocklist_last_updated || null;

      // Load user's custom blocked domains and merge into active checks
      await this.loadCustomBlocklist();

      // Snapshot the built-in domain set so we know which are defaults vs custom
      this.defaultDomains = new Set(DEFAULT_BLOCKLIST_DOMAINS);

      console.log(
        `[TrueProtect] Blocklist loaded: ${this.domainSet.size} domains, ${this.urlPatternSet.size} URL patterns, ${this.miningPatterns.size} mining patterns, ${this.customBlocklist?.size ?? 0} custom blocked`
      );
    } catch (err) {
      console.error("[TrueProtect] Failed to load blocklist from storage:", err);
      this.domainSet = new Set(DEFAULT_BLOCKLIST_DOMAINS);
      this.urlPatternSet = new Set(DEFAULT_BLOCKLIST_URL_PATTERNS);
      this.defaultDomains = new Set(DEFAULT_BLOCKLIST_DOMAINS);
      this.customBlocklist = new Set();
    }
  }

  /**
   * Persist the current blocklist to storage.
   */
  async save() {
    try {
      await chrome.storage.local.set({
        blocklist_domains: Array.from(this.domainSet),
        blocklist_urls: Array.from(this.urlPatternSet),
        blocklist_wildcards: this.wildcardDomains,
        blocklist_mining: Array.from(this.miningPatterns),
        blocklist_whitelist: Array.from(this.customWhitelist),
        blocklist_last_updated: this.lastUpdated,
      });
    } catch (err) {
      console.error("[TrueProtect] Failed to save blocklist:", err);
    }
  }

  /**
   * Check if a domain is blocked. Handles exact match and wildcard/subdomain matching.
   * @param {string} domain - The domain to check (e.g., "evil.example.com")
   * @returns {boolean}
   */
  isDomainBlocked(domain) {
    if (!domain) return false;

    const lowerDomain = domain.toLowerCase().replace(/^www\./, "");

    // Whitelisted domains bypass blocking
    if (this.customWhitelist.has(lowerDomain)) return false;

    // Exact match
    if (this.domainSet.has(lowerDomain)) return true;

    // Subdomain matching: check if any parent domain is blocked
    const parts = lowerDomain.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const parentDomain = parts.slice(i).join(".");
      if (this.domainSet.has(parentDomain)) return true;
    }

    // Wildcard matching
    for (const pattern of this.wildcardDomains) {
      if (this._matchWildcard(lowerDomain, pattern)) return true;
    }

    return false;
  }

  /**
   * Check if a URL path matches any blocked URL pattern.
   * @param {string} url - The full URL to check
   * @returns {boolean}
   */
  isUrlBlocked(url) {
    if (!url) return false;

    try {
      const parsed = new URL(url);

      // Check domain first
      if (this.isDomainBlocked(parsed.hostname)) return true;

      // Check URL path patterns
      const pathAndQuery = parsed.pathname + parsed.search;
      for (const pattern of this.urlPatternSet) {
        if (pathAndQuery.includes(pattern)) return true;
      }
    } catch {
      // Invalid URL
      return false;
    }

    return false;
  }

  /**
   * Check if a URL is a known mining script.
   * @param {string} url - The URL to check
   * @returns {boolean}
   */
  isMiningScript(url) {
    if (!url) return false;
    const lowerUrl = url.toLowerCase();
    for (const pattern of this.miningPatterns) {
      if (lowerUrl.includes(pattern.toLowerCase())) return true;
    }
    return false;
  }

  /**
   * Match a domain against a wildcard pattern.
   * Supports patterns like "*.example.com"
   * @param {string} domain
   * @param {string} pattern
   * @returns {boolean}
   */
  _matchWildcard(domain, pattern) {
    if (!pattern.includes("*")) {
      return domain === pattern;
    }
    const regexStr = pattern
      .replace(/\./g, "\\.")
      .replace(/\*/g, "[a-z0-9\\-]*");
    try {
      const regex = new RegExp(`^${regexStr}$`, "i");
      return regex.test(domain);
    } catch {
      return false;
    }
  }

  /**
   * Add a domain to the blocklist.
   * @param {string} domain
   */
  addDomain(domain) {
    this.domainSet.add(domain.toLowerCase());
  }

  /**
   * Remove a domain from the blocklist.
   * @param {string} domain
   */
  removeDomain(domain) {
    this.domainSet.delete(domain.toLowerCase());
  }

  /**
   * Add a domain to the whitelist.
   * @param {string} domain
   */
  addWhitelist(domain) {
    this.customWhitelist.add(domain.toLowerCase());
  }

  /**
   * Remove a domain from the whitelist.
   * @param {string} domain
   */
  removeWhitelist(domain) {
    this.customWhitelist.delete(domain.toLowerCase());
  }

  /**
   * Merge incoming blocklist data from the True Protection daemon.
   * @param {Object} data - { domains: string[], urls: string[], wildcards: string[], mining: string[] }
   */
  async mergeFromDaemon(data) {
    if (data.domains && Array.isArray(data.domains)) {
      for (const d of data.domains) {
        this.domainSet.add(d.toLowerCase());
      }
    }
    if (data.urls && Array.isArray(data.urls)) {
      for (const u of data.urls) {
        this.urlPatternSet.add(u);
      }
    }
    if (data.wildcards && Array.isArray(data.wildcards)) {
      this.wildcardDomains = [
        ...new Set([...this.wildcardDomains, ...data.wildcards]),
      ];
    }
    if (data.mining && Array.isArray(data.mining)) {
      for (const m of data.mining) {
        this.miningPatterns.add(m);
      }
    }

    this.lastUpdated = Date.now();
    await this.save();

    console.log(
      `[TrueProtect] Blocklist merged from daemon. Now: ${this.domainSet.size} domains`
    );
  }

  /**
   * Get blocklist statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      domainCount: this.domainSet.size,
      urlPatternCount: this.urlPatternSet.size,
      wildcardCount: this.wildcardDomains.length,
      miningPatternCount: this.miningPatterns.size,
      whitelistCount: this.customWhitelist.size,
      customBlocklistCount: this.customBlocklist ? this.customBlocklist.size : 0,
      lastUpdated: this.lastUpdated,
    };
  }

  // ---- Custom Blocklist Management -----------------------------------------

  /**
   * Add a domain to the user's custom blocklist.
   * @param {string} domain
   */
  async addCustomBlockedDomain(domain) {
    domain = domain.toLowerCase().trim();
    if (!domain) return;

    if (!this.customBlocklist) {
      this.customBlocklist = new Set();
    }
    this.customBlocklist.add(domain);
    this.domainSet.add(domain); // Also add to active domain checks

    await chrome.storage.local.set({
      custom_blocklist: [...this.customBlocklist],
    });
  }

  /**
   * Remove a domain from the user's custom blocklist.
   * @param {string} domain
   */
  async removeCustomBlockedDomain(domain) {
    domain = domain.toLowerCase().trim();
    if (!this.customBlocklist) return;

    this.customBlocklist.delete(domain);
    // Only remove from domainSet if it's not in the built-in list
    if (!this.defaultDomains || !this.defaultDomains.has(domain)) {
      this.domainSet.delete(domain);
    }

    await chrome.storage.local.set({
      custom_blocklist: [...this.customBlocklist],
    });
  }

  /**
   * Get all custom blocked domains.
   * @returns {string[]}
   */
  getCustomBlockedDomains() {
    return this.customBlocklist ? [...this.customBlocklist] : [];
  }

  /**
   * Load custom blocklist from storage and merge into active checks.
   */
  async loadCustomBlocklist() {
    try {
      const stored = await chrome.storage.local.get("custom_blocklist");
      if (stored.custom_blocklist && Array.isArray(stored.custom_blocklist)) {
        this.customBlocklist = new Set(stored.custom_blocklist);
        for (const domain of this.customBlocklist) {
          this.domainSet.add(domain);
        }
      } else {
        this.customBlocklist = new Set();
      }
    } catch {
      this.customBlocklist = new Set();
    }
  }
}

// Export for use as ES module in service worker
export { BlocklistManager, MINING_SCRIPT_PATTERNS };
