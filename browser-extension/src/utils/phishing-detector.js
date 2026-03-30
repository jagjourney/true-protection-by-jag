/**
 * True Protection by Jag - Phishing Detection Engine
 * Heuristic-based phishing detection using Levenshtein distance,
 * homoglyph detection, URL shortener unwrapping, and form analysis.
 *
 * Copyright (c) Jag Journey, LLC. All rights reserved.
 */

// Top 100 domains commonly targeted by phishing attacks
const TOP_DOMAINS = [
  "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
  "netflix.com", "paypal.com", "instagram.com", "twitter.com", "linkedin.com",
  "yahoo.com", "outlook.com", "live.com", "hotmail.com", "gmail.com",
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "usbank.com",
  "capitalone.com", "americanexpress.com", "discover.com", "fidelity.com", "schwab.com",
  "dropbox.com", "icloud.com", "adobe.com", "spotify.com", "twitch.tv",
  "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "reddit.com",
  "whatsapp.com", "telegram.org", "signal.org", "discord.com", "slack.com",
  "zoom.us", "webex.com", "teams.microsoft.com", "skype.com", "snapchat.com",
  "tiktok.com", "pinterest.com", "tumblr.com", "wordpress.com", "blogger.com",
  "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
  "lowes.com", "costco.com", "etsy.com", "aliexpress.com", "wish.com",
  "fedex.com", "ups.com", "usps.com", "dhl.com", "royalmail.com",
  "irs.gov", "ssa.gov", "nhs.uk", "canada.ca", "gov.uk",
  "coinbase.com", "binance.com", "kraken.com", "blockchain.com", "metamask.io",
  "steam.com", "steampowered.com", "epicgames.com", "playstation.com", "xbox.com",
  "att.com", "verizon.com", "t-mobile.com", "sprint.com", "comcast.com",
  "spectrum.com", "cox.com", "xfinity.com", "hulu.com", "disneyplus.com",
  "hbo.com", "peacocktv.com", "paramount.com", "youtube.com", "vimeo.com",
  "office.com", "office365.com", "onedrive.com", "sharepoint.com", "salesforce.com",
];

// Unicode homoglyph mappings - characters that look like ASCII letters
const HOMOGLYPH_MAP = {
  "a": ["\u0430", "\u00e0", "\u00e1", "\u00e2", "\u00e3", "\u00e4", "\u0101", "\u0251"],
  "b": ["\u0432", "\u0184", "\u0185"],
  "c": ["\u0441", "\u00e7", "\u010b", "\u0188"],
  "d": ["\u0501", "\u0257", "\u018a"],
  "e": ["\u0435", "\u00e8", "\u00e9", "\u00ea", "\u00eb", "\u0113", "\u0117"],
  "g": ["\u0261", "\u0121", "\u011f"],
  "h": ["\u04bb", "\u0570"],
  "i": ["\u0456", "\u00ec", "\u00ed", "\u00ee", "\u00ef", "\u0131", "\u026a"],
  "j": ["\u0458", "\u029d"],
  "k": ["\u043a", "\u0137"],
  "l": ["\u04cf", "\u0131", "\u013a", "\u013c", "\u1e37"],
  "m": ["\u043c", "\u0271"],
  "n": ["\u0578", "\u0144", "\u0146", "\u014b"],
  "o": ["\u043e", "\u00f2", "\u00f3", "\u00f4", "\u00f5", "\u00f6", "\u014d", "\u0585"],
  "p": ["\u0440", "\u01a5"],
  "q": ["\u051b", "\u0566"],
  "r": ["\u0433", "\u0155", "\u0157"],
  "s": ["\u0455", "\u015b", "\u015d", "\u015f", "\u0161"],
  "t": ["\u0442", "\u0163", "\u0165"],
  "u": ["\u044a", "\u00f9", "\u00fa", "\u00fb", "\u00fc", "\u016b"],
  "v": ["\u0475", "\u028b"],
  "w": ["\u0461", "\u0175"],
  "x": ["\u0445", "\u04b3"],
  "y": ["\u0443", "\u00fd", "\u00ff", "\u0177"],
  "z": ["\u0437", "\u017a", "\u017c", "\u017e"],
  "0": ["\u043e", "\u04e9"],
  "1": ["\u04cf", "\u0196"],
};

// Build reverse map for fast lookup
const HOMOGLYPH_REVERSE = {};
for (const [ascii, homoglyphs] of Object.entries(HOMOGLYPH_MAP)) {
  for (const h of homoglyphs) {
    HOMOGLYPH_REVERSE[h] = ascii;
  }
}

// Known URL shortener domains
const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lnkd.in",
  "db.tt", "qr.ae", "cur.lv", "ity.im", "q.gs",
  "po.st", "bc.vc", "u.to", "t.ly", "soo.gd",
  "s2r.co", "clicky.me", "budurl.com", "rb.gy", "short.io",
  "cutt.ly", "v.gd", "rebrand.ly", "bl.ink", "shrtco.de",
]);

class PhishingDetector {
  constructor() {
    this.topDomains = TOP_DOMAINS;
    this.suspiciousKeywords = [
      "login", "signin", "sign-in", "verify", "account",
      "secure", "update", "confirm", "banking", "password",
      "credential", "authenticate", "wallet", "suspended",
      "unusual", "activity", "locked", "expired", "urgent",
    ];
  }

  /**
   * Run all phishing heuristics on a URL.
   * Returns a threat assessment object.
   * @param {string} url - The URL to analyze
   * @returns {Object} - { isPhishing: boolean, confidence: number, reasons: string[] }
   */
  analyzeUrl(url) {
    const results = {
      isPhishing: false,
      confidence: 0,
      reasons: [],
    };

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();

      // 1. Check typosquatting via Levenshtein distance
      const typosquatResult = this.detectTyposquatting(hostname);
      if (typosquatResult.isSuspicious) {
        results.confidence += typosquatResult.confidence;
        results.reasons.push(
          `Possible typosquat of "${typosquatResult.target}" (distance: ${typosquatResult.distance})`
        );
      }

      // 2. Check for homoglyph/unicode attacks
      const homoglyphResult = this.detectHomoglyphs(hostname);
      if (homoglyphResult.hasHomoglyphs) {
        results.confidence += 40;
        results.reasons.push(
          `Unicode homoglyph characters detected: looks like "${homoglyphResult.normalized}"`
        );
      }

      // 3. Check if URL shortener
      if (this.isUrlShortener(hostname)) {
        results.confidence += 10;
        results.reasons.push("URL uses a shortener service (destination hidden)");
      }

      // 4. Suspicious keywords in URL
      const keywordHits = this.detectSuspiciousKeywords(fullUrl);
      if (keywordHits.length > 0) {
        results.confidence += Math.min(keywordHits.length * 5, 20);
        results.reasons.push(
          `Suspicious keywords in URL: ${keywordHits.join(", ")}`
        );
      }

      // 5. Excessive subdomains
      const subdomainCount = hostname.split(".").length - 2;
      if (subdomainCount >= 3) {
        results.confidence += 15;
        results.reasons.push(
          `Excessive subdomains (${subdomainCount}): may be hiding real domain`
        );
      }

      // 6. IP address as hostname
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        results.confidence += 25;
        results.reasons.push("IP address used as hostname instead of domain name");
      }

      // 7. Suspicious TLDs
      const suspiciousTlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
        ".club", ".work", ".buzz", ".surf", ".icu",
      ];
      for (const tld of suspiciousTlds) {
        if (hostname.endsWith(tld)) {
          results.confidence += 10;
          results.reasons.push(`Uses suspicious TLD: ${tld}`);
          break;
        }
      }

      // 8. Very long hostname (common in phishing)
      if (hostname.length > 50) {
        results.confidence += 10;
        results.reasons.push("Unusually long hostname");
      }

      // 9. Hyphen abuse in domain
      const mainDomain = this._extractMainDomain(hostname);
      const hyphenCount = (mainDomain.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        results.confidence += 15;
        results.reasons.push(
          `Excessive hyphens in domain (${hyphenCount}): common phishing pattern`
        );
      }

      // 10. Data URI or javascript protocol
      if (parsed.protocol === "data:" || parsed.protocol === "javascript:") {
        results.confidence += 50;
        results.reasons.push(`Dangerous protocol: ${parsed.protocol}`);
      }

      // Cap confidence at 100
      results.confidence = Math.min(results.confidence, 100);
      results.isPhishing = results.confidence >= 50;
    } catch {
      // If URL parsing fails, that is itself suspicious
      results.confidence = 30;
      results.reasons.push("URL could not be parsed (malformed)");
    }

    return results;
  }

  /**
   * Calculate the Levenshtein distance between two strings.
   * @param {string} a
   * @param {string} b
   * @returns {number}
   */
  levenshteinDistance(a, b) {
    const m = a.length;
    const n = b.length;

    if (m === 0) return n;
    if (n === 0) return m;

    // Use two-row approach for memory efficiency
    let prevRow = new Array(n + 1);
    let currRow = new Array(n + 1);

    for (let j = 0; j <= n; j++) {
      prevRow[j] = j;
    }

    for (let i = 1; i <= m; i++) {
      currRow[0] = i;
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        currRow[j] = Math.min(
          currRow[j - 1] + 1,         // insertion
          prevRow[j] + 1,             // deletion
          prevRow[j - 1] + cost       // substitution
        );
      }
      [prevRow, currRow] = [currRow, prevRow];
    }

    return prevRow[n];
  }

  /**
   * Detect typosquatting by comparing domain against top domains.
   * @param {string} hostname
   * @returns {Object} - { isSuspicious, target, distance, confidence }
   */
  detectTyposquatting(hostname) {
    const domain = this._extractMainDomain(hostname);
    const result = { isSuspicious: false, target: null, distance: Infinity, confidence: 0 };

    for (const topDomain of this.topDomains) {
      const topMain = topDomain.split(".")[0];
      const testMain = domain.split(".")[0];

      // Skip exact matches
      if (testMain === topMain) continue;

      // Only check domains of similar length (typosquats are close)
      if (Math.abs(testMain.length - topMain.length) > 3) continue;

      const dist = this.levenshteinDistance(testMain, topMain);

      // Threshold: distance of 1-2 for short domains, 1-3 for longer ones
      const threshold = topMain.length <= 5 ? 1 : topMain.length <= 8 ? 2 : 3;

      if (dist > 0 && dist <= threshold && dist < result.distance) {
        result.isSuspicious = true;
        result.target = topDomain;
        result.distance = dist;
        // Higher confidence for closer matches
        result.confidence = dist === 1 ? 45 : dist === 2 ? 30 : 20;
      }
    }

    return result;
  }

  /**
   * Detect unicode homoglyph characters in a domain.
   * @param {string} hostname
   * @returns {Object} - { hasHomoglyphs, normalized, suspiciousChars }
   */
  detectHomoglyphs(hostname) {
    const result = { hasHomoglyphs: false, normalized: "", suspiciousChars: [] };

    let normalized = "";
    for (const char of hostname) {
      if (HOMOGLYPH_REVERSE[char]) {
        result.hasHomoglyphs = true;
        result.suspiciousChars.push({
          original: char,
          looksLike: HOMOGLYPH_REVERSE[char],
          codePoint: char.codePointAt(0).toString(16),
        });
        normalized += HOMOGLYPH_REVERSE[char];
      } else {
        normalized += char;
      }
    }

    result.normalized = normalized;
    return result;
  }

  /**
   * Check if a hostname belongs to a known URL shortener.
   * @param {string} hostname
   * @returns {boolean}
   */
  isUrlShortener(hostname) {
    const cleaned = hostname.replace(/^www\./, "");
    return URL_SHORTENERS.has(cleaned);
  }

  /**
   * Detect suspicious keywords in a URL.
   * @param {string} url
   * @returns {string[]} - List of found keywords
   */
  detectSuspiciousKeywords(url) {
    return this.suspiciousKeywords.filter((kw) => url.includes(kw));
  }

  /**
   * Analyze a form element to determine if it submits credentials to a third-party domain.
   * @param {string} formAction - The form's action URL
   * @param {string} pageDomain - The current page's domain
   * @returns {Object} - { isSuspicious, reason }
   */
  analyzeFormAction(formAction, pageDomain) {
    if (!formAction || formAction === "" || formAction === "#") {
      return { isSuspicious: false, reason: null };
    }

    try {
      const actionUrl = new URL(formAction);
      const actionDomain = actionUrl.hostname.toLowerCase();
      const currentDomain = pageDomain.toLowerCase();

      // Same domain is fine
      if (actionDomain === currentDomain) {
        return { isSuspicious: false, reason: null };
      }

      // Check if it is a subdomain of the same root
      const actionRoot = this._extractRootDomain(actionDomain);
      const currentRoot = this._extractRootDomain(currentDomain);
      if (actionRoot === currentRoot) {
        return { isSuspicious: false, reason: null };
      }

      // Form submits to a completely different domain - suspicious
      return {
        isSuspicious: true,
        reason: `Form submits data to a different domain: ${actionDomain} (page is on ${currentDomain})`,
      };
    } catch {
      // Relative URLs are fine
      return { isSuspicious: false, reason: null };
    }
  }

  /**
   * Extract the main domain (SLD + TLD) from a hostname.
   * @param {string} hostname
   * @returns {string}
   */
  _extractMainDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join(".");
  }

  /**
   * Extract the root domain from a hostname.
   * @param {string} hostname
   * @returns {string}
   */
  _extractRootDomain(hostname) {
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    // Handle common two-part TLDs
    const twoPartTlds = ["co.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp"];
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTlds.includes(lastTwo)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }
}

// Export for use as ES module in service worker
export { PhishingDetector, URL_SHORTENERS, HOMOGLYPH_MAP, HOMOGLYPH_REVERSE, TOP_DOMAINS };
