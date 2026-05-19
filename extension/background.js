/* SecureDNS Guard — MV3 service worker
 *
 * Job: every time the user navigates to a new page, send the hostname to
 * the server's /api/dns/batch endpoint, store the classification result,
 * tell the popup so it can update its feed, and block the tab if the
 * server says the domain is malicious.
 *
 * Design choices:
 *  - Single capture source (chrome.webNavigation.onCommitted, frameId 0).
 *    No webRequest noise from sub-resources/ads/CDNs.
 *  - All settings live in chrome.storage.local; we await a one-shot
 *    "_settingsReady" promise before any network call so we never hit the
 *    server before the API key is loaded.
 *  - Stats and the last 60 results are persisted to storage so the popup
 *    can show the feed even when the service worker has been killed.
 *  - When the popup is open we send it a real-time "RESULT" message so
 *    the feed updates as the user browses.
 */

const SERVER_DEFAULT = "http://localhost:5000";
const ENDPOINT       = "/api/dns/batch";
const PING_ENDPOINT  = "/api/auth/ping";
const MAX_FEED       = 60;

const SKIP_SCHEMES = new Set(["chrome", "chrome-extension", "moz-extension",
                              "edge", "about", "data", "blob", "javascript", "file"]);

const PRIVATE_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80:)/i;

/* ── In-memory state — rebuilt from storage on every SW startup ───────── */
let SERVER  = SERVER_DEFAULT;
let API_KEY = "";
let ENABLED = true;
let STATS   = { total: 0, blocked: 0, safe: 0, lastResults: [] };
let BLOCKED = new Set();
let INFLIGHT = new Set();   // prevent duplicate parallel checks of the same host

/* ── One-shot promise that resolves once storage is loaded ────────────── */
const SETTINGS_READY = new Promise(resolve => {
  chrome.storage.local.get(
    ["server", "apiKey", "enabled", "stats", "blocked"],
    r => {
      if (typeof r.server  === "string")  SERVER  = r.server;
      if (typeof r.apiKey  === "string")  API_KEY = r.apiKey;
      if (typeof r.enabled === "boolean") ENABLED = r.enabled;
      if (r.stats && typeof r.stats === "object") {
        STATS = Object.assign({ total: 0, blocked: 0, safe: 0, lastResults: [] }, r.stats);
        if (!Array.isArray(STATS.lastResults)) STATS.lastResults = [];
      }
      if (Array.isArray(r.blocked)) BLOCKED = new Set(r.blocked);
      console.log("[SecureDNS] ready — server:", SERVER, "key set:", !!API_KEY, "enabled:", ENABLED);
      _refreshBadge();
      resolve();
    }
  );
});

/* ── Live storage updates from the popup ──────────────────────────────── */
chrome.storage.onChanged.addListener(changes => {
  if (changes.server  !== undefined) SERVER  = changes.server.newValue  ?? SERVER_DEFAULT;
  if (changes.apiKey  !== undefined) API_KEY = changes.apiKey.newValue  ?? "";
  if (changes.enabled !== undefined) ENABLED = changes.enabled.newValue ?? true;
  _refreshBadge();
});

/* ── Helpers ─────────────────────────────────────────────────────────── */
function _hostnameFromUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const scheme = u.protocol.replace(":", "");
    if (SKIP_SCHEMES.has(scheme)) return null;
    let h = u.hostname.toLowerCase();
    if (!h) return null;
    if (h === "localhost") return null;
    if (PRIVATE_RE.test(h)) return null;
    try { if (h === new URL(SERVER).hostname) return null; } catch {}
    return h;
  } catch { return null; }
}

function _refreshBadge() {
  if (!ENABLED) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
    return;
  }
  if (!API_KEY) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    return;
  }
  if (STATS.blocked > 0) {
    chrome.action.setBadgeText({ text: String(STATS.blocked) });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    return;
  }
  chrome.action.setBadgeText({ text: "" });
}

function _persist() {
  chrome.storage.local.set({
    stats:   STATS,
    blocked: [...BLOCKED]
  });
}

function _addResultToFeed(serverResult, fallbackHost) {
  STATS.total++;
  if (serverResult.blocked) STATS.blocked++; else STATS.safe++;

  const entry = {
    domain:      serverResult.domain      || fallbackHost,
    blocked:     !!serverResult.blocked,
    confidence:  typeof serverResult.confidence === "number" ? serverResult.confidence : 0,
    attack_type: serverResult.attack_type || null,
    ts:          Date.now()
  };
  STATS.lastResults.unshift(entry);
  if (STATS.lastResults.length > MAX_FEED) STATS.lastResults.length = MAX_FEED;
  _persist();
  _refreshBadge();

  /* Notify the popup if it's open — silently ignore if it isn't */
  chrome.runtime.sendMessage({ type: "RESULT", entry }).catch(() => {});
  return entry;
}

function _blockTab(tabId, host, attackType) {
  if (!tabId || tabId < 0) return;
  const blockUrl = chrome.runtime.getURL(
    `block.html?domain=${encodeURIComponent(host)}&reason=${encodeURIComponent(attackType || "malicious")}`
  );
  chrome.tabs.update(tabId, { url: blockUrl }).catch(() => {});
}

/* ── Network call — POST one domain to /api/dns/batch ─────────────────── */
async function _classify(host, tabId) {
  await SETTINGS_READY;
  if (!ENABLED || !API_KEY || !host) return;
  if (INFLIGHT.has(host)) return;

  if (BLOCKED.has(host)) {
    _blockTab(tabId, host, "Previously blocked");
    return;
  }

  INFLIGHT.add(host);
  try {
    const res = await fetch(SERVER + ENDPOINT, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
      body:    JSON.stringify({ domains: [host] })
    });

    if (res.status === 401) {
      console.warn("[SecureDNS] 401 — invalid API key");
      return;
    }
    if (res.status === 429) {
      console.warn("[SecureDNS] 429 — rate limited, will retry on next nav");
      return;
    }
    if (!res.ok) {
      console.warn("[SecureDNS]", ENDPOINT, "→", res.status);
      return;
    }

    const data = await res.json();
    const r    = (data.results || [])[0];
    if (!r) return;

    _addResultToFeed(r, host);
    if (r.blocked) {
      BLOCKED.add(host);
      _persist();
      _blockTab(tabId, host, r.attack_type);
    }
  } catch (err) {
    console.error("[SecureDNS] fetch error:", err.message);
  } finally {
    INFLIGHT.delete(host);
  }
}

/* ── Capture point: every committed main-frame navigation ─────────────── */
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const host = _hostnameFromUrl(details.url);
  if (!host) return;
  _classify(host, details.tabId);
});

/* Also classify when the user types a URL and the tab starts navigating —
 * onBeforeNavigate fires earlier so we can block before the page even loads. */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const host = _hostnameFromUrl(details.url);
  if (!host) return;
  await SETTINGS_READY;
  if (BLOCKED.has(host)) {
    _blockTab(details.tabId, host, "Previously blocked");
  }
});

/* ── Message protocol with the popup ──────────────────────────────────── */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {

    case "GET_STATE":
      SETTINGS_READY.then(() => sendResponse({
        server: SERVER, apiKey: API_KEY, enabled: ENABLED,
        stats:  STATS,  hasKey: !!API_KEY
      }));
      return true;

    case "SAVE_SETTINGS":
      if (typeof msg.server === "string") SERVER  = msg.server.replace(/\/$/, "");
      if (typeof msg.apiKey === "string") API_KEY = msg.apiKey.trim();
      chrome.storage.local.set({ server: SERVER, apiKey: API_KEY }, () => {
        _refreshBadge();
        sendResponse({ ok: true });
      });
      return true;

    case "SET_ENABLED":
      ENABLED = !!msg.value;
      chrome.storage.local.set({ enabled: ENABLED }, () => {
        _refreshBadge();
        sendResponse({ ok: true });
      });
      return true;

    case "CLEAR":
      STATS   = { total: 0, blocked: 0, safe: 0, lastResults: [] };
      BLOCKED = new Set();
      _persist();
      _refreshBadge();
      sendResponse({ ok: true });
      return true;

    case "TEST_KEY":
      /* Validate the supplied key against /api/auth/ping */
      (async () => {
        try {
          const url = (msg.server || SERVER).replace(/\/$/, "") + PING_ENDPOINT;
          const res = await fetch(url, { headers: { "X-API-Key": msg.apiKey || API_KEY } });
          sendResponse({ ok: res.ok, status: res.status });
        } catch (err) {
          sendResponse({ ok: false, error: err.message });
        }
      })();
      return true;

    case "TEST_NOW":
      /* Manually classify a domain (used by popup "Test" button) */
      (async () => {
        await SETTINGS_READY;
        const host = msg.domain && _hostnameFromUrl("http://" + msg.domain);
        if (!host) { sendResponse({ ok: false, error: "Invalid domain" }); return; }
        await _classify(host, -1);
        sendResponse({ ok: true });
      })();
      return true;
  }
});

/* ── Daily badge reset (nice-to-have) ─────────────────────────────────── */
chrome.alarms.get("daily-reset", a => {
  if (!a) chrome.alarms.create("daily-reset", { periodInMinutes: 60 * 24 });
});
chrome.alarms.onAlarm.addListener(a => {
  if (a.name === "daily-reset") _refreshBadge();
});
