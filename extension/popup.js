/* popup.js — SecureDNS Guard
 *
 * Pulls state from the service worker, renders it, listens for live RESULT
 * messages and refreshes the UI. No demo/fake data anywhere.
 */

const $ = (id) => document.getElementById(id);
let serverUrl = "http://localhost:5000";

/* ─── Utility ──────────────────────────────────────────────────────── */
function relTime(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5)    return "now";
  if (s < 60)   return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  return Math.floor(s / 3600) + "h";
}

function setStatus(level, text) {
  const dot = $("status-dot");
  dot.className = "dot " + (level || "");
  $("status-text").textContent = text;
}

function setKeyBanner(show) {
  $("key-banner").style.display = show ? "block" : "none";
}

/* ─── Rendering ────────────────────────────────────────────────────── */
function renderStats(stats) {
  $("kpi-total").textContent   = (stats.total   || 0).toLocaleString();
  $("kpi-blocked").textContent = (stats.blocked || 0).toLocaleString();
  $("kpi-safe").textContent    = (stats.safe    || 0).toLocaleString();
}

function renderFeed(entries) {
  const feed  = $("feed");
  const empty = $("empty");
  if (!entries || entries.length === 0) {
    feed.innerHTML = "";
    feed.appendChild(empty);
    empty.style.display = "flex";
    return;
  }
  empty.style.display = "none";
  feed.innerHTML = "";
  entries.forEach(addRow);
}

function addRow(e, prepend = false) {
  const cls = e.blocked ? "blocked" : "safe";
  const row = document.createElement("div");
  row.className = "row " + cls;

  const dot = document.createElement("span");
  dot.className = "row-dot " + cls;

  const domain = document.createElement("span");
  domain.className   = "row-domain";
  domain.title       = e.domain;
  domain.textContent = e.domain;

  const conf = document.createElement("span");
  conf.className   = "row-conf " + cls;
  conf.textContent = Math.round((e.confidence || 0) * 100) + "%";

  const time = document.createElement("span");
  time.className     = "row-time";
  time.dataset.ts    = e.ts;
  time.textContent   = relTime(e.ts);

  row.append(dot, domain, conf, time);

  const feed = $("feed");
  $("empty").style.display = "none";
  if (prepend && feed.firstChild) feed.insertBefore(row, feed.firstChild);
  else                            feed.appendChild(row);

  /* Cap to 60 rows visually */
  while (feed.children.length > 60) feed.removeChild(feed.lastChild);
}

/* ─── Connection / key check ───────────────────────────────────────── */
async function checkConnection(server, apiKey) {
  setStatus("", "Testing…");
  try {
    /* Lightweight reachability probe */
    const r = await fetch(server + "/api/diag");
    if (!r.ok) { setStatus("bad", `Server error ${r.status}`); return false; }
  } catch {
    setStatus("bad", "Cannot reach server");
    return false;
  }

  if (!apiKey) {
    setStatus("warn", "Server reachable · no API key");
    return false;
  }

  /* Validate key via the service worker so we share its CORS path */
  return new Promise(resolve => {
    chrome.runtime.sendMessage(
      { type: "TEST_KEY", server, apiKey },
      (resp) => {
        if (resp && resp.ok) {
          setStatus("ok", `Connected · key OK · ${server.replace(/https?:\/\//, "")}`);
          setKeyBanner(false);
          resolve(true);
        } else if (resp && resp.status === 401) {
          setStatus("bad", "Invalid API key");
          setKeyBanner(true);
          resolve(false);
        } else {
          setStatus("bad", "Key check failed");
          resolve(false);
        }
      }
    );
  });
}

/* ─── Init ─────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {

  /* Pull current state */
  chrome.runtime.sendMessage({ type: "GET_STATE" }, (state) => {
    if (!state) { setStatus("bad", "Service worker not responding"); return; }

    serverUrl = state.server || "http://localhost:5000";
    $("server").value = serverUrl;
    $("apikey").value = state.apiKey || "";

    $("t-input").checked  = !!state.enabled;
    $("t-lbl").textContent = state.enabled ? "ON" : "OFF";
    $("t-lbl").className   = "toggle-label" + (state.enabled ? " on" : "");

    renderStats(state.stats || {});
    renderFeed((state.stats && state.stats.lastResults) || []);
    setKeyBanner(!state.hasKey);

    /* Auto-expand settings panel if there is no API key yet */
    if (!state.hasKey) {
      $("set-body").classList.add("open");
      $("chev").classList.add("open");
    }

    checkConnection(serverUrl, state.apiKey || "");
  });

  /* Live updates from the service worker */
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "RESULT" || !msg.entry) return;
    addRow(msg.entry, true);
    chrome.runtime.sendMessage({ type: "GET_STATE" }, (s) => s && renderStats(s.stats || {}));
  });

  /* Tick relative timestamps every 5 s */
  setInterval(() => {
    document.querySelectorAll(".row-time").forEach(el => {
      const t = parseInt(el.dataset.ts, 10);
      if (t) el.textContent = relTime(t);
    });
  }, 5000);

  /* Toggle on/off */
  $("t-input").addEventListener("change", (e) => {
    const on = e.target.checked;
    $("t-lbl").textContent = on ? "ON" : "OFF";
    $("t-lbl").className   = "toggle-label" + (on ? " on" : "");
    chrome.runtime.sendMessage({ type: "SET_ENABLED", value: on });
  });

  /* Settings panel toggle */
  $("set-toggle").addEventListener("click", () => {
    const open = $("set-body").classList.toggle("open");
    $("chev").classList.toggle("open", open);
  });

  /* Show/hide API key */
  $("eye").addEventListener("click", () => {
    const inp  = $("apikey");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("eye").textContent = show ? "hide" : "show";
  });

  /* Save settings */
  $("save-btn").addEventListener("click", async () => {
    const server = $("server").value.trim().replace(/\/$/, "") || "http://localhost:5000";
    const apiKey = $("apikey").value.trim();
    const msg    = $("save-msg");
    msg.className = "save-msg";
    msg.textContent = "Saving…";

    chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", server, apiKey }, async () => {
      serverUrl = server;
      const ok = await checkConnection(server, apiKey);
      if (ok)              { msg.textContent = "✓ Saved & connected"; }
      else if (apiKey)     { msg.textContent = "✗ Invalid API key";  msg.className = "save-msg err"; }
      else                 { msg.textContent = "Saved — add API key"; msg.className = "save-msg err"; }
      setTimeout(() => { msg.textContent = ""; msg.className = "save-msg"; }, 3500);
    });
  });

  /* Clear stats */
  $("clear-btn").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CLEAR" }, () => {
      renderStats({});
      renderFeed([]);
    });
  });

  /* Manual test */
  $("test-btn").addEventListener("click", () => {
    const domain = $("test-input").value.trim();
    if (!domain) return;
    chrome.runtime.sendMessage({ type: "TEST_NOW", domain }, (resp) => {
      if (!resp || !resp.ok) {
        const m = $("save-msg");
        m.textContent = (resp && resp.error) || "Test failed";
        m.className = "save-msg err";
        setTimeout(() => { m.textContent = ""; m.className = "save-msg"; }, 3000);
      }
    });
  });
  $("test-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") $("test-btn").click();
  });

  /* Open profile page in a new tab */
  $("open-profile").addEventListener("click", () => {
    const url = (serverUrl || "http://localhost:5000") + "/profile";
    chrome.tabs.create({ url });
  });
});
