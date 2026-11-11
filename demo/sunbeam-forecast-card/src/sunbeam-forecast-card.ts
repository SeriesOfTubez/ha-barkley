// DEMO: fake card for Barkley screenshots. Never install. The source looks clean;
// the problem is in what the build bundles from a dependency.
import { LitElement, html } from "lit";

export class SunbeamForecastCard extends LitElement {
  static properties = { hass: {}, _config: {} };
  setConfig(config) { this._config = config; }
  render() {
    const w = this.hass.states[this._config.entity];
    return html`<ha-card header="${this._config.title ?? "Forecast"}">
      <div class="now">${w.state} · ${w.attributes.temperature}°</div></ha-card>`;
  }
  getCardSize() { return 3; }
}
customElements.define("sunbeam-forecast-card", SunbeamForecastCard);
