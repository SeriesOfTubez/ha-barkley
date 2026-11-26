// The garden map card for Petal Garden (made up). Map tiles come from OpenMaps,
// or from your own tile address when the card's map_style is Custom.
const TILES = "https://a.tile.openmaps.example/";
const CREDIT = "Map data from OpenMaps (openmaps.example)";

class PetalGardenMap extends HTMLElement {
  setConfig(config) {
    this._config = config;
  }

  set hass(hass) {
    this._hass = hass;
    this._draw();
  }

  _tile(z, x, y) {
    const style = this._config.map_style || "Streets";
    if (style === "Custom") return this._config.custom_tile_url + z + "/" + x + "/" + y + ".png";
    return TILES + style.toLowerCase() + "/" + z + "/" + x + "/" + y + ".png";
  }

  async _draw() {
    const zones = await this._hass.callWS({ type: "petal_garden/zones" });
    const img = document.createElement("img");
    img.src = this._tile(15, 17000, 11000);
    img.alt = CREDIT;
    this.replaceChildren(img);
    this.dataset.zones = String(zones.length);
  }
}

customElements.define("petal-garden-map", PetalGardenMap);
