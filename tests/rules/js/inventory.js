// Inventory rule tests for cards.
class AcmeCard extends HTMLElement {
  set hass(hass) {
    // ruleid: inv-card-call-service
    hass.callService("light", "toggle", { entity_id: "light.x" });
    // ruleid: inv-card-call-ws
    hass.callWS({ type: "config/entity_registry/list" });
    // ruleid: inv-card-call-api
    hass.callApi("GET", "history/period");
    // ruleid: inv-card-subscribe
    hass.connection.subscribeEvents(cb, "state_changed");
    // ruleid: inv-card-states
    const s = hass.states["sun.sun"];
    // ruleid: inv-card-network
    fetch("/local/x.json");
    // ruleid: inv-card-localstorage
    localStorage.getItem("acme-prefs");
  }
}
// ruleid: inv-card-element
customElements.define("acme-card", AcmeCard);
