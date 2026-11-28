"""Constants for a made-up bridge integration (test fixture: hosts are .invalid)."""

DOMAIN = "acme_bridge"
# Where the browser may be sent back to after a client approves access (OAuth).
DEFAULT_OAUTH_REDIRECT_ALLOWLIST: tuple[str, ...] = (
    "https://chat.example.invalid/api/mcp/auth_callback",
    "https://agent.example.invalid/oauth-redirect",
)
