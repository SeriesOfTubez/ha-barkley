# Sniff before you install

**This is the protection for a new install.** Since Home Assistant 2026.11 a new
integration is set up right after its files land, which loads its code. Auto-sniff comes
after that, so for a brand-new install it can only tell you about what is already
running. Sniff first, then install.

## How

1. On Barkley's first page, use the search box. It searches the whole Marketplace
   catalog, integrations and cards.
2. Click **Sniff it** on a result. Barkley scans exactly what the Marketplace would
   install, without installing it.
3. Read the app's page. See [An app's page](An-apps-page).

**Other versions** lists a project's 10 newest releases, betas included, each with its
score or a Sniff button, so you can sniff the exact version you plan to pick.

## What happens to these scans

They appear under "Sniffed, not installed" on the first page. If you install the app at
that version, auto-sniff reuses the scan. If you don't, the scan is deleted after
7 days. Scans of anything installed are never deleted.
