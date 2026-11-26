# Sniff before you install

Since Home Assistant 2026.11, the Marketplace opens a new integration's setup right after its files land, and starting the setup loads its code. Auto-sniff runs after that, so for a brand-new install it can only tell you about code that's already running. To check a new app before it runs, sniff it from search first and install it afterwards.

## How

1. On Barkley's first page, use the search box. It searches the whole Marketplace
   catalog, integrations and cards.
2. Click **Sniff it** on a result. Barkley scans exactly what the Marketplace would
   install, without installing it.
3. Read the app's sniff report. See [An app's page](An-apps-page.md).

**Other versions** lists a project's 10 newest releases, betas included, each with its
readings or a Sniff button, so you can sniff the exact version you plan to pick.

## What happens to these scans

They appear under "Sniffed, not installed" on the first page. If you install the app at
that version, auto-sniff reuses the scan. If you don't, the scan is deleted after
7 days. Scans of anything installed are never deleted.
