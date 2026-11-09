# Sniff Test

Sniffs Home Assistant Marketplace (HACS) integrations and cards before they get into
the house: token theft, data sent off-box, obfuscated or compiled code that isn't the
code you can read, risky dependencies, and repos that changed hands.

## How it works

- Open **Sniff Test** in the sidebar (HA ingress; HA handles the login).
- **Sniff it:** scan a repo at the release HACS would install, or at a tag.
- **What would updating change?** Give the tag you have installed. The app scans the
  release HACS would install now, reuses the stored scan of your installed tag (or
  scans it), and shows what the update changes, most important first: new publishers,
  new data flows, new hosts, new findings. The diff never changes a score.
- Every scan is stored in `/data/sniff-test.db` (SQLite), which is part of the app's
  backups. Downloaded HA constraints are cached in `/data/cache` and left out of
  backups.

Scanned code is treated as hostile: it is downloaded and read, never run, built or
installed. Scores are computed by fixed rules; no AI decides anything.

## Options

| Option | Default | Meaning |
|---|---|---|
| `exposure` | `local` | `public` if your HA is reachable from the internet. Raises inbound findings; never lowers exfiltration findings. |
| `jobs` | `1` | Parallel Semgrep jobs. More is faster and uses more memory. |
| `github_token` | empty | A GitHub token (no scopes needed) for the 5,000 requests/hour limit instead of 60. |

## Resources

Semgrep is the heavy part: plan for 0.5–1 GB of RAM while a large card bundle is
scanned. Scans run one at a time.

## Permissions

The app asks for the Home Assistant API only, to read the installed HA version so
dependencies resolve against the release you run. No host network, no ports, no
Supervisor role, no folder access.

## Installing as a local add-on

1. In the repository: `uv run python scripts/stage_addon.py` (writes
   `dist/addon/sniff_test/`, the add-on plus the scanner's source, and
   `dist/addon/sniff_test.tar`, a plain archive of it).
2. Stream the archive into Home Assistant's local add-on folder, `/local_apps` in the
   Terminal & SSH add-on (older installs: `/addons`):
   `ssh root@homeassistant.local 'rm -rf /local_apps/sniff_test && tar -C /local_apps -xf -' < dist/addon/sniff_test.tar`
   Don't pipe macOS `tar` instead: it adds pax headers that the HA side extracts as
   stray files.
3. Settings → Apps → the app store → ⋮ → Check for updates (older HA: Settings →
   Add-ons → Add-on store). Sniff Test appears in the local section. Install it (your box builds the image: a few minutes, about
   1 GB of disk), then start it and open it from the sidebar.

To update, stage again, stream the archive again, then use Rebuild on the app's page.

## Building the image elsewhere

```
uv run python scripts/stage_addon.py
docker buildx build --platform linux/amd64,linux/arm64 dist/addon/sniff_test
```
