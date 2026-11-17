# Standalone (no Supervisor)

Barkley is an app (add-on), and apps need the Supervisor: Home Assistant OS or
Supervised. You can still run it without one:

- **Home Assistant Container or Core**, which have no Supervisor and no app store.
- **A small box**, such as a Raspberry Pi with 1 or 2 GB, even one running Home Assistant
  OS. A scan needs 0.5 to 1.5 GB of memory for a minute or two, which a small box may not
  have to spare. Run Barkley on a NAS or PC and point it at Home Assistant. The Pi then
  only answers a few API calls.

It is the same signed image the app store installs, started differently. Everything works
as it does in the app: the list, sniffing, update comparison, auto-sniff and
notifications, advisory re-checks, and the AI explanations. AI explanations still go
through Home Assistant's AI Task entity, so the AI provider you set up in Home Assistant
is the one used, and Barkley stores no AI key of its own.

## What is different

| | The app | Standalone |
|---|---|---|
| How it reaches Home Assistant | The Supervisor's proxy, no token to handle | `HA_URL` and a long-lived access token of an administrator |
| Who can open it | Home Assistant's ingress (the sidebar) | Anyone who logs in with Home Assistant as an administrator |
| Containment | AppArmor profile, no open port, and the tool sandbox | The tool sandbox, and what you give the container (the compose file: non-root, read-only, no capabilities) |
| Where it shows up | The sidebar | Its own address, such as `http://192.168.1.20:8099` |

## Set it up

1. **A token.** In Home Assistant, it's best to make a user just for Barkley
   (Settings → People → Users, with **Administrator** on, since the Marketplace's list is
   for administrators). Log in as that user once, open the profile → Security →
   Long-lived access tokens, and create one. A user of its own makes it easy to see
   Barkley's calls in the logs and to revoke it.
2. **The files.** Copy [`standalone/compose.yaml`](https://github.com/SeriesOfTubez/ha-barkley/blob/main/standalone/compose.yaml)
   into a new folder, then:
   ```sh
   mkdir -p data && sudo chown 1000:1000 data
   printf '%s' 'PASTE-THE-TOKEN' > ha_token && chmod 600 ha_token
   ```
3. **Two addresses** in `compose.yaml`:
   - `HA_URL`: Home Assistant, as the container reaches it, such as
     `http://homeassistant.local:8123`. Use `https` if Home Assistant has it: with plain
     http, the token crosses your network unencrypted.
   - `BARKLEY_URL`: Barkley, as your browser reaches it, such as
     `http://192.168.1.20:8099`. The login and the links in notifications use it.
4. `docker compose up -d`, open `BARKLEY_URL`, and log in with Home Assistant.

## The login

Every page asks for a login with Home Assistant, using Home Assistant's own login page. It
shows the address that is asking (`BARKLEY_URL`). Only administrators get in, as with the
app. Barkley revokes the login's tokens straight away and keeps only a session of its own
(a cookie that lasts 12 hours, or until Barkley restarts). It never sees your password.

If your browser reaches Home Assistant at another address than the container does (for
example the container uses `http://homeassistant:8123` on a Docker network), set
`HA_BROWSER_URL` to the browser's one.

Already have a reverse proxy that does its own login? Leave out `BARKLEY_URL` and set
`BARKLEY_ALLOW` to the proxy's address instead. Barkley won't start with neither, so the
panel is never open to the network by accident.

## The tool sandbox

Barkley's own AppArmor profile is only for the app, and Docker doesn't load it. On
Docker Desktop, or on a host without AppArmor, there may be no AppArmor at all. What
protects you if a scanner tool is exploited by a file it reads is Barkley's tool
sandbox, built on Landlock, a Linux kernel feature that needs nothing installed on the
host. Each run of Semgrep, GuardDog, osv-scanner or uv:

- can write only that scan's own folder, and can't read the scan store, the token or
  other scans;
- can run only what the image ships, so nothing it downloaded or wrote;
- can connect only to port 443 (Semgrep nowhere), and can't listen;
- can't signal Barkley or read its environment.

It needs Linux 5.13 or later (the port limit 6.7 or later); Docker Desktop has it.
Diagnostics shows "Tool sandbox (Landlock)". **Without it, Barkley doesn't start
standalone**, because it would be parsing hostile code with nothing around it. To run
anyway, knowing that, set `BARKLEY_UNSANDBOXED=1`.

## Settings

Environment variables. Settings you can change in the panel (the AI entity, AI mode,
auto-sniff and the notify target) are kept there once you change them.

| Variable | What it does |
|---|---|
| `HA_URL` | Home Assistant, as the container reaches it: scheme, host and port only |
| `HA_TOKEN_FILE` or `HA_TOKEN` | The long-lived access token (a file is better: it stays out of `docker inspect`) |
| `HA_CA_FILE` | A CA certificate, when an `https` Home Assistant uses a private CA |
| `HA_BROWSER_URL` | Home Assistant, as your browser reaches it, if different |
| `BARKLEY_URL` | Barkley, as your browser reaches it |
| `BARKLEY_ALLOW` | Client addresses to let in, comma-separated (instead of the login, behind a proxy that does its own) |
| `BARKLEY_PORT` | The port inside the container (8099) |
| `BARKLEY_EXPOSURE`, `BARKLEY_PARALLEL`, `BARKLEY_JOBS` | As the app's [options](Options) `exposure`, `parallel_scans`, `jobs` |
| `BARKLEY_AI_ENTITY`, `BARKLEY_AI_MODE`, `BARKLEY_AUTO_SCAN`, `BARKLEY_NOTIFY_TARGET` | Starting values for the panel's settings |
| `GITHUB_TOKEN_FILE` or `GITHUB_TOKEN` | Optional, as the app's `github_token` |
| `BARKLEY_UNSANDBOXED` | `1` starts Barkley on a kernel without Landlock, with the scanner tools unsandboxed |

## Memory

The memory guard reads the container's limit (`mem_limit` in the compose file) as well
as the machine's free memory, and goes by the lower one. Under 2 GB available it warns,
and under 1 GB it doesn't start a scan. With `BARKLEY_PARALLEL` above 1, give it about
1.5 GB more per extra scan.

## Updating

Change the version in `image:` and run `docker compose up -d`. The scans in `data/` are
kept. The image's signature can be checked as for the app; see
[Installing and updating](Installing-and-updating).
