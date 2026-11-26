# Permissions and how Barkley is secured

Barkley reads code it treats as hostile, so this page lists what it can do on your box and how it's protected.

## What the app can do on your box

- **It has one permission, the Home Assistant API.** It has no host network, no open port, no Supervisor role and no access to your configuration folder, so `secrets.yaml` and the
  auth storage are out of its reach. It never opens the installed copies of your apps.
- **What it uses the API for** is a fixed list: reading your Home Assistant version, and
  whether an external URL is set (yes or no; the address isn't kept); asking the
  Marketplace for its installed list and its catalog; subscribing to two Marketplace
  signals for auto-sniff; creating the bell notification and, if you picked
  one, calling your notify service; listing your AI Task entities and notify services
  for the two dropdowns; and calling `ai_task.generate_data` only when you click an AI
  button (over Home Assistant's websocket, because a request through the Supervisor's
  API ends after 5 minutes and a slow model can take longer).
- **Its own AppArmor profile, enforcing** (Home Assistant security rating 8). Every
  process in the container can run only programs the image ships, write only under
  `/data`, `/tmp`, and the folders under `/run` and `/etc` that the container's service
  manager (s6) needs to start Barkley, and use only ordinary network sockets. Nothing
  downloaded is executable.
- **The panel** answers only Home Assistant's ingress, which handles the login. It ships no JavaScript, and its content security policy allows no scripts.

- **Each scanner tool in its own sandbox.** Where the Linux kernel has Landlock, Barkley
  sets it up for every run of Semgrep, osv-scanner or uv. The tool can write only that
  scan's own folder (and uv its package cache). It can read the image and the system,
  but not the scan store, the Home Assistant token or other scans. It can run only what
  the image ships and connect only to port 443; Semgrep can't connect anywhere. It can't
  read Barkley's environment. Landlock needs Linux 5.13 or later; the port limit needs
  6.7 or later, and the limit on signalling Barkley needs 6.12 or later.
- **Home Assistant OS's kernel is built without Landlock** (checked on 6.18). There each
  tool runs in a stricter AppArmor profile of its own, `tools`. It can't read where the
  Supervisor's key is kept, the app's options, the GitHub token or the scan store, and it
  can write only Barkley's caches and the temporary folder. It doesn't limit ports. If
  neither sandbox works, Barkley won't start unless you set `BARKLEY_UNSANDBOXED=1`. The
  Tool sandbox line on the Diagnostics page says which one is on.

When you run Barkley [standalone](Standalone), there's no Supervisor around it. It reaches Home
Assistant with a long-lived token of an administrator, sends it only to `HA_URL`, follows
no redirects and ignores proxy settings. The same fixed list of calls applies, plus the
ones for logging in and for its own token: who logged in, and making, listing and
deleting its own long-lived token. Its panel is on the network, so every page asks for a
login with Home Assistant (administrators only), unless you name the addresses allowed
in instead (`BARKLEY_ALLOW`, for use behind a proxy). Barkley revokes the login's tokens
at once. The one exception is the first-run login, kept only for the setup's Home
Assistant step and for 10 minutes at most. There the container does the containing, and the compose file runs it as a non-root user with a read-only filesystem and no capabilities. The tool sandbox works the same there, and Barkley won't start standalone
without it unless you tell it to.

## How scanned code is handled

It is treated as hostile. Barkley never executes, imports, builds or installs it.
Archives are extracted into a fresh temporary folder with protections against path
tricks, symlinks and oversized files. Dependencies are resolved from prebuilt wheels
only, so no build script ever runs.

One kind of library is downloaded and read: the one an integration hands the login you
gave it (or an address) to. Barkley downloads that library's published package (the
exact version the app gets, checksum checked, at most four per scan and 40 MB each),
unpacks it as files and reads it as text. It is never installed, imported or run.

## Where the image comes from

The release workflow builds the image on GitHub's runners from the source at the release
tag. Every tool is pinned by version, the downloaded binaries by checksum, and nothing
is compiled during the build. The base image's signature is checked before the build,
and a published version is never overwritten. Each image is signed with Cosign;
checking that signature is optional, see
[Installing and updating](Installing-and-updating).

## Checks on every change

Every push and pull request is scanned before it can reach `main`: Gitleaks for secrets,
Semgrep's registry rules and CodeQL for the code, Trivy for dependencies and for the
built image (high and critical CVEs that have a fix), Checkov and Hadolint for the
Dockerfile and the workflows. A finding fails the run. Anything accepted is written down
with its reason in the repository.

## AI-assisted development

Barkley was built with AI pair-programming assistance (Claude, via Claude Code) under
human direction and review, and most of the code and docs are AI-generated. The checks
above run on all of it, and all of it is in the repository to read.
