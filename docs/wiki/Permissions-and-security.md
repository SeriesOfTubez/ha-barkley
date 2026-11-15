# Permissions and how Barkley is secured

A security tool that reads hostile code should be held to its own standard.

## What the app can do on your box

- **One permission: the Home Assistant API.** No host network, no open port, no
  Supervisor role, and no access to your configuration folder, so `secrets.yaml` and the
  auth storage are out of its reach. It never opens the installed copies of your apps.
- **What it uses the API for** is a fixed list: reading your Home Assistant version;
  asking the Marketplace for its installed list and its catalog; subscribing to two
  Marketplace signals for auto-sniff; creating the bell notification and, if you picked
  one, calling your notify service; listing your AI Task entities and notify services
  for the two dropdowns; and calling `ai_task.generate_data` only when you click an AI
  button.
- **Its own AppArmor profile, enforcing** (Home Assistant security rating 8). Every
  process in the container can run only the tools the image ships, write only under
  `/data` and `/tmp`, and use only ordinary network sockets. Nothing downloaded is
  executable.
- **The panel** answers only Home Assistant's ingress, which handles the login. It ships
  no JavaScript: its content security policy allows no scripts.

## How scanned code is handled

It is treated as hostile. Barkley never executes, imports, builds or installs it.
Archives are extracted into a fresh temporary folder with protections against path
tricks, symlinks and oversized files. Dependencies are resolved from prebuilt wheels
only, so no build script ever runs.

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
