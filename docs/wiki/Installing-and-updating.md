# Installing and updating

## What you need

- Home Assistant OS or Supervised (Barkley is an app, so it needs the Supervisor), on
  amd64 or aarch64. With Home Assistant Container or Core, or to run Barkley on another
  machine than a small box, see [Standalone (no Supervisor)](Standalone).
- About 200 MB for the download. Most scans use under 0.5 GB of memory, a few big apps
  far more; by default Barkley won't start a scan with under 1 GB free. See
  [Diagnostics and troubleshooting](Diagnostics-and-troubleshooting) for the memory guard.

## Install

1. Settings → Apps → the app store → ⋮ → Repositories, and add
   `https://github.com/SeriesOfTubez/ha-barkley`.
2. Install **Barkley**, start it, and open it from the sidebar.

Home Assistant downloads a prebuilt image for your box. Nothing needs configuring before
the first start; the [options](Options) all have defaults.

## First steps

- Barkley lists what you have installed through the Marketplace. One button sniffs
  everything that hasn't been sniffed yet. See [The list](The-list).
- Auto-sniff is on by default: installs, updates and offered updates are sniffed and you
  get a notification. To also get them on your phone, pick a notify service on
  the Settings page. See [Auto-sniff and notifications](Auto-sniff-and-notifications).
- A GitHub token is optional but useful when you sniff many apps in a row. See
  [Options](Options).

## Updating

Updates appear on the app's page like any other app's. An update of Barkley keeps its
stored scans unless it changed what a scan finds (its rules, its checks or the scanner
tools). When it did, the list offers one button to sniff everything again with the new
rules. Your stored scans and their history are kept either way.

**Updating from 0.14 to 0.15:** 0.15 changes what a scan finds, so the list offers that
button once. The 0–100 score is replaced by two readings, Threat and Exposure (see
[An app's page](An-apps-page)). Reviews, Malware check only and Addresses you trust are
removed, and on its first start 0.15 deletes what 0.14 stored for them: the findings you
accepted, the addresses you trusted and the apps set to Malware check only. Stored scans
and your other settings stay.

## Checking the image's signature (optional)

Each image is built on GitHub's runners by the repository's release workflow and signed
with Cosign by that workflow. Home Assistant doesn't check app signatures, so there is
nothing you have to do. If you'd like to check it yourself, use the version you are
installing:

```sh
cosign verify ghcr.io/seriesoftubez/barkley:0.15.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/SeriesOfTubez/ha-barkley/'
```
