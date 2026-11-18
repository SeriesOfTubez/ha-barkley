# Installing and updating

## What you need

- Home Assistant OS or Supervised (Barkley is an app, so it needs the Supervisor), on
  amd64 or aarch64. With Home Assistant Container or Core, or to run Barkley on another
  machine than a small box, see [Standalone (no Supervisor)](Standalone).
- About 200 MB for the download, and 0.5 to 1 GB of free memory while a scan runs. See
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

Updates appear on the app's page like any other app's. After an update Barkley counts
only scans made by the new version, so the list offers one button to sniff everything
again with the new rules. Your stored scans and their history are kept.

## Checking the image's signature (optional)

Each image is built on GitHub's runners by the repository's release workflow and signed
with Cosign by that workflow. Home Assistant doesn't check app signatures, so there is
nothing you have to do. If you'd like to check it yourself, use the version you are
installing:

```sh
cosign verify ghcr.io/seriesoftubez/barkley:0.14.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/SeriesOfTubez/ha-barkley/'
```
