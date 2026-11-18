# Auto-sniff and notifications

Auto-sniff is on by default. Barkley watches the Marketplace and reacts to three things:

- **An install:** it sniffs the version that landed. A stored scan of that exact version
  is reused, for example one you made from search.
- **An update:** it sniffs the new version and shows what changed since the version you
  had.
- **An offered update:** as soon as the Marketplace offers a new version of something
  you have, Barkley sniffs it and tells you what it would change, before you click
  Update.

Barkley also reads the installed list every 10 minutes and once at start, so nothing is
missed while it was stopped.

## Read this before you rely on it

**A new integration runs as soon as it is installed.** Home Assistant opens its setup
dialog right after the files land, which loads its code. For a new install, auto-sniff
can only report on what you already let in. The protection is to
[sniff it from search first](Sniff-before-you-install). An update's new code waits for
the next restart, so there the sniff and the comparison come before the code runs.

Barkley reports. It never moves, refuses or blocks anything.

## Notifications

Every result sends a bell notification in Home Assistant. If you pick a notify service
on the Settings page (Notify; for example your phone through the companion app), it gets
the same message. **Send a test notification** there sends a sample through both. Recent
auto-sniffs are listed on the Settings page too.

A notification carries the app's `owner/repo` name and version, the verdict and score,
up to three things worth a look in fixed wording, for an update a count of what changed,
and a link to open Barkley. It never contains text from the scanned project: no code, no
package names, no README text.

## Turning it off

Set Auto-sniff to Off on the Settings page, or use the `auto_scan` option. The Settings
page wins over the option.
