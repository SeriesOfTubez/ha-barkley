# Auto-sniff and notifications

Auto-sniff is on by default. Barkley watches the Marketplace and reacts to three things:

- **An install:** it sniffs the version that landed. A stored scan of that exact version
  is reused, for example one you made from search.
- **An update:** it sniffs the new version and shows what changed since the version you
  had.
- **An offered update:** as soon as the Marketplace offers a new version of something
  you have, Barkley sniffs it and tells you what it would change, before you click
  Update. This includes an older version you install on purpose while a newer one
  is offered: both versions are sniffed.

Barkley also reads the installed list every 10 minutes and once at start, so nothing is
missed while it was stopped.

## Read this before you rely on it

**A new integration runs as soon as it is installed.** Home Assistant opens its setup
dialog right after the files land, which loads its code. For a new install, auto-sniff can only report on what you already let in. To check a new app before it runs, [sniff it from search first](Sniff-before-you-install). An update's new code waits for
the next restart, so there the sniff and the comparison come before the code runs.

Barkley only reports. It never moves, refuses or blocks an app.

## Notifications

By default every result sends a bell notification in Home Assistant. Settings → Notify
when can limit that to Exposure medium or high, Exposure high, or only signs of
malicious behavior. Signs of malicious behavior always notify, and so does a sniff that
didn't finish or couldn't run. Every result is still listed under Auto-sniff activity
on the Settings page and on the app's page. If you pick a notify service
on the Settings page (Notify; for example your phone through the companion app), it gets
a shorter message: the app and version are in its title, the body starts with the two
readings, and tapping it opens Barkley. **Send a test notification** there sends a sample through both. Recent
auto-sniffs are listed on the Settings page too.

A notification carries:

- the app's `owner/repo` name and version;
- the two readings, each with a coloured light: 🟢 for no threat found or Low exposure,
  🟡 for a possible threat or Medium exposure, 🔴 for a found threat or High exposure.
  The Exposure number is given when it isn't 0, and for an update the number before it
  when it changed;
- for a found or possible threat, one fixed sentence saying what it is. For a found
  threat the title says so and the message says: "Remove it, then log out of Home
  Assistant everywhere.";
- for an update, counts of what changed;
- "Part of the check didn't finish." when it didn't;
- a link to open Barkley.

It never contains text from the scanned project (no code, no package names, no README
text) and nothing written by an AI.

## Turning it off

Set Auto-sniff to Off on the Settings page, or use the `auto_scan` option. The Settings
page wins over the option.
