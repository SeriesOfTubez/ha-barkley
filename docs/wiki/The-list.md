# The list

Barkley's first page shows what you have installed through the Marketplace, with the
version you run and the version the Marketplace would install now.

## What comes first

Apps that weren't checked yet come first, then the ones that need a look (a checked
update that brings something important, a scan under 90 or unfinished, or an accepted
finding whose code changed), each sorted by score, lowest first. A reviewed app is sorted
and coloured by your reviewed score, shows Barkley's own score beside it, and marks the
chips of findings you accepted with ✓. It stops asking for a look until an accepted
finding's code changes.

## Filters, views and pages

- The counts at the top are filters: needs a look, reviewed by you, on Malware check
  only, no concerns found, with privacy notes, updates waiting, and not checked.
- Switch between **cards** (12 per page) and a **table** (25 per page). Barkley
  remembers the view.
- "What the colours and scores mean" under the list is the legend:

| Score | On the card | Verdict on the app's page |
|---|---|---|
| 90–100 | Fine | 🦴 Good Boy |
| 70–89 | Look | 🐕 Kinda Sus |
| 40–69 | Sus | 🐕‍🦺 Very Sus |
| 0–39 | Bork | 🚨 BORK BORK BORK |
| dashed grey | ? | not checked or unfinished |

A purple chip marks a privacy note. Privacy notes are never scored.

## Buttons

- **Sniff it** on an app scans the version you have installed; **Sniff again** runs a
  fresh scan of it instead of reusing the stored one.
- **Check update** scans the offered version and shows what the update would change. See
  [What an update would change](Update-comparison).
- **Sniff the N not yet sniffed** scans every installed app that has no scan by this
  version of Barkley. **Sniff the N unfinished again** repeats every scan that didn't
  finish. When every app has a scan, **Sniff all N again** runs a fresh scan of each, one
  after another (the memory guard still checks each one). Apps already queued or running
  are skipped.

A button brings you back to the page, filter and view you clicked it on.

## While something runs

A status box at the top shows what is being sniffed, what is queued and what just
finished, and the page reloads itself every 5 seconds until the work is done. The panel
uses no JavaScript, so that reload is how progress is shown.

## Further down

- **Sniffed, not installed:** apps you sniffed from search. Their scans are deleted
  after 7 days unless you install the app.
- **Check any repository:** sniff a repository by name, at the release the Marketplace
  would install or at a tag you give.
- **What would updating change?** for a repository and tag you name.
- **All stored scans** and the **Jobs** table.
- The **Auto-sniff** box, the search box, and the links to **Diagnostics**, **Report an
  issue** (a new public issue on Barkley's GitHub with the versions filled in) and
  **Settings**.
