# The list

Barkley's first page shows what you have installed through the Marketplace, with the
version you run and the version the Marketplace would install now.

## What comes first

1. **Needs a look:** an update Barkley checked that brings something important, or a
   scan that scored under 90 or didn't finish.
2. **Updates not checked yet.**
3. **Updates checked: nothing important changed.**
4. Everything that is up to date and fine folds into one line.

## Filters, views and pages

- The counts at the top are filters: worth a look, no concerns found, with privacy
  notes, updates waiting, and not checked.
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

- **Sniff it / Sniff again** on an app scans the version you have installed.
- **Check update** scans the offered version and shows what the update would change. See
  [What an update would change](Update-comparison).
- **Sniff the N not yet sniffed** scans every installed app that has no scan by this
  version of Barkley. **Sniff the N unfinished again** repeats every scan that didn't
  finish. Apps already queued or running are skipped.

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
- The **Auto-sniff** box, the search box and the link to **Diagnostics**.
