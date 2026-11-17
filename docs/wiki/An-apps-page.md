# An app's page

Every scan has a page. From top to bottom:

- **The score and verdict.** If you trust addresses for this app, the score shown counts
  them as fine and Barkley's own score is shown beside it. See
  [Addresses you trust](Addresses-you-trust).
- **In short:** a few sentences built from the scan by fixed rules (no AI).
- **What we found:** every finding in plain words, most serious first, with what it means
  and where in the code it is. "Technical details" under a finding has the rule name and
  the evidence.
- **Where your data can go:** a diagram of the flows Barkley saw. Arrows point outward to
  sites the app contacts and inward for ports it listens on; a line without an arrow
  means the direction is unknown.
- **Where it connects:** each address and port from the code. A well-known service is
  named as a hint; that name never changes a score, and no address is ever sent anywhere
  to be looked up.
- **Privacy notes** such as telemetry, analytics or unencrypted connections. They are
  never scored. In deep mode a note links to the AI's reading of the address or port
  behind it.
- **What it can do inside Home Assistant:** the services, views and events it hooks into.
- **The developer's security habits:** whether the project runs security scanners in its
  workflows, has Dependabot or Renovate and a SECURITY.md, how many dependency-update
  pull requests wait, and open issues that look security-related. This is context from
  public signs and never changes the score.
- **History:** every stored scan of this app.

## Actions on the page

- **Sniff this version again** runs a fresh scan instead of reusing the stored one.
- **Other versions** lists the 10 newest releases, betas included.
- **Check advisories again**: see [Advisory re-checks](Advisory-re-checks).
- **Explain this app** and, in deep mode, **Explain in context**: see
  [AI explanations](AI-explanations).

## "Unfinished"

A scan is unfinished when something that may work next time went wrong: a tool timed out
or a service couldn't be reached. Its score is capped at 89, it is never reused, and the
page offers **Sniff again**. A file Barkley's code rules can't read at all is different:
it happens on every sniff, so it is a finding in a finished scan.
