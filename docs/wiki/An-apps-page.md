# An app's page

Every scan has a page. From top to bottom:

- **The score and verdict.** Once you've reviewed findings, the circle shows your
  reviewed score, with Barkley's own score in a small circle beside it and what your
  review added. Barkley's own score never changes. "Powerful" marks an app that can do a
  lot while nothing points to malicious behavior. Stars on GitHub and the downloads of
  the release file are shown as facts and never scored (an app installed from its source
  has no release file, so its downloads aren't counted). See
  [What gets checked and how the score works](Checks-and-scoring).
- **Accept all**, right under the score: marks every finding of this version reviewed,
  with an optional note. Each Threat needs its own tick, and known malware can never be
  accepted.
- **In short:** a few sentences built from the scan by fixed rules (no AI).
- **What we found:** every finding in plain words, grouped by kind (Threats first), with
  what it means and where in the code it is. "Technical details" under a finding has the
  rule name and the evidence. Under each finding: **Mark reviewed** (with a note), or
  **✓ Accepted** with who accepted it and when (**Undo** takes it back), or, when the code
  changed since you accepted it, **What changed?** and **Accept again**. **Report a false
  positive** opens a new public issue on Barkley's GitHub with the versions, the rule, the
  file and the line filled in; you write why it's wrong and submit it yourself. Minor
  findings are left out unless you show them or turn on Paranoid mode.
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
  workflows or through pre-commit (Gitleaks, detect-private-key, Ruff's security rules and
  the like; since 0.14.1, and only checks a workflow runs count toward the star), has Dependabot or Renovate and a SECURITY.md, how many dependency-update
  pull requests wait, and open issues that look security-related. This is context from
  public signs and never changes the score. When every check is green, a gold star says
  **A+ security habits**; a dependency-update pull request younger than 7 days doesn't
  count against it.
- **History:** every stored scan of this app.

## Actions on the page

- **Sniff this version again** runs a fresh scan instead of reusing the stored one.
- **Other versions** lists the 10 newest releases, betas included.
- **Malware check only** shows and notifies only Threats and known malware for this app;
  **Show everything again** undoes it.
- **Check advisories again**: see [Advisory re-checks](Advisory-re-checks).
- **Explain this app** and, in deep mode, **Explain in context**: see
  [AI explanations](AI-explanations).

## "Unfinished"

A scan is unfinished when something that may work next time went wrong: a tool timed out
or a service couldn't be reached. Its score is capped at 89, it is never reused, and the
page offers **Sniff again**. A file Barkley's code rules can't read at all is different:
it happens on every sniff, so it is a finding in a finished scan.
