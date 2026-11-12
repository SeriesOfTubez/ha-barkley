# Security

## Reporting a problem

Please report privately: on this repository's **Security** tab, choose **Report a
vulnerability** (GitHub's private vulnerability reporting). Don't open a public issue
for anything below.

Worth a private report:

- **A way to hide code from Barkley.** A construct that makes a rule, a parser or the
  dependency resolution skip code that Home Assistant would still run, so that a
  malicious integration or card scores better than it should.
- **A way to make Barkley run, build or install the code it scans**, or to write
  outside its workspace while extracting an archive.
- **A way to reach beyond the app's container or its permissions** from scanned
  content, including through the panel (it serves text taken from scanned projects)
  or through the AI explanations (scanned code can contain text aimed at the AI).
- A way to change a score, a finding or a stored scan without the user doing it.

A false positive or a missed pattern with no evasion involved is an ordinary issue.

## What to expect

This is a one-person project. Reports are read, and a fix or an answer follows as soon
as time allows; there is no bounty. Fixes ship as a new app version, and the release
notes say what was fixed once users have had the chance to update.

## Supported versions

Only the newest release.

## The sample code in this repository

`tests/fixtures/`, `tests/rules/` and `demo/` contain deliberately malicious or
suspicious-looking sample code, so the rules have something to catch. It is never run,
by the tests or by anything else, and every address its payloads would send to ends in
`.invalid` or `.example`, which can't resolve. Scanners that flag those folders are
right about the code and wrong about the intent.
