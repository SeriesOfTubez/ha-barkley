# Barkley

Barkley gives Home Assistant Marketplace (formerly HACS) custom integrations and frontend
cards a sniff test before they get into the house. It runs as an app (add-on) in your
Home Assistant sidebar. It downloads the code and reads it; it never runs, builds or
installs it.

**Three things to know first**

- **Barkley is a first pass, not a verdict.** A clean sniff means its checks found
  nothing, not that the code is safe. It reports; it never blocks, moves or removes
  anything.
- **Barkley was built with AI assistance** (Claude, via Claude Code) under human direction
  and review. Most of the code and these pages are AI-generated. If that is a dealbreaker
  for you, this project isn't for you. The source and the checks that run on every change
  are public: see [Permissions and how Barkley is secured](Permissions-and-security).
- **Scores come from fixed rules.** The optional AI features can explain a finding. They
  can never set, clear or change a score.

## Pages

**Getting started**
- [Installing and updating](Installing-and-updating)
- [Standalone (no Supervisor)](Standalone): Home Assistant Container or Core, or Barkley on
  another machine
- [The list](The-list): what you see when you open Barkley
- [An app's page](An-apps-page): the score, the findings and everything under them

**What Barkley does**
- [What gets checked and how the score works](Checks-and-scoring)
- [Sniff before you install](Sniff-before-you-install)
- [What an update would change](Update-comparison)
- [Auto-sniff and notifications](Auto-sniff-and-notifications)
- [Advisory re-checks](Advisory-re-checks)
- [Addresses you trust](Addresses-you-trust)
- [AI explanations](AI-explanations)

**Reference**
- [Options](Options)
- [Diagnostics and troubleshooting](Diagnostics-and-troubleshooting)
- [Permissions and how Barkley is secured](Permissions-and-security)
- [FAQ](FAQ)

Found a security problem in Barkley itself? Please report it privately: the repository's
Security tab → "Report a vulnerability".
