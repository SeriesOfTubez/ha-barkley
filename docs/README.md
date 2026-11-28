# Barkley

Barkley reads the code of Home Assistant Marketplace (formerly HACS) custom integrations and frontend cards before they run in your home. It runs as an app (add-on) in your Home Assistant sidebar. It downloads the code and reads it, and never runs, builds or installs it.

**Before you rely on it**

- **A clean result doesn't make an app safe.** Barkley only catches what its rules describe, so a clean sniff means none of them matched. It reports what it finds and never blocks, moves or removes anything.
- **Barkley was built with AI assistance** (Claude, via Claude Code) under human direction
  and review. Most of the code and these pages are AI-generated. If that is a dealbreaker
  for you, this project isn't for you. The source and the checks that run on every change are public, and [Permissions and how Barkley is secured](Permissions-and-security.md) describes them.
- **The readings come from fixed rules.** Each app gets two, Threat (signs of malicious behavior) and Exposure (what it opens up to someone who isn't an administrator). The optional AI features can explain what a scan found. They can't change a reading, and they're only as good as the model you pick.

## Pages

**Getting started**
- [Installing and updating](Installing-and-updating.md)
- [Standalone (no Supervisor)](Standalone.md): Home Assistant Container, or Barkley on
  another machine
- [The list](The-list.md): what you see when you open Barkley
- [An app's page](An-apps-page.md): the sniff report, with the two readings and everything
  under them

**What Barkley does**
- [What gets checked and how the readings work](Checks-and-scoring.md)
- [Sniff before you install](Sniff-before-you-install.md)
- [What an update would change](Update-comparison.md)
- [Auto-sniff and notifications](Auto-sniff-and-notifications.md)
- [Advisory re-checks](Advisory-re-checks.md)
- [AI explanations](AI-explanations.md)

**Reference**
- [Options](Options.md)
- [Diagnostics and troubleshooting](Diagnostics-and-troubleshooting.md)
- [Permissions and how Barkley is secured](Permissions-and-security.md)
- [FAQ](FAQ.md)

Found a security problem in Barkley itself? Please report it privately through the repository's Security tab → "Report a vulnerability".
