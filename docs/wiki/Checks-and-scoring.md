# What gets checked and how the score works

Barkley scans exactly what the Marketplace would install: the version you ask for, else
the newest release, else the default branch pinned to one commit.

## What gets checked

- **Code** (Semgrep with Barkley's Home Assistant rules): token and data exfiltration,
  encoded payload loaders, use of auth internals, other integrations' credentials,
  unauthenticated views, tampering with Home Assistant itself.
- **Python dependencies** (integrations): the requirements are resolved the way Home
  Assistant installs them, for x86_64 and aarch64. Then: typosquats, requirements that
  point at a URL or repository, brand-new packages, known vulnerabilities and
  known-malicious packages (osv-scanner), and heuristic malware checks (GuardDog) on every
  package Home Assistant doesn't already ship.
- **npm dependencies** (cards): the repository's lockfile, checked with osv-scanner.
  Known malware is reported for every package; vulnerabilities only for packages bundled
  into the card.
- **Addresses:** every host and IP in the shipped code, sorted into declared, local,
  infrastructure or undeclared. Paste sites, request catchers, tunnels, chat webhooks
  with a built-in token and URLs with a hardcoded public IP are findings.
- **Possible exfiltration:** reading secrets, auth data or other integrations'
  credentials and being able to send data to an undeclared host is flagged high, even
  when the two are in different files.
- **Code you can't read:** compiled `.pyc` files or native `.so` modules that Home
  Assistant's Python would run instead of, or without, readable source.
- **Scanner evasion:** forms that hide code from the scanner are rewritten in Barkley's
  copy (with the same meaning) or flagged. A code file the rules still can't read is its
  own finding.
- **Repository signals:** ownership transfers, a first release by a new publisher, very
  new repositories, release tags that aren't on the default branch, and release zips
  whose code differs from the tagged source.

## The score

The score starts at 100 and each finding takes points off:

| Severity | Points for the first finding of a rule |
|---|---|
| Critical | 60 |
| High | 25 |
| Medium | 8 |
| Low | 2 |

Each repeat of the same rule costs a quarter of that, and one rule can never cost more
than twice its first hit. Then the caps:

- any critical finding: at most 39;
- any high finding: at most 89;
- an unfinished scan: at most 89;
- a code file the rules couldn't read: at most 89.

| Score | Verdict |
|---|---|
| 90–100 | 🦴 Good Boy (passed the sniff test) |
| 70–89 | 🐕 Kinda Sus (a few things worth a look) |
| 40–69 | 🐕‍🦺 Very Sus (the dog won't stop staring at it) |
| 0–39 | 🚨 BORK BORK BORK (do not install) |

The same findings always give the same score. No AI is involved.

## Exposure

With the option `exposure: public` (your Home Assistant is reachable from the internet),
findings about what an app accepts from outside are raised one level. Nothing is ever
lowered, and exfiltration findings are top severity either way.
