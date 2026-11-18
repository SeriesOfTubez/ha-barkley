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

## Kinds of findings

Since 0.14.0 every finding has a kind, and an app's page groups them:

- **Threats**: signs of malicious behavior. Sending your data or logins off the box
  (traced, or possible), addresses used to collect stolen data, known malware, code
  that decodes or downloads code and runs it, disguised code, and code you can't read
  (compiled files, native modules, the `<!--` trick, names built from pieces).
- **What it can do**: powerful things the app is able to do, such as changing who can
  log in, reading other apps' settings or running programs. Normal for some apps; it's
  what an attacker would get if the app were ever compromised.
- **Known bugs in its libraries**: published vulnerabilities.
- **How it's made**: release and dependency habits, usage reporting.
- **What Barkley couldn't read**: code files the rules couldn't parse.

The kind never changes a severity.

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

### Settings that change the score

On Barkley's Settings page (the defaults are Barkley's own score):

| Setting | Default | What it does |
|---|---|---|
| Paranoid mode | Off | Off: minor findings aren't shown or counted. They touch no password or login, change nothing, and usually have a plain reason: listing user accounts, reading other apps' settings (options, not their stored data), writing its own files in `.storage`, a bug in a build tool that never ships in a card, installing its own declared libraries, and usage reporting that is disclosed or optional. An app's page says how many it left out, with a link to show them. |
| Powerful, no threat | On | With no Threat finding and no critical one, a complete scan doesn't go below 40 (Very Sus): what an app can do, alone, never makes it BORK. |
| Pages without a login | List only | With exposure Local only, an app's pages that work without a login aren't counted. With exposure Public they always count. |
| Hidden usage reporting | Count it | Usage data an app sends by itself, with no setting to turn it off, and doesn't tell you about. |

### Your review

You can mark findings reviewed on an app's page, one at a time or with Accept all at the
top (each Threat needs its own tick; known malware can never be accepted). The circle then
shows your **reviewed score**: the same formula without the findings you accepted.
Barkley's own score is kept unchanged and shown beside it, with what your review added.

An acceptance follows the code, not the line number: the same code in the next version
stays accepted; changed code opens the finding again, notifies you (a setting), and
"What changed?" shows the code then and now. Settings → Ask again can also reopen
acceptances after 6 or 12 months. Addresses you trust count as reviewed too.

Per app, **Malware check only** shows and notifies only Threats and known malware. The app
is still checked the same way; it cuts noise, not memory or time.

## Exposure

With exposure set to Public (Settings) (your Home Assistant is reachable from the internet),
findings about what an app accepts from outside are raised one level. Nothing is ever
lowered, and exfiltration findings are top severity either way.
