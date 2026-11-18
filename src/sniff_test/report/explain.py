"""Plain-English text for every rule, for people who don't know application security.

Fixed in code like the rules themselves. Nothing here changes a score or a severity;
the panel shows it next to the finding, and the technical line stays underneath.

Each rule answers three questions:
- `title`: what was found, as a headline;
- `means`: what that is and why it can matter;
- `worry`: should you worry, and when it would be a real problem.
`chip` is a two-to-four word label for the card grid.

`tests/test_explain.py` checks that every rule id the scanner can produce has text.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Explanation:
    title: str
    means: str
    worry: str
    chip: str
    # (label, https URL) pairs shown as "Read more"; fixed here, never from a report.
    links: tuple[tuple[str, str], ...] = ()


LEVELS = {
    "critical": "Danger",
    "high": "Serious",
    "medium": "Worth a look",
    "low": "Minor",
    "info": "FYI",
}

_E = Explanation

RULES: dict[str, Explanation] = {
    # --- data leaving your box -------------------------------------------------------
    "ha-exfil-taint": _E(
        "Sends private Home Assistant data out of your home",
        "We traced private data (such as passwords, login tokens or other apps' settings) "
        "from where the code reads it to where it sends it over the network or to another "
        "program. Apps run inside Home Assistant with no walls around them, so this is "
        "exactly what stealing your data looks like.",
        "Yes. Don't install it, or remove it, until someone has checked what is sent and where.",
        "Sends your data out",
    ),
    "possible-exfil": _E(
        "Reads private data and talks to a site we can't explain",
        "The app reads something private (for example your secrets file or other apps' "
        "passwords) and also contacts a site that isn't in its own documentation. We could "
        "not trace a direct path between the two, so this is a warning sign, not proof.",
        "Take it seriously. Check what the app reads and why, and what the unexplained site "
        "is, before trusting it.",
        "Possible data leak",
    ),
    "card-token-exfil": _E(
        "Its dashboard card may send your login to another site",
        "Dashboard cards run inside your Home Assistant page in the browser. This one puts "
        "your Home Assistant login token into a web request that we couldn't prove stays "
        "on your own Home Assistant. Anyone who gets that token can act as you, from "
        "anywhere.",
        "Yes, until you know where the request goes. A card should only ever send your "
        "login to your own Home Assistant.",
        "May send your login out",
    ),
    "endpoint-exfil-host": _E(
        "Talks to a site used for collecting data",
        "The code contains the address of a paste site, a request catcher, a tunnel, or a "
        "chat webhook with its key built in. Those are places where someone collects what "
        "is sent to them. A normal app has no reason to send anything there.",
        "Yes. This is a common way to carry stolen data out.",
        "Data-collection site",
    ),
    "endpoint-public-ip-literal": _E(
        "Connects to a raw internet address instead of a site name",
        "The code connects to a hard-coded internet IP address rather than a named site. "
        "Real cloud services use names; fixed IP addresses are typical of servers that "
        "control malware.",
        "Worth checking what that address is. It is sometimes a forgotten test server.",
        "Hard-coded IP address",
    ),
    # --- your logins, secrets and other apps' data -------------------------------------
    "ha-read-secrets": _E(
        "Reads your secrets file",
        "secrets.yaml holds the passwords and keys for your whole Home Assistant. Apps get "
        "their own settings through Home Assistant and have no need to open this file.",
        "Yes, unless the app is a tool built specifically to manage your configuration "
        "and you trust it.",
        "Reads your secrets",
    ),
    "ha-read-auth-storage": _E(
        "Opens Home Assistant's login and password storage",
        "These files hold password hashes, login tokens and every app's saved passwords. "
        "No normal app opens them directly.",
        "Yes. Find out why before keeping it.",
        "Reads login storage",
    ),
    "ha-raw-storage-access": _E(
        "Looks inside Home Assistant's private storage folder",
        "Home Assistant keeps its internal data, including login data, in a hidden "
        ".storage folder. Apps are meant to use a helper that keeps them in their own "
        "file. This one builds a path into that folder by hand.",
        "Usually not, but check what it opens. Many apps do this to tidy up their own "
        "files; reading other files there would be a problem.",
        "Reads HA's private storage",
    ),
    "ha-own-storage-path": _E(
        "Keeps its own file in Home Assistant's storage folder",
        "The app writes its own file into Home Assistant's .storage folder, where Home "
        "Assistant also keeps logins and every integration's settings. It builds the "
        "file's path itself; Home Assistant's code has a helper (Store) that does this "
        "for an app. Home Assistant has no documentation page saying which way to use.",
        "No. The file is the app's own; this is shown for information and isn't scored.",
        "Own storage file",
        (
            (
                "Home Assistant's Store helper (source)",
                "https://github.com/home-assistant/core/blob/dev/homeassistant/helpers/storage.py",
            ),
            (
                "Home Assistant developer blog, 2022: Store is now a Generic class",
                "https://contributors.home-assistant.io/blog/2022/07/08/generic-store/",
            ),
        ),
    ),
    "ha-auth-internals": _E(
        "Handles Home Assistant login tokens",
        "The app reads, creates or removes login tokens, or reaches into Home Assistant's "
        "own login store. A login token lets whoever holds it act as that user.",
        "Yes, unless that's the app's whole purpose (for example a login add-on).",
        "Handles login tokens",
    ),
    "ha-auth-change-users": _E(
        "Changes who can log in to Home Assistant",
        "The app can create, enable, disable or remove user accounts.",
        "Only if the app isn't meant to manage users. A user-management tool needs this.",
        "Changes user accounts",
    ),
    "ha-auth-list-users": _E(
        "Reads the list of Home Assistant users",
        "The app lists every user account: names, ids and who is an administrator. Apps "
        "do this to offer a list of people to pick from, for example in their own panel.",
        "Usually not. The list holds no passwords or login tokens.",
        "Lists users",
    ),
    "ha-foreign-entry-data": _E(
        "Reads other apps' saved passwords and settings",
        "Each app keeps its passwords and API keys in its own settings entry. This one "
        "reads the entries of other apps.",
        "Yes, unless it's a tool built to manage other integrations and you trust it.",
        "Reads other apps' passwords",
    ),
    "ha-foreign-entry-options": _E(
        "Reads other apps' settings",
        "Apps keep their options (filters, chosen devices, entity lists) separately from "
        "their passwords. This one reads the options of other apps.",
        "Usually not. Tools that check or tidy up other integrations do this.",
        "Reads other apps' settings",
    ),
    "ha-bulk-location-read": _E(
        "Reads where the people in your home are",
        "The app reads the location of people and tracked devices in your home.",
        "Only if the app has nothing to do with location. For presence or map apps it's expected.",
        "Reads locations",
    ),
    "ha-supervisor-token": _E(
        "Reads the key that controls your whole Home Assistant system",
        "The Supervisor key can install and remove apps, make and restore backups, and "
        "control the machine. Custom integrations have no need for it.",
        "Yes. Find out why before keeping it.",
        "Reads the system key",
    ),
    "card-read-tokens": _E(
        "Its dashboard card reads your saved login",
        "Your browser keeps a long-lived Home Assistant login in its storage. Cards talk to "
        "Home Assistant through the page and never need that saved login. A card that "
        "reads it can keep acting as you even after you close the page.",
        "Yes. A card has no good reason to do this.",
        "Reads your saved login",
    ),
    "card-access-token-use": _E(
        "Its dashboard card uses your Home Assistant login",
        "Dashboard cards run inside your Home Assistant page in the browser. This one reads "
        "your login token, the key your browser uses to prove it's you, usually to load "
        "data from Home Assistant. Anything holding that key can do whatever you can do.",
        "Usually not. It only matters where the login is sent. We check that separately, "
        "and a card that sends it to another site gets a serious finding of its own.",
        "Uses your login",
    ),
    # --- running code it didn't ship ---------------------------------------------------
    "py-b64-exec": _E(
        "Hides code and then runs it",
        "The app decodes a scrambled block of text and runs it as code. Hiding code like "
        "this only makes sense if someone doesn't want it read. It's a classic way to "
        "smuggle in malware.",
        "Yes. Don't install it until someone has decoded and read that code.",
        "Runs hidden code",
    ),
    "py-eval-exec": _E(
        "Builds code while running and executes it",
        "The app turns text into code and runs it. Whatever ends up in that text runs with "
        "full access to Home Assistant, so it matters where the text comes from.",
        "Worth checking. It's sometimes used for harmless formulas or templates.",
        "Runs built-up code",
    ),
    "py-dynamic-import": _E(
        "Loads code whose name is only known while running",
        "The app picks which code to load at run time. Reading the code can't tell what "
        "will actually be loaded.",
        "Usually not. Many apps load their own parts this way.",
        "Loads code dynamically",
    ),
    "py-runtime-pip": _E(
        "Installs extra software while running",
        "The app installs Python packages by itself while Home Assistant runs, skipping "
        "the list it declares. Nobody checks those packages, and all apps share them.",
        "Yes. Ask why it doesn't declare them like other apps do.",
        "Installs software itself",
    ),
    "py-runtime-pip-listed": _E(
        "Installs named software while running",
        "The app installs Python packages itself instead of declaring them, but the "
        "package names are written in its code, so Barkley checked those packages like "
        "the declared ones.",
        "Usually not. It's an old habit; the packages it installs were checked.",
        "Installs listed packages",
    ),
    "py-shell-exec": _E(
        "Runs commands on your system",
        "The app runs system commands. That can be fine (for example calling a helper "
        "program), but it matters what is run and whether any part of it comes from "
        "outside the app.",
        "Worth a look at what it runs.",
        "Runs system commands",
    ),
    "py-obfuscation": _E(
        "Uses tricks that make its code hard to read",
        "The code uses techniques that hide what it does, such as large scrambled blocks "
        "or text built one character at a time. Honest code rarely needs these.",
        "Worth checking what is being hidden.",
        "Hard-to-read code",
    ),
    "py-write-outside-own-dir": _E(
        "Writes or deletes files outside its own folder",
        "The app writes to sensitive places: your configuration, login storage, other "
        "apps' code, or system files. That can be how malware keeps itself installed or "
        "changes other apps.",
        "Yes. Check exactly which files it changes.",
        "Changes other files",
    ),
    "ha-monkeypatch": _E(
        "Changes how Home Assistant itself works",
        "The app replaces parts of Home Assistant, its login system, or its network and "
        "encryption code while running. That changes things for every app, and it's a way "
        "to hide traffic, grab passwords on the way, or switch off security checks.",
        "Yes. Find out what it replaces and why.",
        "Changes HA itself",
    ),
    "py-bytecode-runs-instead-of-source": _E(
        "Ships compiled code that runs instead of the readable code",
        "The app includes pre-compiled Python files that Home Assistant would run instead "
        "of the readable source next to them. What runs may not match what anyone "
        "reviewed.",
        "Yes. There's no good reason to ship these in an integration.",
        "Unreadable code runs",
    ),
    "py-native-module-shadows-source": _E(
        "Ships a compiled module that replaces readable code",
        "The app includes a compiled program file with the same name as a readable Python "
        "file. Home Assistant loads the compiled one, which nobody can read.",
        "Yes. What runs isn't what anyone reviewed.",
        "Unreadable code runs",
    ),
    "py-native-module-without-source": _E(
        "Ships compiled code with no readable version",
        "The app includes a compiled program file that Home Assistant can load, with no "
        "readable source. We can't check what it does.",
        "Yes, unless the developer explains it and you trust them.",
        "Unreadable code",
    ),
    # --- dashboard cards ---------------------------------------------------------------
    "card-b64-eval": _E(
        "Its dashboard card hides code and then runs it",
        "The card decodes scrambled text and runs it as code in your browser, with your "
        "Home Assistant login. Hiding code this way only makes sense if someone doesn't "
        "want it read.",
        "Yes. Don't install it until someone has decoded that code.",
        "Runs hidden code",
    ),
    "card-hidden-name": _E(
        "Its dashboard card spells out a sensitive name in pieces",
        "The card builds a name like fetch (send data), eval (run text as code) or "
        "hassTokens (your stored login) from pieces while running, for example "
        "['fe','tch'].join(''). Code only does this so the name can't be found by "
        "reading or searching it. We put the pieces together and checked what the code "
        "does with the name; anything found is listed separately.",
        "Yes. Find out why the card hides the name before you install it.",
        "Hides a name",
    ),
    "card-eval-remote": _E(
        "Its dashboard card runs code it gets from outside",
        "The card takes text from a download, a message, the page address or browser "
        "storage and runs it as code in your browser, with your Home Assistant login. That "
        "code was never part of what we checked, and whoever controls its source controls "
        "what runs.",
        "Yes, unless you know where that code comes from and trust it.",
        "Runs outside code",
    ),
    "card-eval": _E(
        "Its dashboard card builds code while running and executes it",
        "The card puts together a piece of code and runs it in your browser, with your "
        "Home Assistant login. Charting and template libraries do this to make their own "
        "code fast. We found no sign the code comes from outside the card, but we can't "
        "follow it everywhere.",
        "Usually not. It would matter if the pieces could come from the internet.",
        "Runs built-up code",
    ),
    "card-eval-config": _E(
        "Its dashboard card runs code from its own settings",
        "The card runs bits of code you write in its dashboard settings (to support "
        "templates). Only people who can edit your dashboards control that.",
        "Only if you paste card settings from sources you don't trust.",
        "Runs code from settings",
    ),
    "card-remote-script": _E(
        "Its dashboard card loads code from the internet",
        "The card downloads extra code from a website while running. That code runs with "
        "your Home Assistant login, and it was never part of what we checked.",
        "Worth a look: whoever controls that website controls what runs in your dashboard.",
        "Loads code from the web",
    ),
    "card-html-comment-token": _E(
        "Its dashboard card uses a trick that hides code from scanners",
        "The card contains `<!--` inside its code. Many scanners skip the rest of such a "
        "line, but browsers run it. We read the hidden part anyway.",
        "Worth a look. Normal code and normal build tools don't produce this.",
        "Scanner-hiding trick",
    ),
    # --- doors into your Home Assistant -----------------------------------------------
    "ha-unauth-view": _E(
        "Adds a web page that works without logging in",
        "The app adds an address to your Home Assistant that anyone who can reach it can "
        "open without a login. That's normal for things like sign-in callbacks and image "
        "links.",
        "Usually not. It matters more if your Home Assistant is reachable from the internet.",
        "Page without login",
    ),
    "ha-cors-allowed": _E(
        "Lets other websites call one of its pages",
        "The app allows web pages on other sites to call one of its Home Assistant pages "
        "from your browser.",
        "Usually not. It's worth knowing if your Home Assistant is reachable from the internet.",
        "Open to other sites",
    ),
    "ha-webhook-remote": _E(
        "Accepts messages from the internet",
        "The app sets up a webhook, an address that accepts messages from outside your "
        "home. The webhook's secret address is the only thing protecting it.",
        "Usually not. Webhooks are how many cloud services notify Home Assistant.",
        "Internet webhook",
    ),
    # --- the code libraries it uses ---------------------------------------------------
    "dep-malicious": _E(
        "Uses a code library known to be malware",
        "One of the code libraries this app installs is on a public list of known "
        "malicious packages.",
        "Yes. Don't install it.",
        "Malware library",
    ),
    "dep-vuln": _E(
        "Uses a code library with known security bugs",
        "One of the code libraries this app uses has publicly known security bugs. A newer "
        "version of that library usually fixes them.",
        "Depends on the bug. Most only matter in situations a Home Assistant app doesn't "
        "hit, but it's worth updating the app when a fix ships.",
        "Outdated library",
    ),
    "telemetry-shadow": _E(
        "Sends usage data on its own, without telling you",
        "The app reports how it's used to a server the developer runs, by itself (when "
        "Home Assistant starts or on a timer). Barkley found no option in the code to "
        "turn it off, and the app's description doesn't mention it.",
        "It's a privacy matter, not an attack: the server learns your home's internet "
        "address and whatever the report contains. Ask the developer what it sends.",
        "Hidden telemetry",
    ),
    "telemetry-opt-out": _E(
        "Sends usage data unless you turn it off",
        "The app reports how it's used to a server the developer runs, by itself. It's "
        "either on by default behind an option, or the app's description mentions it.",
        "A privacy choice: check the app's options if you'd rather it didn't.",
        "Telemetry, on by default",
    ),
    "telemetry-usage": _E(
        "Can send usage data to the developer",
        "The code has what looks like usage reporting to a server the developer runs. "
        "Barkley says below what it could tell about when it's sent.",
        "Shown for information and not scored.",
        "Usage reporting",
    ),
    "dep-build-tool-vuln": _E(
        "A build tool with known security bugs",
        "The card lists a tool that turns its source into the JavaScript you download "
        "(such as rollup or babel). That tool has publicly known bugs, but it only runs on "
        "the developer's machine when the card is built; none of its code is in the card.",
        "No, not for you: the bugs are in the developer's build step. Shown for "
        "information and not scored.",
        "Build tool",
    ),
    "dep-typosquat": _E(
        "Uses a code library with a name one typo away from a popular one",
        "Copycat packages copy well-known names with a small typo so that people install "
        "them by mistake.",
        "Worth checking it's the real thing. Sometimes it's a genuine, unrelated package.",
        "Lookalike library",
    ),
    "dep-vcs-or-url-requirement": _E(
        "Installs a code library straight from a web address",
        "Instead of a normal package, one of its libraries comes straight from a website "
        "or a code repository. What's there can change at any time, without a new "
        "version.",
        "Worth a look: you can't know what will be installed next time.",
        "Library from a web address",
    ),
    "dep-invalid-requirement": _E(
        "Has a strange entry in its list of libraries",
        "One entry in the list of libraries it asks Home Assistant to install isn't a "
        "plain package name. Some entries like this can change how installing works.",
        "Worth a look at what the entry does.",
        "Odd library entry",
    ),
    "dep-very-new-package": _E(
        "Uses a brand-new code library",
        "One of its libraries was first published only days ago. New packages have no "
        "track record, and most malicious packages are caught within days.",
        "Worth waiting a little, or checking the package.",
        "Brand-new library",
    ),
    "dep-unresolvable": _E(
        "Asks for a library version that can't be installed",
        "Home Assistant couldn't install one of the libraries this app asks for, so we "
        "couldn't check that part either.",
        "Mostly a sign the app may not work. It also means part of it went unchecked.",
        "Library can't install",
    ),
    "dep-sdist-only": _E(
        "Builds one of its libraries on your machine",
        "One library has no ready-made package, so Home Assistant would build it from "
        "source on your machine. Building runs that library's own setup code.",
        "Usually not, but building runs code we couldn't check.",
        "Built on your machine",
    ),
    "dep-npm-no-lockfile": _E(
        "Doesn't pin the versions of the code it's built from",
        "The card is built from code libraries it doesn't pin to exact versions. Each time "
        "the developer builds a new release, it can pick up newer versions of those "
        "libraries, which is how a hijacked library gets into a card. The release you'd "
        "install is already built, and we checked its code, but we couldn't match the "
        "libraries inside it against known-malicious versions.",
        "Not about this release. It's a weakness in how future releases get built: worth "
        "checking the next update.",
        "Library versions unpinned",
    ),
    # --- who publishes it --------------------------------------------------------------
    "repo-transferred": _E(
        "The project changed owners",
        "This project now belongs to a different account than before. Handovers are often "
        "fine, but taking over a trusted project is also a known way to ship malware to "
        "its users.",
        "Worth a look at who the new owner is, especially if the change is recent.",
        "Changed owners",
    ),
    "repo-new-maintainer-release": _E(
        "The installed version was published by someone new",
        "This version is the first one published by this person; earlier versions came "
        "from others.",
        "Worth a look at who they are. New helpers are common in healthy projects.",
        "New publisher",
    ),
    "repo-young": _E(
        "The project is very new",
        "The project was created recently, so it has little history and few people have "
        "looked at it.",
        "Not by itself. Just less track record.",
        "New project",
    ),
    "repo-no-releases": _E(
        "The project has no releases",
        "Without releases, the Marketplace installs whatever is in the project right now. "
        "We checked that exact version, but it can change at any time without a version "
        "number.",
        "Not by itself. It just makes changes harder to follow.",
        "No releases",
    ),
    "repo-release-fills-constant": _E(
        "The download fills in a value the public code leaves empty",
        "The code you install is the same as the code on GitHub, except for a setting "
        "that is empty there and filled in the download, usually a key for the "
        "developer's own service that they keep out of public view. It isn't a web "
        "address.",
        "Usually not. The rest of the code matches what anyone can review.",
        "Fills in a key",
    ),
    "repo-release-source-mismatch": _E(
        "The download differs from the code people can read",
        "The files the Marketplace installs differ from the same files in the project's "
        "public code. Reviewing the project doesn't review what you actually install.",
        "Worth a look at what's different.",
        "Download differs from code",
    ),
    "repo-release-extra-code": _E(
        "The download contains code that isn't in the project",
        "The release download includes code files that aren't in the public project, "
        "such as generated or bundled files. We checked them, but nobody else can review "
        "them in the project.",
        "Usually not, but it's extra code with no public history.",
        "Extra code in download",
    ),
    "repo-release-asset-missing": _E(
        "The release is missing the file the project says to install",
        "The project says to install a specific download, but the release doesn't have "
        "it, so the Marketplace falls back to the source code.",
        "No. We checked what it would install instead.",
        "Release file missing",
    ),
    "repo-tag-off-default-branch": _E(
        "The installed version isn't on the project's main line",
        "The version you install contains changes that never landed in the project's "
        "main code, where people normally review it.",
        "Worth a look at what those changes are.",
        "Unreviewed changes",
    ),
    "repo-multiple-integrations": _E(
        "The project contains more than one integration",
        "The project has several integration folders. We checked the one the Marketplace installs.",
        "No.",
        "Several integrations",
    ),
    # --- coverage ----------------------------------------------------------------------
    "scan-parse-error": _E(
        "Part of the code was too tangled for us to read",
        "One section of a file couldn't be fully read by our scanner, so we can't vouch "
        "for that part.",
        "Usually not. It happens with big compressed files. It's listed so a gap in "
        "coverage is never hidden.",
        "Partly unreadable",
    ),
    "scan-file-not-checked": _E(
        "A whole code file couldn't be read by our code checks",
        "Our code scanner couldn't make sense of this file at all, so none of its checks "
        "ran on it. The other checks (addresses it names, code libraries, the project's "
        "history) still did.",
        "Worth knowing. Nothing bad was found in it, but we couldn't look, so the score "
        "can't go above 89 while a file like this is there.",
        "File not checked",
    ),
}

# GuardDog heuristics on dependencies. The rule id is built from GuardDog's rule name,
# so new names can appear; they fall back to _GUARDDOG.
_GUARDDOG = _E(
    "One of its code libraries has suspicious-looking code",
    "An automatic check of one of its code libraries found a pattern often seen in "
    "malware. It's a rule of thumb, not proof.",
    "Worth a look. Popular, well-known libraries often trip these checks harmlessly.",
    "Suspicious library code",
)
GUARDDOG_WHAT = {
    "network-exfil-messenger": "sends data to a chat service",
    # GuardDog's rule matches the address alone (a drop-box service, an ending such as
    # .xyz, a public IP), not a data flow; the old text "reads data and sends it out"
    # claimed more than the rule sees (0.8.0)
    "network-exfiltration": "names an address of a kind often used to collect stolen data",
    "network-dns-exfil": "hides data in internet name lookups",
    "network-exfil-sysinfo": "sends details about your system out",
    "network-reverse-shell": "opens a remote-control connection",
    "runtime-keylogging": "records keystrokes",
    "runtime-screencapture": "takes screenshots",
    "runtime-obfuscation-base64exec": "decodes hidden code and runs it",
    "process-download-exec": "downloads a program and runs it",
    "process-cryptomining": "looks like a cryptocurrency miner",
    "runtime-self-propagation": "copies itself elsewhere",
    "process-injection-dll": "injects code into other programs",
    "process-powershell-encoded": "runs hidden PowerShell commands",
    "setup-network-in-install": "goes online while being installed",
    "filesystem-destruction": "deletes files in bulk",
    "runtime-obfuscation-steganography": "hides code inside images",
    "runtime-obfuscation": "uses code that's hard to read",
    "runtime-obfuscation-general": "uses code that's hard to read",
    "runtime-obfuscation-api": "calls functions in a way that hides what they are",
    "runtime-obfuscation-import-exec": "loads and runs code in a hidden way",
    "runtime-obfuscation-dynamic-eval": "builds code while running and executes it",
    "runtime-obfuscation-chr": "builds text one character at a time to hide it",
    "runtime-obfuscation-unicode": "uses lookalike characters in its code",
    "runtime-obfuscation-hidden-code": "contains code hidden from view",
    "runtime-obfuscation-pyarmor": "is scrambled with a code-protection tool",
    "runtime-obfuscation-log-suppress": "switches off logging",
    "network-outbound-shady-links": "contains links to suspicious sites",
    "process-spawn-silent": "starts programs silently in the background",
    "filesystem-autostart": "sets something up to start automatically",
    "setup-suspicious-imports": "loads unusual modules while being installed",
    "setup-import-aliasing": "renames modules while being installed",
    "process-hooks": "hooks into other programs",
    "runtime-dynamic-loader": "loads code whose name is only known while running",
}

_UNKNOWN = _E(
    "Something worth knowing",
    "One of our checks found something in the code. The technical line below says what.",
    "Read the technical details, or ask the AI explanation if you set one up.",
    "Finding",
)


def explain(rule_id: str) -> Explanation:
    if rule_id in RULES:
        return RULES[rule_id]
    if rule_id.startswith("dep-guarddog-"):
        what = GUARDDOG_WHAT.get(rule_id.removeprefix("dep-guarddog-"))
        if what:
            return _E(
                f"One of its code libraries {what}",
                _GUARDDOG.means,
                _GUARDDOG.worry,
                _GUARDDOG.chip,
            )
        return _GUARDDOG
    return _UNKNOWN


def level(severity: str) -> str:
    return LEVELS.get(severity, severity)


# --- the user's data, in plain words (data-flow diagram and "can read") ------------------

DATA_LABELS = {
    "secrets.yaml": "Your secrets file",
    "auth and credential storage": "Login and password storage",
    ".storage files": "HA's private storage",
    "users and tokens": "Users and login tokens",
    "login tokens": "Login tokens",
    "user accounts": "User accounts",
    "the user list": "The list of users",
    "other integrations' settings": "Other apps' settings",
    "other integrations' credentials": "Other apps' passwords",
    "config entries of other integrations": "Other apps' settings",
    "household locations": "Where people are",
    "Supervisor token": "The system key",
    "stored HA tokens": "Your saved login",
    "user's access token": "Your HA login",
    "calling user lookup": "Who is using it",
    "browser localStorage": "Browser storage",
    "environment variables": "System settings",
    "recorder history": "Your history",
    "sensitive data (source not attributed)": "Private data",
}


def data_label(label: str) -> str:
    return DATA_LABELS.get(label, label)


# --- what it can do inside Home Assistant (from the graph's HA ring) ---------------------

_CAN_DO: list[tuple[tuple[str, str], str, str]] = [
    # (relation, kind) -> (one, many with {n})
    (
        ("registers", "http_view"),
        "Adds a page to your Home Assistant",
        "Adds {n} pages to your Home Assistant",
    ),
    (("registers", "http_static"), "Serves files from your Home Assistant", ""),
    (("registers", "panel"), "Adds a page to the sidebar", ""),
    (
        ("registers", "service"),
        "Adds an action you can use in automations",
        "Adds {n} actions you can use in automations",
    ),
    (("registers", "ws_command"), "Adds commands for the Home Assistant app and dashboards", ""),
    (("registers", "webhook"), "Accepts webhooks", ""),
    (("registers", "custom_element"), "Adds dashboard cards or elements", ""),
    (
        ("calls", "service"),
        "Runs a Home Assistant action",
        "Runs {n} kinds of Home Assistant actions",
    ),
    (("calls", "ws_command"), "Talks to Home Assistant's live connection", ""),
    (("calls", "rest_api"), "Calls Home Assistant's web API", ""),
    (("reads", "states"), "Reads the state of your devices", ""),
    (("tracks", "states"), "Watches your devices change", ""),
    (("reads", "registry"), "Reads your device and entity lists", ""),
    (("fires", "event"), "Sends Home Assistant events", ""),
    (("listens", "event"), "Listens to Home Assistant events", ""),
    (("injects", "frontend_js"), "Adds code to every Home Assistant page", ""),
]
_CAN_DO_CAPS = {
    "HTTP client": "Makes web requests",
    "network requests": "Makes web requests",
    "websocket client": "Opens live connections to other servers",
    "raw sockets": "Opens raw network connections",
    "subprocesses": "Runs other programs",
}
_CAN_READ = {
    "recorder history",
    "environment variables",
    "browser localStorage",
    "calling user lookup",
}


def can_do(report: dict[str, Any]) -> list[str]:
    """Plain lines for the HA ring, packages and capabilities. Counts come from the graph."""
    g = report.get("graph") or {}
    nodes = {n["id"]: n for n in g.get("nodes", [])}
    counts: Counter[tuple[str, str]] = Counter()
    caps: list[str] = []
    reads: list[str] = []
    pkgs = {"total": 0, "ha": 0}
    for e in g.get("edges", []):
        if e["source"] != g.get("subject"):
            continue
        n = nodes.get(e["target"], {})
        kind, label = n.get("kind", ""), n.get("label", "")
        counts[(e["relation"], kind)] += 1
        if e["relation"] == "uses" and kind == "capability" and label in _CAN_DO_CAPS:
            phrase = _CAN_DO_CAPS[label]
            if phrase not in caps:
                caps.append(phrase)
        elif e["relation"] == "reads" and label in _CAN_READ:
            reads.append(data_label(label).lower().replace("ha's", "HA's"))
        elif e["relation"] == "depends_on" and kind == "package":
            pkgs["total"] += 1
            pkgs["ha"] += bool(e.get("attrs", {}).get("ha_provided"))
    out: list[str] = []
    for key, one, many in _CAN_DO:
        n = counts.get(key, 0)
        if n:
            line = many.format(n=n) if n > 1 and many else one
            if key == ("calls", "service"):
                line += _high_privilege(g, nodes)
            out.append(line)
    if reads:
        out.append("Reads " + _join(sorted(set(reads))))
    out += caps
    if pkgs["total"]:
        t, h = pkgs["total"], pkgs["ha"]
        line = f"Uses {t} code package{'s' * (t != 1)}"
        if h == t:
            line += ", all already part of Home Assistant" if t > 1 else ", already part of HA"
        elif h:
            line += f" ({h} already part of Home Assistant)"
        out.append(line)
    bundled = counts.get(("bundles", "package"), 0)
    if bundled:
        out.append(f"Built from {bundled} code librar{'ies' if bundled != 1 else 'y'}")
    return out


def _high_privilege(g: dict[str, Any], nodes: dict[str, Any]) -> str:
    """ ", 2 of them high-privilege" (kinds.high_privilege, the agreed fixed list)."""
    from sniff_test import kinds

    labels = {
        str(nodes.get(e["target"], {}).get("label", ""))
        for e in g.get("edges", [])
        if e["source"] == g.get("subject")
        and e["relation"] == "calls"
        and nodes.get(e["target"], {}).get("kind") == "service"
    }
    hi = sum(1 for x in labels if kinds.high_privilege(x))
    if not hi:
        return ""
    return " (high-privilege)" if len(labels) == 1 else f", {hi} of them high-privilege"


def _join(items: list[str]) -> str:
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def patch_means(patch: object) -> str | None:
    """ "What it means" for a `ha-monkeypatch` finding once the scan knows what is replaced
    (report.context.patch_fact), in place of the general text about logins, network and
    encryption: that text describes the whole rule, this names the one thing replaced. Only
    for Home Assistant's own source; None otherwise (the general text stays). Text only:
    the finding, its severity and the score are the same. The names come from the scanned
    code; callers escape the result."""
    if not isinstance(patch, dict):
        return None
    obj, attr, origin = (str(patch.get(k) or "") for k in ("object", "attr", "origin"))
    if not obj.startswith("homeassistant.") or not attr:
        return None
    what = f"{attr} of {obj.rsplit('.', 1)[-1]}"
    if origin.startswith("Home Assistant's built-in "):
        name = origin.removeprefix("Home Assistant's built-in ").removesuffix(" integration")
        return (
            f"While it runs, the app swaps {what}, a part of {origin}, for its own code. From "
            f"then on Home Assistant runs the app's version wherever that part is used, with "
            f"everything the {name} integration can reach: its devices, their logins and "
            "their data. What the replacement does with that is what matters. An update of "
            "Home Assistant that changes the original can also break it."
        )
    return (
        f"While it runs, the app swaps {what}, a part of Home Assistant's own code, for its "
        "own code. From then on Home Assistant and every other app run the app's version "
        "wherever that part is used. That is a way to hide traffic, grab passwords on the "
        "way, or switch off security checks, so what the replacement does is what matters."
    )
