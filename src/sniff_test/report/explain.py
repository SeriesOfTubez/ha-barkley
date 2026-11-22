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
    "medium": "Check this",
    "low": "Minor",
    "info": "FYI",
}

_E = Explanation

RULES: dict[str, Explanation] = {
    # --- data leaving your box -------------------------------------------------------
    "ha-exfil-taint": _E(
        "Sends private Home Assistant data out of your home",
        "Barkley followed private data, such as passwords, login tokens or other apps' "
        "settings, from where the code reads it to where it sends it. It goes out over the "
        "network or to another program. Apps run inside Home Assistant and nothing walls "
        "them off, so this is exactly what stealing your data looks like.",
        "Yes. Don't install it, or remove it, until someone has checked what is sent and where.",
        "Sends your data out",
    ),
    "possible-exfil": _E(
        "Reads private data and talks to a site that isn't the app's own",
        "The app reads something private, for example your secrets file or other apps' "
        "passwords. It also contacts a site that isn't its own: its manifest or package.json "
        "doesn't link to it, and it doesn't match the app's name. Barkley "
        "couldn't trace a direct path between the two, so this is a warning sign, not proof.",
        "Take it seriously. Before you trust it, check what the app reads and why, and what "
        "that site is.",
        "Possible data leak",
    ),
    "card-token-exfil": _E(
        "Its dashboard card may send your login to another site",
        "Dashboard cards run inside your Home Assistant page in the browser. This one puts "
        "your Home Assistant login token into a web request. Barkley couldn't prove the "
        "request stays on your own Home Assistant. Anyone who gets that token can act as "
        "you, from anywhere.",
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
        "The code connects to a fixed internet IP address instead of a site name. Normal "
        "cloud services use names. Fixed IP addresses are typical of servers that control "
        "malware.",
        "Check what that address is. Sometimes it's a forgotten test server.",
        "Hard-coded IP address",
    ),
    # --- your logins, secrets and other apps' data -------------------------------------
    "ha-read-secrets": _E(
        "Reads your secrets file",
        "secrets.yaml holds the passwords and keys for your whole Home Assistant. Apps get "
        "their own settings through Home Assistant and have no need to open this file.",
        "Yes, unless the app is built to manage your configuration and you trust it.",
        "Reads your secrets",
    ),
    "py-pickle-stored": _E(
        "Unpickles data it stored",
        "Pickle is a Python format that can run code while it loads. The app decodes data "
        "it saved or was given (a cookie, an id) and loads it with pickle. That's only "
        "safe while nobody else can change that data.",
        "Usually not. It's a habit worth fixing, not a sign of hidden code.",
        "Loads saved data with pickle",
    ),
    "ha-read-own-secret": _E(
        "Reads one named entry from your secrets file",
        "secrets.yaml holds the passwords and keys for your whole Home Assistant. This app "
        "opens it and reads one entry by name, usually a setting you put there for this "
        "app. Barkley saw no other entry used where the file is opened.",
        "Usually not, if you put that entry there for this app.",
        "Reads one secret by name",
    ),
    "ha-read-auth-storage": _E(
        "Opens Home Assistant's login and password storage",
        "These files hold scrambled copies of your passwords (hashes), login tokens and "
        "every app's saved passwords. No normal app opens them directly.",
        "Yes. Find out why before keeping it.",
        "Reads login storage",
    ),
    "ha-raw-storage-access": _E(
        "Looks inside Home Assistant's private storage folder",
        "Home Assistant keeps its internal data, including login data, in a hidden "
        ".storage folder. Apps are meant to use a helper that keeps each app to its own "
        "file. This one writes the path into that folder itself.",
        "Usually not, but check what it opens. Many apps do this to tidy up their own "
        "files. Reading other files there would be a problem.",
        "Reads HA's private storage",
    ),
    "ha-own-storage-path": _E(
        "Keeps its own file in Home Assistant's storage folder",
        "The app writes its own file into Home Assistant's .storage folder. Home Assistant "
        "also keeps logins and every integration's settings there. The app builds the "
        "file's path itself. Home Assistant's code has a helper, called Store, that does "
        "this for an app. Home Assistant has no documentation page that says which way to "
        "use.",
        "No. The file is the app's own. Barkley shows this for information and doesn't score it.",
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
        "The app reads, creates or removes login tokens, or works directly with Home "
        "Assistant's own login store. A login token lets whoever holds it act as that user.",
        "Yes, unless that's the app's whole purpose (for example a login add-on).",
        "Handles login tokens",
    ),
    "ha-auth-token-check": _E(
        "Checks login tokens sent to it",
        "When someone sends the app a login token or a signed link, the app checks that it "
        "is valid and whose it is. Home Assistant does the same for its own pages. The app "
        "doesn't read the token's secret value or the key that signs it.",
        "Rarely. Apps with their own web pages or streams do this to check who's asking.",
        "Checks login tokens",
    ),
    "ha-auth-change-users": _E(
        "Changes who can log in to Home Assistant",
        "The app can create, enable, disable or remove user accounts.",
        "Only if the app isn't meant to manage users. A user-management tool needs this.",
        "Changes user accounts",
    ),
    "ha-auth-list-users": _E(
        "Reads the list of Home Assistant users",
        "The app lists every user account, with names, ids and who is an administrator. Apps "
        "do this to offer a list of people to pick from, for example in their own panel.",
        "Usually not. The list holds no passwords or login tokens.",
        "Lists users",
    ),
    "ha-foreign-entry-data": _E(
        "Reads other apps' saved passwords and settings",
        "Each app keeps its passwords and API keys in its own saved settings. This one "
        "reads other apps' saved settings.",
        "Yes, unless it's a tool built to manage other integrations and you trust it.",
        "Reads other apps' passwords",
    ),
    "ha-foreign-entry-options": _E(
        "Reads other apps' settings",
        "Apps keep their options, such as filters, chosen devices and entity lists, apart "
        "from their passwords. This one reads other apps' options.",
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
        "The Supervisor is the part of Home Assistant that runs the system. Its key can "
        "install and remove apps, make and restore backups, and control the machine. Custom "
        "integrations have no need for it.",
        "Yes. Find out why before keeping it.",
        "Reads the system key",
    ),
    "ha-supervisor-token-local": _E(
        "Asks the Supervisor with the system key",
        "The Supervisor is the part of Home Assistant that runs the system. The app reads "
        "its key and uses it to ask the Supervisor on this same box a question, such as "
        "which apps are installed. In the function that reads the key, Barkley saw it sent "
        "nowhere else. The key itself can do far more than that.",
        "Usually not. It's unusual for a custom integration, so check that the reason "
        "makes sense for what the app does.",
        "System key, used on this box",
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
        "your login token, usually to load data from Home Assistant. The token is the key "
        "your browser uses to prove it's you. Anything holding that key can do whatever you "
        "can do.",
        "Usually not. What matters is where the login is sent. Barkley checks that "
        "separately. A card that sends it to another site gets a serious warning of its own.",
        "Uses your login",
    ),
    # --- running code it didn't ship ---------------------------------------------------
    "py-b64-exec": _E(
        "Hides code and then runs it",
        "The app decodes a scrambled block of text and runs it as code. Hiding code like "
        "this only makes sense if someone doesn't want it read. It's a common way to "
        "sneak in malware.",
        "Yes. Don't install it until someone has decoded and read that code.",
        "Runs hidden code",
    ),
    "py-eval-exec": _E(
        "Builds code while running and executes it",
        "The app turns text into code and runs it. Whatever ends up in that text runs with "
        "full access to Home Assistant, so it matters where the text comes from.",
        "Check it. It's sometimes used for harmless formulas or templates.",
        "Runs code it builds",
    ),
    "py-dynamic-import": _E(
        "Loads code whose name is only known while running",
        "The app picks which code to load while it runs. You can't tell from reading the "
        "code what will be loaded.",
        "Usually not. Many apps load their own parts this way.",
        "Picks code while running",
    ),
    "py-runtime-pip": _E(
        "Installs extra software while running",
        "The app installs Python packages itself while Home Assistant runs, instead of "
        "listing them the normal way. Nobody checks those packages, and all apps share them.",
        "Yes. Ask the developer why it doesn't list them like other apps do.",
        "Installs software itself",
    ),
    "py-runtime-pip-listed": _E(
        "Installs named software while running",
        "The app installs Python packages itself instead of listing them the normal way. "
        "The package names are written in its code, so Barkley checked those packages like "
        "any listed ones.",
        "Usually not. It's an old habit, and Barkley checked the packages it installs.",
        "Installs listed packages",
    ),
    "py-shell-exec": _E(
        "Runs commands on your system",
        "The app runs system commands. That can be fine, for example to call a helper "
        "program. What matters is what it runs and whether any part of the command comes "
        "from outside the app.",
        "Check what it runs.",
        "Runs system commands",
    ),
    "py-obfuscation": _E(
        "Uses tricks that make its code hard to read",
        "The code uses tricks that hide what it does, such as large scrambled blocks "
        "or text built one character at a time. Honest code rarely needs these.",
        "Check what it hides.",
        "Hard-to-read code",
    ),
    "py-write-outside-own-dir": _E(
        "Writes or deletes files outside its own folder",
        "The app writes to sensitive places, such as your configuration, login storage, "
        "other apps' code or system files. Malware can do this to keep itself installed or "
        "to change other apps.",
        "Yes. Check exactly which files it changes.",
        "Changes other files",
    ),
    "ha-monkeypatch": _E(
        "Changes how Home Assistant itself works",
        "While it runs, the app replaces parts of Home Assistant, its login system, or its "
        "network and encryption code. That changes things for every app. It's also a way to "
        "hide traffic, grab passwords as they pass, or switch off security checks.",
        "Yes. Find out what it replaces and why.",
        "Changes HA itself",
    ),
    "py-bytecode-runs-instead-of-source": _E(
        "Ships compiled code that runs instead of the readable code",
        "The app includes compiled Python files. Home Assistant would run them instead of "
        "the readable code next to them. What runs may not match what anyone reviewed.",
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
        "The app includes a compiled program file that Home Assistant can load. There is "
        "no readable version of it, so Barkley can't check what it does.",
        "Yes, unless the developer explains it and you trust them.",
        "No readable version",
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
        "While it runs, the card builds a sensitive name out of pieces, for example "
        "['fe','tch'].join(''). Names like this include fetch (send data), eval (run text "
        "as code) and hassTokens (your stored login). Code only does this so nobody finds "
        "the name by reading or searching the code. Barkley put the pieces together and "
        "checked what the code does with the name. Anything it found is listed separately.",
        "Yes. Find out why the card hides the name before you install it.",
        "Hides a name",
    ),
    "card-code-loader": _E(
        "Can run code from an address it is given",
        "Part of its code downloads JavaScript from an address it is handed and runs it, "
        "often a library's way of adding plugins. Barkley lists any script address it sees "
        "written in the app as code the app may load. If nothing hands it an address, it "
        "loads nothing.",
        "Usually not on its own. Check the code the app loads from other sites, if any.",
        "Code loader",
    ),
    "card-eval-remote": _E(
        "Its dashboard card runs code it gets from outside",
        "The card takes text from a download, a message, the page address or browser "
        "storage. It runs that text as code in your browser, with your Home Assistant "
        "login. Barkley never saw that code. Whoever controls where it comes from controls "
        "what runs.",
        "Yes, unless you know where that code comes from and trust it.",
        "Runs outside code",
    ),
    "card-eval": _E(
        "Its dashboard card builds code while running and executes it",
        "The card puts together a piece of code and runs it in your browser, with your "
        "Home Assistant login. Charting and template libraries do this to make their own "
        "code fast. Barkley found no sign the code comes from outside the card, but it "
        "can't follow the code everywhere.",
        "Usually not. It would matter if the pieces could come from the internet.",
        "Runs code it builds",
    ),
    "card-eval-config": _E(
        "Its dashboard card runs code from its own settings",
        "The card supports templates, so it runs bits of code you write in its dashboard "
        "settings. Only people who can edit your dashboards control that code.",
        "Only if you paste card settings from sources you don't trust.",
        "Runs code from settings",
    ),
    "card-remote-script": _E(
        "Its dashboard card loads code from the internet",
        "While it runs, the card downloads extra code from a website. Which version it gets "
        "is only decided then. That code runs with your Home Assistant login, and Barkley "
        "never saw it.",
        "Check it. Whoever controls that website, or can publish that package, controls what "
        "runs in your dashboard, now and after every new release.",
        "Loads code from the web",
    ),
    "card-eval-address": _E(
        "A link can make its dashboard card run code",
        "The card runs code it takes from the page address, directly or through its "
        "settings. Anyone who gets you to open a link to your dashboard can make it run "
        "code there, with your Home Assistant login.",
        "Check it. Be careful with links to your dashboard that you didn't make yourself.",
        "A link can run code",
    ),
    "card-remote-pinned": _E(
        "Its dashboard card loads a fixed version of code from the internet",
        "While it runs, the card downloads one fixed version of extra code from a website. "
        "That code can't change under you, but it runs with your Home Assistant login, and "
        "Barkley never saw it.",
        "Worth knowing. The card depends on that website being up and serving the same file.",
        "Loads fixed web code",
    ),
    "card-html-comment-token": _E(
        "Its dashboard card uses a trick that hides code from scanners",
        "The card has `<!--` inside its code. Many scanners skip the rest of that line, "
        "but browsers run it. Barkley read the hidden part anyway.",
        "Check it. Normal code and normal build tools don't produce this.",
        "Scanner-hiding trick",
    ),
    # --- doors into your Home Assistant -----------------------------------------------
    "ha-unauth-view": _E(
        "Adds a web page that works without logging in",
        "The app adds an address to your Home Assistant that opens without logging in. "
        "Anyone who can reach your Home Assistant can open it. Some apps need this: for "
        "example, the page another service sends you back to after you sign in there, or a "
        "link to a camera picture.",
        "Usually not. It matters more if your Home Assistant is reachable from the internet.",
        "Page without login",
    ),
    "ha-cors-allowed": _E(
        "Lets other websites call one of its pages",
        "The app allows web pages on other sites to call one of its Home Assistant pages "
        "from your browser.",
        "Usually not. Keep it in mind if your Home Assistant is reachable from the internet.",
        "Open to other sites",
    ),
    "ha-webhook-remote": _E(
        "Accepts messages from the internet",
        "The app sets up a webhook. That's an address that accepts messages from outside "
        "your home. Its secret address is the only thing protecting it.",
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
    "dep-malicious-build": _E(
        "Built with a tool known to be malware",
        "A tool the developer used to build this app is on a public list of known malicious "
        "packages. It runs on the developer's machine while the app is built, not in your "
        "home, but it could change the files that ship. Barkley read the shipped files "
        "themselves, and anything found in them is listed on its own. The developer should "
        "update or remove the tool.",
        "Maybe. Check what Barkley found in the shipped files, and whether the project is "
        "still looked after.",
        "Malware build tool",
    ),
    "dep-npm-standin": _E(
        "Lists an empty package npm put in place of removed malware",
        "When npm removes a malicious package, it publishes an empty one under the same "
        "name so nobody can take it again. This app's lock file lists that empty package. "
        "It has no code, so nothing from it is installed or ships with the app.",
        "No. It's a dependency the app doesn't need.",
        "Empty stand-in package",
    ),
    "dep-vuln": _E(
        "Uses a code library with known security bugs",
        "One of the code libraries this app uses has publicly known security bugs. A newer "
        "version of that library usually fixes them.",
        "It depends on the bug. Most only matter in situations a Home Assistant app doesn't "
        "run into. Still, update the app when a fix comes out.",
        "Library with known bugs",
    ),
    "telemetry-shadow": _E(
        "Sends usage data on its own, without telling you",
        "The app reports how it's used to a server the developer runs. It does this on its "
        "own, when Home Assistant starts or on a timer. Barkley found no option in the code "
        "to turn it off, and the app's description doesn't mention it.",
        "It's a privacy matter. It isn't an attack. The server learns your home's internet "
        "address and whatever the report contains. Ask the developer what it sends.",
        "Hidden usage reports",
    ),
    "telemetry-opt-out": _E(
        "Sends usage data unless you turn it off",
        "The app reports how it's used to a server the developer runs. It does this on its "
        "own. Either it's on by default with an option to turn it off, or the app's "
        "description mentions it.",
        "It's a privacy choice. If you'd rather it didn't, check the app's options.",
        "Usage reports, on by default",
    ),
    "telemetry-usage": _E(
        "Can send usage data to the developer",
        "The code has what looks like usage reporting to a server the developer runs. "
        "Below, Barkley says what it could tell about when it's sent.",
        "Barkley shows this for information and doesn't score it.",
        "Usage reporting",
    ),
    "dep-build-tool-vuln": _E(
        "Is built with a tool that has known security bugs",
        "The card lists a build tool, such as rollup or babel. It turns the developer's "
        "code into the JavaScript you download. That tool has publicly known bugs. But it "
        "only runs on the developer's machine when the card is built, and none of its code "
        "is in the card.",
        "No. The bugs are in the developer's build step, not in what you install. Barkley "
        "shows this for information and doesn't score it.",
        "Build tool bugs",
    ),
    "dep-lookalike-own": _E(
        "Uses its owner's own library with a name close to a popular one",
        "One of its libraries has a name one typo away from a well-known package. PyPI's "
        "record of how it was published names a GitHub workflow in this app owner's "
        "account, so it is the owner's own library, not an imitation.",
        "No.",
        "Owner's own library",
    ),
    "dep-typosquat": _E(
        "Uses a code library with a name one typo away from a popular one",
        "Copycat packages use a well-known name with a small typo, so people install them "
        "by mistake.",
        "Check that it's the real thing. Sometimes it's a genuine, unrelated package.",
        "Lookalike library",
    ),
    "dep-vcs-or-url-requirement": _E(
        "Installs a code library straight from a web address",
        "One of its libraries comes straight from a website or a code project's online "
        "storage, not as a normal package. What's there can change at any time, without a "
        "new version.",
        "Check it. You can't know what will be installed next time.",
        "Library from a web address",
    ),
    "dep-invalid-requirement": _E(
        "Has a strange entry in its list of libraries",
        "The app gives Home Assistant a list of libraries to install. One entry in that "
        "list isn't a plain package name. Some entries like this can change how installing "
        "works.",
        "Check what the entry does.",
        "Odd library entry",
    ),
    "dep-very-new-package": _E(
        "Uses a brand-new code library",
        "One of its libraries was first published only days ago. New packages have no "
        "track record. Most malicious packages are caught within days.",
        "Wait a little, or check the package.",
        "Brand-new library",
    ),
    "dep-unresolvable": _E(
        "Asks for a library version that can't be installed",
        "Home Assistant couldn't install one of the libraries this app asks for, so "
        "Barkley couldn't check that part either.",
        "It mostly means the app may not work. It also means Barkley couldn't check part of it.",
        "Library can't install",
    ),
    "dep-sdist-only": _E(
        "Builds one of its libraries on your machine",
        "One library has no ready-made package, so Home Assistant would build it from its "
        "code on your machine. Building runs that library's own setup code.",
        "Usually not, but building runs code Barkley couldn't check.",
        "Built on your machine",
    ),
    "dep-npm-no-lockfile": _E(
        "Doesn't fix the exact versions of the libraries it's built from",
        "The card is built from code libraries without fixing their exact versions. Each "
        "time the developer builds a new release, it can pick up newer versions of those "
        "libraries. That's how a hijacked library gets into a card. The release you'd "
        "install is already built, and Barkley checked its code. But Barkley couldn't match "
        "the libraries inside it against known malicious versions.",
        "Not for this release. It's a weakness in how future releases get built, so check "
        "the next update.",
        "Library versions not fixed",
    ),
    # --- who publishes it --------------------------------------------------------------
    "repo-transferred": _E(
        "The project changed owners",
        "This project now belongs to a different account than before. Handovers are often "
        "fine. But taking over a trusted project is also a known way to get malware to its "
        "users.",
        "Check who the new owner is, especially if the change is recent.",
        "Changed owners",
    ),
    "repo-new-maintainer-release": _E(
        "The installed version was published by someone new",
        "This person never published a version before this one. Earlier versions came from "
        "other people.",
        "Check who they are. New helpers are common in healthy projects.",
        "New publisher",
    ),
    "repo-young": _E(
        "The project is very new",
        "The project was created recently, so it has little history and few people have "
        "looked at it.",
        "Not by itself. It just has less of a track record.",
        "New project",
    ),
    "repo-no-releases": _E(
        "The project has no releases",
        "Without releases, the Marketplace installs whatever is in the project right now. "
        "Barkley checked that exact copy, but it can change at any time without a new "
        "version number.",
        "Not by itself. It just makes changes harder to follow.",
        "No releases",
    ),
    "repo-release-fills-constant": _E(
        "The download fills in a value the public code leaves empty",
        "The code you install is the same as the code on GitHub, except for one setting. "
        "It's empty on GitHub and filled in in the download. Usually it's a key for the "
        "developer's own service that they keep out of public view. The value isn't a web "
        "address.",
        "Usually not. The rest of the code matches what anyone can review.",
        "Fills in a key",
    ),
    "repo-release-source-mismatch": _E(
        "The download differs from the code people can read",
        "The files the Marketplace installs differ from the same files in the project's "
        "public code. So someone who reviews the project hasn't reviewed what you install.",
        "Check what's different.",
        "Download differs from code",
    ),
    "repo-release-extra-code": _E(
        "The download contains code that isn't in the project",
        "The release download includes code files that aren't in the public project, "
        "such as generated or bundled files. Barkley checked them, but nobody else can "
        "review them in the project.",
        "Usually not, but it's extra code with no public history.",
        "Extra code in download",
    ),
    "repo-release-asset-missing": _E(
        "The release is missing the file the project says to install",
        "The project says to install a specific download, but the release doesn't have "
        "it, so the Marketplace falls back to the source code.",
        "No. Barkley checked what it would install instead.",
        "Release file missing",
    ),
    "repo-tag-off-default-branch": _E(
        "The installed version isn't on the project's main line",
        "The version you install has changes that were never added to the project's main "
        "code, where people normally review it.",
        "Check what those changes are.",
        "Not on the main line",
    ),
    "repo-multiple-integrations": _E(
        "The project contains more than one integration",
        "The project has several integration folders. Barkley checked the one the Marketplace "
        "installs.",
        "No.",
        "Several integrations",
    ),
    # --- coverage ----------------------------------------------------------------------
    "scan-parse-error": _E(
        "Barkley couldn't fully read part of the code",
        "Barkley couldn't fully read one section of a file, so it can't say anything about "
        "that part.",
        "Usually not. It happens with big compressed files. Barkley lists it so you always "
        "know what it couldn't read.",
        "Partly unreadable",
    ),
    "scan-file-not-checked": _E(
        "Barkley's code checks couldn't read a whole file",
        "Barkley's code scanner couldn't make sense of this file at all, so none of its "
        "checks ran on it. Barkley's other checks still ran. Those cover the addresses it "
        "names, its code libraries and the project's history.",
        "Barkley found nothing bad in it, but it couldn't look. While a file like this is "
        "there, the score can't go above 89.",
        "File not checked",
    ),
}

# GuardDog heuristics on dependencies. The rule id is built from GuardDog's rule name,
# so new names can appear; they fall back to _GUARDDOG.
_GUARDDOG = _E(
    "One of its code libraries has suspicious-looking code",
    "An automatic check of one of its code libraries found a pattern often seen in "
    "malware. That's a hint, not proof.",
    "Check it. Popular, well-known libraries often set off these checks for harmless reasons.",
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
    "Barkley found something",
    "One of Barkley's checks found something in the code. The technical line below says what.",
    "Read the technical details, or use the AI explanation if you set it up.",
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
    "environment variables": "Home Assistant's environment variables",
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
    (
        ("registers", "ws_command"),
        "Adds commands that the Home Assistant app and dashboards can send it",
        "",
    ),
    (("registers", "webhook"), "Accepts webhooks", ""),
    (("registers", "custom_element"), "Adds dashboard cards or elements", ""),
    (
        ("calls", "service"),
        "Runs a Home Assistant action",
        "Runs {n} kinds of Home Assistant actions",
    ),
    (("calls", "ws_command"), "Sends commands over Home Assistant's live connection", ""),
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
    """ ", 2 of them powerful ones" (kinds.high_privilege, the agreed fixed list)."""
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
    return " that is a powerful one" if len(labels) == 1 else f", {hi} of them powerful ones"


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
            f"While it runs, the app replaces {what}, a part of {origin}, with its own code. "
            "From then on Home Assistant runs the app's version wherever that part is used. "
            f"That version can reach everything the {name} integration can: its devices, "
            "their logins and their data. What matters is what the replacement does with "
            "that. A Home Assistant update that changes the original part can also break it."
        )
    return (
        f"While it runs, the app replaces {what}, a part of Home Assistant's own code, with "
        "code of its own. From then on Home Assistant and every other app run the app's "
        "version wherever that part is used. Replacing code like this is a way to hide "
        "traffic, grab passwords as they pass, or switch off security checks. What matters "
        "is what the replacement does."
    )
