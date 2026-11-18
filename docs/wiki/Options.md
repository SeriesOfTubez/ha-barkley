# Options and Settings

Since 0.14.0 Barkley has its own **Settings** page (the link at the top of the panel). The
app's options (Settings → Apps → Barkley → Configuration) give the starting values; once
you save the Settings page, it wins. Standalone, the `BARKLEY_*` variables play the part
of the options (see [Standalone](Standalone)).

## The Settings page

| Setting | Default | Meaning |
|---|---|---|
| Exposure | Local only | Public if your Home Assistant is reachable from the internet. Raises findings about what an app accepts from outside; never lowers anything. A hint under it says whether Home Assistant has an external URL set. |
| Paranoid mode | Off | Show and count the minor findings. See [scoring](Checks-and-scoring). |
| Powerful, no threat | On | With no Threat finding, what an app can do won't put its score below Very Sus (40). Only for a finished scan with no critical finding. |
| Pages without a login | List only | Count an app's pages that work without a login under Local only. |
| Hidden usage reporting | Count it | Count usage data an app sends by itself, with no setting to turn it off, and doesn't tell you about. |
| When an accepted finding changes | Notify me | A reopened finding is always reopened; this decides whether the notification says so. |
| Ask again | Never | Reopen acceptances after 6 or 12 months even if nothing changed. |
| Auto-sniff | On | Sniff installs, updates and offered updates, and notify. |
| Notify | Bell only | A `notify` service that gets each result besides the bell. |
| AI | Off | The AI Task entity for explanations. Only as good as the model you pick. |
| AI mode | Explain only | Or also read the code around a finding. See [AI explanations](AI-explanations). |
| Parallel scans | 2 (app), 1 (standalone) | How many apps are scanned at the same time (1 to 4). Another scan starts only while there's free memory for it: 1.5 GB for each scan already running, on top of a 2 GB reserve; otherwise it waits. |
| Semgrep jobs | 1 | Inside one scan, how many files Semgrep reads at once (1 to 4); GuardDog uses the same number for an integration's libraries. Helps apps that ship many files, such as cards split into chunks, not one big file. Barkley's passes over the code still run one after another. Each extra job needs its own memory. |
| GitHub token | none | See below. |

Each section has **Reset to defaults**. Some settings have a **How this works** line that
opens a longer explanation.

## GitHub token

Optional. Without one GitHub allows 60 requests an hour; with one, 5,000. A scan makes
about 6 or 7. The token needs **no permissions**: on GitHub, Settings → Developer
settings → Personal access tokens → Fine-grained tokens → Generate new token, with
**Repository access: Public repositories** and nothing else. Paste it on Barkley's
Settings page. Barkley keeps it in its own file next to its database (never in the
database) and never shows it again; **Remove** deletes it. A token in the app's
`github_token` option still works, and one saved on the Settings page wins over it.

## The app's options

| Option | Default | Starting value for |
|---|---|---|
| `exposure` | `local` | Exposure |
| `jobs` | `1` | Semgrep jobs |
| `parallel_scans` | `2` | Parallel scans |
| `github_token` | empty | GitHub token |
| `ai_entity` | empty | AI |
| `ai_mode` | `summary` | AI mode |
| `auto_scan` | `true` | Auto-sniff |
| `notify_target` | empty | Notify |

There is no light or dark setting: the panel follows the mode of your Home Assistant
profile.
