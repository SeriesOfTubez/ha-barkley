# Options

Settings → Apps → Barkley → Configuration. Every option has a default, and four of them
are easier to set in the panel, where the choice wins over the option.

| Option | Default | Meaning |
|---|---|---|
| `exposure` | `local` | Set `public` if your Home Assistant is reachable from the internet. Raises findings about what an app accepts from outside; never lowers anything. |
| `jobs` | `1` | Parallel Semgrep jobs inside one scan (1 to 4). More is faster and uses more memory. |
| `parallel_scans` | `2` | How many scans may run at once (1 to 4). A further scan starts only while the box has enough free memory; otherwise it waits. |
| `github_token` | empty | A GitHub token with no scopes, for 5,000 requests an hour instead of 60. |
| `ai_entity` | empty | The AI Task entity for explanations. Easier: pick it on an app's page. |
| `ai_mode` | `summary` | `summary` or `deep`. Also set in the panel. See [AI explanations](AI-explanations). |
| `auto_scan` | `true` | Sniff installs, updates and offered updates, and notify. Also set in the panel. |
| `notify_target` | empty | A `notify` service name that gets each auto-sniff result besides the bell. Easier: pick it in the panel. |

There is no light or dark setting: the panel follows the mode of your Home Assistant
profile.
