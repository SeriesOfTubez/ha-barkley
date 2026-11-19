# Diagnostics and troubleshooting

## The Diagnostics page

Linked from Barkley's first page. It opens at once and fills in as each check ends. The
checks run on small samples Barkley writes itself, never on scanned code:

- **environment**, which includes the AppArmor profile the app runs under;
- **memory guard:** the free memory figure and whether a scan may start;
- **GitHub API:** how many requests are left this hour;
- **Home Assistant version** and the **Marketplace installed list**;
- each tool, run the way a scan runs it: **semgrep scan**, **guarddog scan** and
  **osv-scanner scan (empty sample lockfile)**. For the last one, "exit 128: read the
  lockfile, which names no package (as expected)" is the good result.

After an update, check that the AppArmor line names Barkley's own profile, ending in
`sniff_test (enforce)`, not `docker-default`.

## A scan says "Unfinished"

Something that may work next time went wrong, such as a timeout or an unreachable
service. The score is capped at 89 and the scan isn't reused. Click **Sniff again**, or
**Sniff the N unfinished again** on the first page. If it keeps happening, open
Diagnostics: a tool that fails there fails in every scan.

## Scans wait or are refused: memory

Home Assistant sets no memory limit for apps, so Barkley guards itself. With under 2 GB
available on the box the panel warns; under 1 GB it refuses to start a scan. Plan for
0.5 to 1 GB while a scan runs. Lower `parallel_scans` on a small box.

## "Out of temporary space"

An integration's libraries are downloaded and unpacked into the temporary folder while
GuardDog reads them. Since 0.14.1 each one is deleted as soon as it has been read, so a
scan keeps only a few there at a time (before, one real integration peaked at about
354 MB with every library kept to the end), but a library with large files still needs
room. When the folder fills up, the scan is Unfinished and says "out of temporary space:
N MB free in …". Diagnostics shows the free space next to `TMPDIR`. In the app the temporary folder is on
Home Assistant's data disk. Standalone uses `/data/tmp`; on the command line, set
`TMPDIR` to a folder with about 1 GB free.

## Scans wait: GitHub's hourly limit

Without a token GitHub allows 60 requests an hour, and a sniff may need up to twelve. When the
budget is used up Barkley waits for the reset and then carries on. A rate limit is never
treated as a scan result. A token with no scopes (the `github_token` option) raises the
limit to 5,000.

## The AI button shows an error

The model behind your AI Task entity must support structured output. See
[AI explanations](AI-explanations).

## An update check takes minutes

The first check scans the offered version and, if there is no stored scan, the version
you run. Later checks reuse both.

## Reporting a problem

Open an issue in the repository with what Diagnostics shows. Leave out your GitHub
token. For a security problem in Barkley itself, use the Security tab → "Report a
vulnerability" instead.
