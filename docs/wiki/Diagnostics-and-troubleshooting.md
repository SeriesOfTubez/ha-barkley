# Diagnostics and troubleshooting

## The Diagnostics page

Linked from Barkley's first page. It opens at once and fills in as each check ends. The
checks run on small samples Barkley writes itself, never on scanned code:

- **environment**, which includes the AppArmor profile the app runs under, `TMPDIR` and
  the free space in the temporary folder;
- **CPU:** whether it has the x86-64-v2 instructions the scanner tools need;
- **Tool sandbox:** Landlock and its version, or on a kernel without Landlock (Home
  Assistant OS) the app's AppArmor profile for tools;
- **Barkley's Python;**
- **memory guard:** the free memory figure and whether a scan may start;
- **GitHub API:** how many requests are left this hour;
- **Home Assistant version** and the **Marketplace installed list**;
- each tool, run the way a scan runs it: **semgrep scan** and
  **osv-scanner scan (empty sample lockfile)**. For the last one, "exit 128: read the
  lockfile, which names no package (as expected)" is the good result.

After an update, check that the AppArmor line names Barkley's own profile, ending in
`sniff_test (enforce)`, not `docker-default`.

## A scan says "Unfinished"

Something that may work next time went wrong, such as a timeout or an unreachable
service. The app's page says which part didn't finish, Threat reads "None found so far"
when nothing was found in the part that did, and the scan isn't reused. Click **Sniff
again**, or
**Sniff N unfinished again** on the first page. If it keeps happening, open
Diagnostics: a tool that fails there fails in every scan.

## Scans wait or are refused: memory

Home Assistant sets no memory limit for apps, so Barkley guards itself. With under 2 GB
available on the box the panel warns. By default it won't start a scan with under 1 GB
free. Settings → Low memory lowers that to 0.5 GB, or turns it off, if you accept that
Home Assistant may run short. Most scans use under 0.5 GB; a few big apps use far more.
On a small box keep Parallel scans at 1.

## Every scan fails: "CPU ISA level is lower than required"

The scanner tools need a CPU with the x86-64-v2 instructions. A virtual machine whose
CPU type hides them (Proxmox's default, `kvm64`, does) can't run them, so every scan is
Unfinished. Since 0.15 the scan says so with the fix, and Diagnostics checks the CPU
before any scan runs. The fix: set the VM's CPU type to one that passes the instructions
through (on Proxmox: x86-64-v2-AES or host), then shut the VM down completely and start
it again; a restart from inside the VM isn't enough.

## "Out of temporary space"

Each scan keeps its copy of the app in the temporary folder while it reads it, plus the
packed files it unpacks (at most 32 MB) and, for a library that is published only as
source, that library's archive (its list of dependencies is read from it; nothing is
built). Since 0.15 GuardDog is gone, so Barkley no longer downloads every library of an
integration, and a scan needs far less room than before. It downloads only the libraries
an integration hands the login you gave it (or an address) to: at most four per scan, up
to 40 MB each, read as text. A very large app still needs space for its copy. When the folder fills up, the scan is Unfinished and says "out of temporary space:
N MB free in …". Diagnostics shows the free space next to `TMPDIR`. In the app the temporary folder is on
Home Assistant's data disk. Standalone uses `/data/tmp`; on the command line, set
`TMPDIR` to a folder with about 1 GB free.

## Scans wait: GitHub's hourly limit

Without a token GitHub allows 60 requests an hour, and a sniff makes about 10 to 20. When the
budget is used up Barkley waits for the reset and then carries on. A rate limit is never
treated as a scan result. A token with no scopes (the `github_token` option) raises the
limit to 5,000.

## The AI button shows an error

The model behind your AI Task entity must support structured output. See
[AI explanations](AI-explanations).

## An update check takes minutes

The first check scans the offered version and, if there is no stored scan, the version
you run. Later checks reuse both.

## Barkley flagged something that looks fine

Use **Report a false positive** under the item on the app's page. It opens a new public
issue on Barkley's GitHub with the versions, the rule, the file and the line filled in;
you write why it's wrong and submit it yourself. There is no Accept or Mark reviewed
since 0.15.

## Reporting a problem

Open an issue in the repository with what Diagnostics shows. Leave out your GitHub
token. For a security problem in Barkley itself, use the Security tab → "Report a
vulnerability" instead.
