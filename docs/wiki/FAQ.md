# FAQ

**Does Good Boy mean an app is safe?**
No. It means Barkley's checks found no signs of malicious behavior. Barkley is a first
pass, not a substitute for reading the code.

**Where did the 0–100 score go?**
Since 0.15 each app has two readings instead: Threat (signs of malicious behavior) and
Exposure (what it opens up to someone who isn't an administrator). Everything else is
listed as context and isn't scored. The old number is still in the technical report and
the command line, as the capability score. See
[What gets checked and how the readings work](Checks-and-scoring).

**Where are Accept, Mark reviewed, Malware check only and Addresses you trust?**
Removed in 0.15. With the two readings they no longer changed anything. If you think
Barkley got something wrong, use Report a false positive under the item.

**Why does an app that can do a lot read Good Boy?**
A custom integration runs unsandboxed inside Home Assistant, so what its code openly uses
says little about whether it means harm. Threat counts only signs of malicious behavior.
What the app can do is still listed on its page, under "What it can do (not scored)".

**Does Barkley block or remove anything?**
No. It reports. There is no quarantine and no install gate.

**Does Barkley run the code it scans?**
No. The code is downloaded and read. It is never executed, imported, built or installed.

**Can it scan Home Assistant apps (add-ons)?**
No. Barkley checks integrations and dashboard cards only. It doesn't check apps
(add-ons), AppDaemon apps, Python scripts, themes or templates; the list says how many
of those you have that it didn't check.

**Was Barkley written with AI?**
Yes, with AI assistance under human direction and review; most of the code and docs are
AI-generated. See [Permissions and how Barkley is secured](Permissions-and-security).

**Does the AI decide the readings?**
No. The readings come from fixed rules. The optional AI features only explain, and are only as
good as the model you pick. See [AI explanations](AI-explanations).

**What does Barkley contact on the internet?**
GitHub (the code, releases and repository facts), PyPI and Home Assistant's wheel index
(to resolve dependencies, and, for a package name that looks like a popular one, PyPI's
record of who published it), the OSV advisory database through osv-scanner, and the npm
registry (the newest release
of a vulnerable card package). For a library an integration hands the login you gave
it to, it downloads that library's published package from PyPI's file host and reads
it as text. Once a day the panel reads the Marketplace's list of removed apps
(`data-v2.hacs.xyz`). With Published libraries on (the default), it also sends
jsDelivr the SHA-256 of an integration's larger JavaScript files and asks npm about the
packages it names (publish date, downloads). For a dependency with a known
vulnerability it reads the CVE record from `cveawg.mitre.org` (the CVE id only), for CISA's
assessment of how it's exploited. Your AI provider is contacted only when
you click an AI button. No address found in a scan is ever sent to a lookup service.

**Does it read my Home Assistant configuration?**
No. It has no access to the configuration folder. See
[Permissions and how Barkley is secured](Permissions-and-security).

**Why did an app's readings change when its code didn't?**
A new advisory was published for one of its packages (see
[Advisory re-checks](Advisory-re-checks)), you changed "Where Home Assistant runs" on the
Settings page (or "Build tool known to be malware"), or Barkley was updated and its
rules changed.
After an update of Barkley that changed its rules, its checks or its scanner tools, the
list offers one button to sniff everything again with the new rules. An update that
changed none of them keeps the stored scans.

**Why is a brand-new install sniffed only after it ran?**
Home Assistant sets a new integration up as soon as it is installed. Sniff it from
search first: see [Sniff before you install](Sniff-before-you-install).

**Do I have to verify the image's signature?**
No, it is optional. See [Installing and updating](Installing-and-updating).
