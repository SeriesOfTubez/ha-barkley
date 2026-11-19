# FAQ

**Does a score of 100 mean an app is safe?**
No. It means Barkley's checks found nothing. Barkley is a first pass, not a substitute
for reading the code.

**Does Barkley block or remove anything?**
No. It reports. There is no quarantine and no install gate.

**Does Barkley run the code it scans?**
No. The code is downloaded and read. It is never executed, imported, built or installed.

**Can it scan Home Assistant apps (add-ons)?**
No. Barkley scans what the Marketplace installs: custom integrations and frontend cards.

**Was Barkley written with AI?**
Yes, with AI assistance under human direction and review; most of the code and docs are
AI-generated. See [Permissions and how Barkley is secured](Permissions-and-security).

**Does the AI decide scores?**
No. Scores come from fixed rules. The optional AI features only explain, and are only as
good as the model you pick. See [AI explanations](AI-explanations).

**What does Barkley contact on the internet?**
GitHub (the code, releases and repository facts), PyPI and Home Assistant's wheel index
(to resolve dependencies), the OSV advisory database through osv-scanner, a list of
popular package names that GuardDog refreshes, and the npm registry (the newest release
of a vulnerable card package). With Published libraries on (the default), it also sends
jsDelivr the SHA-256 of an integration's larger JavaScript files and asks npm about the
packages it names (publish date, downloads). Your AI provider is contacted only when
you click an AI button. No address found in a scan is ever sent to a lookup service.

**Does it read my Home Assistant configuration?**
No. It has no access to the configuration folder. See
[Permissions and how Barkley is secured](Permissions-and-security).

**Why did an app's score change when its code didn't?**
Either a new advisory was published for one of its packages (see
[Advisory re-checks](Advisory-re-checks)), or Barkley was updated and its rules changed.
After an update of Barkley, the list offers one button to sniff everything again with
the new rules.

**Why is a brand-new install sniffed only after it ran?**
Home Assistant sets a new integration up as soon as it is installed. Sniff it from
search first: see [Sniff before you install](Sniff-before-you-install).

**Are there other tools like this?**
Yes, for example HA Security Sandbox and Marketplace Guard. Barkley's difference is
depth: dependencies resolved the way Home Assistant installs them, data-flow rules,
release and publisher history, and the comparison of an update.

**Do I have to verify the image's signature?**
No, it is optional. See [Installing and updating](Installing-and-updating).
