# Advisory re-checks

A scan is reused for as long as an app stays at that version. But a vulnerability, or a
package found to be malicious, can be published after the scan was made.

So each scan keeps the exact list of packages it resolved, and **once a day** Barkley
asks the advisory database (OSV, through osv-scanner) about those packages again, for
every installed version and every update waiting. This takes seconds, because the app's code isn't fetched or scanned again and GitHub isn't asked anything.

- **Nothing changed:** you hear nothing. The app's page notes when advisories were last
  asked.
- **Something changed:** the result is stored as a **new entry**. The earlier entry
  stays in the history exactly as it was. The readings are worked out again by the same
  rules, and you get a notification with the two readings, the Exposure number before,
  counts of what changed, and a link to the comparison. This notification comes
  whatever Settings → Notify when says. A package the app uses that is newly listed as
  malicious is a found threat. A build tool newly listed as malware is a possible threat
  at the default setting (Settings → Build tool known to be malware).
- **OSV can't be reached:** nothing changes, and Barkley tries again an hour later. An
  unreachable service is never treated as a result.

**Check advisories again** on an app's page does the same on request.
