# Demo apps (fake, for screenshots only)

Two made-up Marketplace (HACS) apps used to show what Barkley reports. **Never install them.**
Every server they name ends in `.invalid`, a domain that can never resolve.

- `sunbeam-forecast-card/`: a weather card that looks normal, but a dependency bundled into it reads
  your Home Assistant login and sends it away. Its lockfile pins the real event-stream 3.3.6 /
  flatmap-stream 0.1.1 pair from the 2018 npm supply-chain attack (it's only read, never installed).
- `petal-garden-hub/`: an integration that isn't malicious, just careless: an HTTP endpoint with no
  login, a shell command built from your settings, plain MQTT on port 1883, and an old dependency
  with known vulnerabilities.

Scan them with `sniff-test scan demo/<name> --store <db>` and look with `sniff-test serve`.
