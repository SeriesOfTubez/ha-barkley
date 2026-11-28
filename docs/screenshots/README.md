# Screenshots

The pictures in `docs/images/` come from Barkley's own made-up test apps
(`tests/fixtures`), never from a real project. `scripts/doc_shots.py` scans nothing itself:
it reads their reports, loads the AI answers in `ai-answers.json`, and renders the panel's
pages light and dark.

`ai-answers.json` holds real answers to Barkley's own requests for those apps, written by
Claude Sonnet 5.5 standing in for the AI Task model a user picks. Each answer goes through
the same checks as on a real box, so only what passes is shown. A user's own model will
answer differently.

To make them again:

    for f in evil_integration evil_card hidden_card clean_integration clean_integration_v2 oauth_redirects petal_garden; do
      uv run sniff-test scan tests/fixtures/$f --json --ha-version 2026.11.2 -o /tmp/reports/$f.json
    done
    uv run --with playwright python scripts/doc_shots.py --reports /tmp/reports \
      --answers docs/screenshots/ai-answers.json --out /tmp/doc-shots --shots
    # then copy the chosen PNGs into docs/images/

Don't add `--offline`: it skips the dependency checks, so every app with requirements
shows as Unfinished. The dependency checks ask PyPI about the test apps' made-up
requirements. Without Chrome, pass Playwright's own browser with `--chromium`.

`disclosure-light.png` and `disclosure-dark.png` are in An app's page and on the
disclosure.yaml spec page on the website. They show the made-up Petal Garden
(`tests/fixtures/petal_garden`), whose `disclosure.yaml` is the spec's sample with one
planted difference, so the caption in both places says it's made up.
