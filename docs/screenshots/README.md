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
      uv run sniff-test scan tests/fixtures/$f --json --offline -o /tmp/reports/$f.json
    done
    uv run --with playwright python scripts/doc_shots.py --reports /tmp/reports \
      --answers docs/screenshots/ai-answers.json --out /tmp/doc-shots --shots
    # then copy the chosen PNGs into docs/images/

`disclosure-light.png` and `disclosure-dark.png` are for the disclosure.yaml spec page on
the website, not for these docs. They show the made-up Petal Garden
(`tests/fixtures/petal_garden`), whose `disclosure.yaml` is the spec's sample with one
planted difference, so the caption there says it's made up.
