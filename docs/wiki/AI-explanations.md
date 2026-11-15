# AI explanations

Optional. Barkley works without any AI, and every score comes from fixed rules.

**The explanations are only as good as the model behind the AI Task entity you pick, and
they can be wrong.** In testing, GLM 5.3 and GLM 5.3 Flash both gave good results.

## Setting it up

On any app's page, pick one of your Home Assistant AI Task entities from the dropdown,
and choose the mode. The choice made in the panel wins over the `ai_entity` and
`ai_mode` options.

The model must support structured output. Home Assistant's OpenRouter integration asks
for a strict JSON schema, so a model without schema support fails with an error on the
page.

## Summary mode: Explain this app

Each app's page gets an **Explain this app** button. Nothing is sent until you click
it. Barkley then sends that scan's findings: rule names, severities, file names and
short code excerpts from the public project that was scanned. The answer is shown as
plain text labelled as an AI explanation, next to the fixed explanation.

## Deep mode: Explain in context

Each finding, each port and each address the app's docs don't explain gets an **Explain
in context** button. During the scan Barkley keeps the code around it, and you can open
it under "The code it reads" before you click. On your click, that code and the question
go to your AI.

What the code is, for an integration: the function the finding is in; the functions
and classes of the app that it calls or refers to, starting with the ones named on the
flagged line (at most 150 lines together); and the import lines and constants behind the
names used (at most 40 more lines, plus the blank lines between them). For a dashboard
card it is the lines around the finding in the bundle.

### When the AI asks to see more

For integrations, the AI may ask once to see more of the app's code. It can only pick
from a list of names Barkley offers (functions, classes, methods and constants of the
app, at most 40 names, three picks). It can't name a file path or ask in its own words,
and anything that isn't on the list is ignored: code from a scanned project can contain
text aimed at the AI, and that text must not decide what Barkley reads. Barkley adds
the code it picked (at most 150 more lines) and asks again. Your one click covers both
requests, the sheet says what the AI asked for, and the added code is shown under "The
code it reads". There is never a third request.

To do this without downloading anything on your click, Barkley keeps a compressed copy
of an integration's Python files beside its scan: one copy per version, for the
installed version and an update that is waiting. Copies of older versions are deleted
(their scans stay), a copy of an app you only sniffed from search goes when its scan
ages out, and an app whose Python is over 1 MB compressed gets no copy; its sheet then
says the AI can't ask for more. Dashboard cards get no copy: their bundles are minified.

### A finding about replaced Home Assistant code

For the finding "Changes how Home Assistant itself works", the page says what is
replaced, whose code that is, and where the replacement is defined, under **What it
replaces**. Barkley reads this from the code's import lines during the scan; no AI is
involved.

### How answers are checked

The AI answers in short statements, and each must cite the lines it rests on. Barkley
shows a statement only if the cited lines are in the code it sent, they are code and not
comments, and they contain the names the statement mentions. The page says how many
statements were left out and why. An answer can take minutes, longer when the AI asks to see more; you
can close the sheet and come back.

## What the AI can't do

- It can't set, clear or change a score or a finding. A statement that calls a finding a
  false positive, safe or harmless is dropped.
- It gets nothing from your Home Assistant: only findings and code from the public
  project.

## Where the request goes

To whatever provider your AI Task entity uses. For OpenRouter and similar integrations
that is a cloud service. Code from a scanned project can contain text aimed at the AI;
it is marked as untrusted in the request, and the checks above apply to every answer.
