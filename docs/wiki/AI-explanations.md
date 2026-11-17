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

A privacy note (telemetry, analytics, a server the developer runs, unencrypted
addresses, MQTT without encryption) shows the button, or the AI's reading, of the
address or port behind it. It is the same reading as under "Where it connects", not a
second one. A note whose addresses are all named in the app's documentation or manifest
has no reading, and says so.

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
the code it picked (at most 150 more lines) and asks again. The sheet then shows the
checked statements of both readings together, and the questions of the second. Your one
click covers both requests, the sheet says what the AI asked for, and the added code is shown under "The
code it reads". When the AI asks for something that isn't on the list, the sheet says
how many such asks were ignored and shows what they were (each cut to 60 characters).
There is never a third request.

To do this without downloading anything on your click, Barkley keeps a compressed copy
of an integration's Python files beside its scan: one copy per version, for the
installed version and an update that is waiting. Copies of older versions are deleted
(their scans stay), a copy of an app you only sniffed from search goes when its scan
ages out, and an app whose Python is over 1 MB compressed (or more than 3,000 files) gets no
copy; its sheet then says the AI can't ask for more. Dashboard cards get no copy: their bundles are minified.

### A finding about replaced Home Assistant code

For the finding "Changes how Home Assistant itself works", the page says what is
replaced, whose code that is, and where the replacement is defined, under **What it
replaces**. Barkley reads this from the code's import lines during the scan; no AI is
involved.

When what is replaced is a function in Home Assistant's own source and the replacement is
a function of the app, Barkley also compares the two. During the scan it reads that one
file of Home Assistant, at your Home Assistant version, from Home Assistant's repository
on GitHub, and compares the functions line by line. **How it differs from the original**
gives the count of lines only in the replacement and only in the original, and the
comparison itself opens underneath. No AI is involved. When there is no comparison the
page says why (for example GitHub did not answer, or the replacement is not a function);
that is never counted for or against the app. **The rest of the replacement** says
whether the scan has any other finding, address or port on the replacement's own lines.
That sentence describes what Barkley's rules look for; it is not a statement that the
code is safe. The score is the same with or without a comparison.

On such a finding, "Explain in context" also sends the comparison, so the AI can say
what the replacement does differently and cite the lines.

### The AI's opinion on the README

For the finding "Changes how Home Assistant itself works", "Explain in context" also
sends the first lines of the repository's README (at most 80), as what the app's author
says the app does. The AI
may then add one sentence saying that the code is consistent with the README. Barkley
shows it only if it cites README lines and lines of the app's code, and gives no verdict:
a sentence that calls the code safe, fine, expected or the like is dropped. It is shown
apart from the statements, under **The AI's opinion: consistent with the README**.

Read it for what it is. The README is written by the same person as the code, so code
that matches it does what the author says, which is not the same as safe. The finding
and the score do not change. No other finding gets this opinion: not one about data
leaving your Home Assistant or where it goes, and no address, port or package.

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
