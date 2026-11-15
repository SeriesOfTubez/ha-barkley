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
in context** button. During the scan Barkley keeps the code around it (at most 150
lines), and you can open it under "The code it reads" before you click. On your click,
that code and the question go to your AI.

The AI answers in short statements, and each must cite the lines it rests on. Barkley
shows a statement only if the cited lines are in the code it sent, they are code and not
comments, and they contain the names the statement mentions. The page says how many
statements were left out and why. An answer can take minutes; you can close the sheet
and come back.

## What the AI can't do

- It can't set, clear or change a score or a finding. A statement that calls a finding a
  false positive, safe or harmless is dropped.
- It gets nothing from your Home Assistant: only findings and code from the public
  project.

## Where the request goes

To whatever provider your AI Task entity uses. For OpenRouter and similar integrations
that is a cloud service. Code from a scanned project can contain text aimed at the AI;
it is marked as untrusted in the request, and the checks above apply to every answer.
