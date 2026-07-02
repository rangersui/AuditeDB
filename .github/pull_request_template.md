## What

Briefly describe the change.

## Linked Issues

Closes #N, or write "no linked issue".

## Why

What problem does this solve?

## Surface

- [ ] Rust core
- [ ] Python SDK
- [ ] CoAP
- [ ] Packaging / release
- [ ] Docs only

## Review Shape

- [ ] One coherent change per PR; commits will be squashed on merge
- [ ] Production diff is under 500 lines, or maintainer sign-off is noted
- [ ] New Rust production files are under 500 lines, or maintainer sign-off is noted
- [ ] Pure move / extraction is declared if applicable

## Core Checklist

For Rust core changes:

- [ ] Blocking work is off the Tokio worker path
- [ ] Storage errors propagate explicitly
- [ ] Auth gate is correct
- [ ] Notify behavior matches externally visible state
- [ ] Durable mutations are audited
- [ ] Response headers obey the denylist
- [ ] Resources are bounded
- [ ] Expected storage exhaustion maps to 507
- [ ] Docs and tests cover new public behavior

## Verification

Paste the commands you ran and their results.

```text

```

## Follow-ups

List intentional follow-ups that are not part of this PR.
