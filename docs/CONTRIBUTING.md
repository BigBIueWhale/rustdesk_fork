# Contributing to the hardened fork

Use this fork's repository for issues, pull requests, and review requests. Comment
on an existing issue before starting work so contributors can coordinate.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md) when participating in this project.

Read [the project rules](../AGENTS.md), [the normative requirements](../requirements.html),
and [the current hardening ledger](../HARDENING_STATUS.md) before changing behavior.
The [verification guide](../scripts/README.md) describes the available checks.

Keep each pull request focused on one problem and base it on the fork's current
`master`. Each commit should compile and pass the checks relevant to its change.
Include a Developer Certificate of Origin sign-off with `git commit -s`, and
preserve the [project license](../LICENCE) and required attribution.

Describe the behavior before and after the change, the affected authority or
lifetime boundary, and how it was verified. Security fixes need focused tests
that distinguish the unsafe behavior from the required result. Run product,
build, and test payloads only in the owned isolated environment required by the
project rules. State the exact platform and scope of the evidence; source checks
and component tests cannot establish installed-service or release acceptance.

Keep timeless requirements in `requirements.html` and implementation status in
`HARDENING_STATUS.md`. Record unresolved risks and missing native evidence there
instead of describing partial work as complete.
