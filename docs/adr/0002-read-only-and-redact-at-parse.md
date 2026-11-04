# Read-only, and redact at parse time

driftscan never applies, never takes a state lock (`plan -lock=false`) and never obtains credentials itself: the caller provides them per Root as environment variables, ideally short-lived and read-only. Plan JSON is reduced to resource addresses, types and changed attribute paths the moment it is parsed, and the raw plan file is deleted, so no later stage (Report, Slack, SARIF, metrics) can leak a value. Attribute values are not emitted at all in v1.

## Consequences

- A Finding says which attribute drifted, not to what. Reviewers open the provider console or run `plan` themselves for values.
- Because the plan needs read access to every resource and to state, the identity running driftscan is the real security boundary, not driftscan.
