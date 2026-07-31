# Specs

Specs live in the [project wiki](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/home),
not in this repository.

A spec is a point-in-time decision record — written once, true of a moment, read
later for its conclusions. Keeping them here buried the living documentation they
sat beside, so they moved. Contributor guides, engineering standards and testing
conventions stay in `docs/`, because those change with the code.

| Spec | Title | Status |
|---|---|---|
| [0001](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0001-sigillum-bootstrap) | Bootstrap sigillum: a standalone signing & verification CLI over go/signing | `IMPLEMENTED` |
| [0002](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0002-kms-ed25519-minisign-artifact-signing) | KMS-Ed25519 minisign artefact signing | `IN PROGRESS` |

## Referring to a spec

By **number and name** — "0002, the minisign artefact signing spec" — never by
date. The number is a stable handle; a date is not something anyone remembers.

## Writing a new one

Claim the next number first, then draft against the canonical shape. See the
`spec-driven-development` skill in the phpboyscout marketplace.
