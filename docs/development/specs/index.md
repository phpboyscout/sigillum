# Specs

Specs live in the [project wiki](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/home),
not in this repository.

A spec is a point-in-time decision record. It is written once, true of a
moment, and read later for its conclusions. Keeping them here buried the living documentation they
sat beside, so they moved. Contributor guides, engineering standards and testing
conventions stay in `docs/`, because those change with the code.

| Spec | Title | Status |
|---|---|---|
| [0001](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0001-sigillum-bootstrap) | Bootstrap sigillum: a standalone signing & verification CLI over go/signing | `IMPLEMENTED` |
| [0002](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0002-kms-ed25519-minisign-artifact-signing) | KMS-Ed25519 minisign artefact signing | `IMPLEMENTED` |
| [0003](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0003-mcp-tool-surface) | An MCP tool surface for sigillum | `IN PROGRESS` |
| [0004](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0004-kms-backed-openpgp-decryption) | KMS-backed OpenPGP certificate assembly and decryption | `IMPLEMENTED` |
| [0005](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0005-estate-container-image-signing) | Estate container image signing | `APPROVED` |
| [0006](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0006-countersigned-tuf-releases) | Countersigned TUF releases | `DRAFT` |
| [0007](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0007-sigillum-is-the-signing-cli) | sigillum is the signing CLI, and the libraries own their Settings | `APPROVED` |
| [0008](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0008-keys-rotate) | keys rotate: issue a signed rotation manifest | `IMPLEMENTED` |

## Referring to a spec

By **number and name** ("0002, the minisign artefact signing spec"), never by
date. The number is a stable handle; a date is not something anyone remembers.

## Writing a new one

Claim the next number first, then draft against the canonical shape. See the
`spec-driven-development` skill in the phpboyscout marketplace.
