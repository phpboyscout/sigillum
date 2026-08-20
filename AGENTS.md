# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, agy, codex, etc.) when working with code in this repository.

**This file is a seed.** It carries what could be derived from the repository
and checked. What the tool is for beyond its README, where it has got to, and
the traps it sets are not here yet. Issue #8 tracks filling that in.

Ways of working live in the phpboyscout skills and are not repeated here.

## What this is

`gitlab.com/phpboyscout/sigillum` is a standalone signing and encrypted-report
CLI for the phpboyscout ecosystem, built on
[go-tool-base](https://gitlab.com/phpboyscout/go-tool-base). It produces
signatures over release artefacts, OpenPGP for checksum manifests and minisign
for the artefacts themselves, and exposes the ecosystem's `sign` and `keys`
commands as top-level commands.

## It sits on the signing and encryption families

Its direct toolkit dependencies say what it actually consumes:

- **`go/signing`, `go/signing-cli`, `go/signing-aws-kms`.** The real signing
  logic lives in `go/signing`; `go/signing-cli` owns the shareable command
  surface, and this tool exposes that surface top level rather than reimplementing
  it. A change to a shape `go/signing` owns reaches here.
- **`go/encryption`, `go/encryption-aws-kms`** for the encrypted-report half.
- **`go/credentials`, `go/errorhandling`, `go/errors`** as the common spine.

Everything else in `go.mod` arrives through go-tool-base and is marked indirect.

## It is a gtb project

`.gtb/manifest.yaml` describes the application and `.gtb/ignore` marks what the
generator must not overwrite. Use the project-pinned gtb rather than the one on
your PATH; the manifest pins `v0.37.1`. See **work-on-a-gtb-project**.

## The quality gate

`just ci` runs `tidy`, `generate`, `test`, `test-race` and `lint`. There is a
`features/` directory, so the suite includes Godog scenarios as well as unit
tests.

## Which skills apply here

| When | Skill |
|---|---|
| Changing code in this repo at all | `work-on-a-gtb-project` |
| Adding or modifying a command | `add-a-gtb-command` |
| Reading config, logging or the filesystem | `gtb-props-and-config` |
| Reaching past basic commands into the framework | `build-on-gtb-framework` |
| Handling a key, a token, an untrusted pattern or an external endpoint | `centralize-security-footguns` |
| Deciding whether a change wants a scenario or a unit test | `bdd-when-and-how` |
| Editing a `.feature` file or a step definition | `write-godog-scenarios` |
| Adding a feature that should stay reusable | `library-first-tdd` |
| Before `glab mr create` | `verify-before-pr` |
| Faking exec, `time.Now`, network or filesystem in a test | `race-safe-test-injection` |
| Adding a test that hits the network, a real API, or real git or disk | `env-gated-integration-tests` |
| Reaching for a dependency the toolkit may already have | `use-the-go-toolkit` |
| Writing a commit message or a merge request description | `conventional-commits`, `pre-1-0-release-safety` |
| Committing, branching, merging, or opening a merge request | `forge-publish-workflow` |

**`centralize-security-footguns` is the one to read first.** This tool exists to
handle keys and signatures, so a value crossing a trust boundary is the normal
case here rather than the exception.

## House rules

- Linear history. Rebase and fast-forward; never squash-merge from the UI.
- Conventional Commits, and the type decides whether a release is cut. Only
  `feat` and `fix` release.
- No AI attribution in anything published, and never at-mention anyone.
- Never cut a release yourself. That is the maintainer's call, every time.
