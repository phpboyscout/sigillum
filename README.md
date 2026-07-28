# sigillum

**Standalone artefact signing and verification CLI for the phpboyscout
ecosystem.**

`sigillum` is a small, single-purpose command-line tool that produces and
publishes OpenPGP signatures over release artefacts. It exposes the ecosystem's
`sign` and `keys` commands as first-class, **top-level** commands — the same
command surface as `gtb sign` / `gtb keys`, but as a purpose-built utility you
can drop into any release pipeline, Go or not.

It is built on [gtb](https://gitlab.com/phpboyscout/go-tool-base), but its reason
to exist is signing: any non-Go / non-gtb pipeline can install one small binary
and sign, with no framework build required.

## What it does

- **`sigillum sign <input-file>`** — produce an ASCII-armored OpenPGP **detached**
  signature over a file using a configured backend. The private key never leaves
  the HSM/KMS or the local PEM file.
- **`sigillum keys generate`** — generate a fresh keypair locally (Ed25519 or
  RSA) and emit both halves.
- **`sigillum keys mint`** — mint an ASCII-armored OpenPGP public key from an
  existing signer (e.g. an AWS KMS key).
- **`sigillum keys wkd`** — generate a Web Key Directory tree from your public
  keys for external trust-anchor publication.

Signatures verify under `gpg --verify`, any modern OpenPGP implementation, and
the in-tool verifier in `gitlab.com/phpboyscout/go/signing/verify`.

## Architecture

sigillum is deliberately thin. All signing logic is upstream; sigillum wires the
command surface together and ships the backends:

```
sigillum  →  go/signing-cli  →  go/signing  (+ go/signing/openpgpkey, .../verify)
   │              (sign / keys        (all signing &
   │               cobra builders)     verification logic)
   │
   ├─ go/signing-aws-kms   AWS KMS backend   (blank-imported)
   └─ go/signing/local     local PEM backend (blank-imported)
```

- **`go/signing`** holds all signing/verification logic.
- **`go/signing-cli`** holds only the cobra command builders (`sign`, `keys`);
  it depends on `go/signing` + cobra and nothing else, so there is no module
  cycle back to gtb or sigillum.
- **sigillum** attaches those commands to its root and blank-imports the backends
  it ships. Which backends are compiled in is a build-time decision — a regulated
  build can drop a blank import and rebuild, and linker dead-code elimination
  keeps the unused SDK out of the binary.

See [`docs/explanation/`](docs/explanation/index.md) for the full rationale.

## Install

Install the latest release with `go install`:

```bash
go install gitlab.com/phpboyscout/sigillum/cmd/sigillum@latest
```

The `main` package lives at `cmd/sigillum/`, so the install path ends in
`/cmd/sigillum`. Alternatively, download a pre-built binary from the
[GitLab Releases](https://gitlab.com/phpboyscout/sigillum/-/releases) page.

## Quick start

Generate a local keypair, sign a file, and verify it — no cloud account needed:

```bash
# 1. Generate a keypair (algorithm is an explicit, required choice)
sigillum keys generate --algorithm rsa --rsa-bits 4096 \
    --name "Test Signer" --email test@example.org \
    --output release.asc --private-output release.pem

# 2. Sign a file with the local backend
sigillum sign --backend local --key-id ./release.pem \
    --public-key ./release.asc checksums.txt   # → checksums.txt.sig

# 3. Verify with gpg
gpg --import release.asc
gpg --verify checksums.txt.sig checksums.txt
```

For the production AWS KMS path (`--backend aws-kms --kms-region … --key-id
alias/…`) and CI/OIDC integration, see
[Sign a release artefact](docs/how-to/sign-a-release-artefact.md).

## Documentation

The documentation site source lives in [`docs/`](docs/) and follows the
[Diátaxis](https://diataxis.fr/) framework:

- **[Getting Started](docs/getting-started.md)** — install, generate a key, sign,
  and verify.
- **[How-to guides](docs/how-to/index.md)** — sign a release artefact, generate
  or mint a key, publish a WKD tree.
- **[CLI reference](docs/reference/cli/index.md)** — every command and flag.
- **[Explanation](docs/explanation/index.md)** — the architecture and its
  rationale.

Serve the site locally with `just docs-serve`.

## Prerequisites

- **Go 1.26.5** or newer — required to build and install from source.

The following are only needed for **development** (each is invoked by a `just`
recipe): [`just`](https://github.com/casey/just),
[`golangci-lint`](https://golangci-lint.run),
[`pre-commit`](https://pre-commit.com), `zensical` (docs site), and
[`goreleaser`](https://goreleaser.com).

## Build & develop

This repository ships a [`justfile`](justfile) with the common tasks:

```bash
just            # tidy + generate + build → bin/sigillum
just build      # the same, explicitly
just install    # install the built binary into $GOPATH/bin

just test       # unit tests with coverage
just test-race  # tests under the race detector
just lint       # golangci-lint
just check      # pre-commit hooks across the tree
just ci         # the full local CI suite (tidy, generate, test, test-race, lint)
```

Run `just ci` before opening a merge request — it mirrors what CI runs.

### Project layout

| Path | What lives there |
| --- | --- |
| `cmd/sigillum/` | The `main` entry point, backend blank-imports (`signing.go`), and keychain opt-in (`keychain.go`). |
| `pkg/cmd/root/` | The root command — wiring, config loading, and the `sign` / `keys` attachment from `go/signing-cli`. |
| `internal/version/` | Build-time version metadata (injected via ldflags). |
| `docs/` | The documentation site source (served by `zensical`). |
| `.gtb/` | The gtb generator manifest and ignore rules. |

`pkg/cmd/root/cmd.go` is generated by gtb but then hand-customised to attach the
signing commands, so it is marked hands-off in `.gtb/ignore`. Do not expect
`gtb regenerate` to re-render it.

## Contributing

- Follow [Conventional Commits](https://www.conventionalcommits.org/) for every
  commit — the changelog and version bumps are computed from them.
- Run `just ci` before opening a merge request.

## Releasing

Releases are driven by Conventional Commits and run through the scaffolded GitLab
CI pipeline together with [GoReleaser](https://goreleaser.com). Merging the
release cuts the tag and publishes the build artefacts.

## License & source

- Repository (source & issues) — <https://gitlab.com/phpboyscout/sigillum>
- Framework docs (gtb) — <https://gtb.phpboyscout.uk/>
