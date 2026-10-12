# sigillum

**A standalone CLI that signs release artefacts and decrypts the vulnerability reports sent to your security contact.**

`sigillum` does two jobs for a project's release pipeline and security contact.

It produces **signatures** over release artefacts: OpenPGP for checksum
manifests, minisign for the artefacts themselves. The `sign` and `keys` commands
are the same ones `gtb sign` and `gtb keys` provide, mounted here as
**top-level** commands, so a release pipeline written in any language can call
them.

It also **receives encrypted vulnerability reports**. `certificate` assembles
the OpenPGP certificate you publish at your security contact address, and
`decrypt` reads the reports researchers send to it. Both keys behind that
certificate live in a key service. The private halves never leave it, so
decrypting a report is a key-service call rather than a key on a laptop.

The binary's own description string still reads "signing and verification CLI".
The command surface does not bear that out: there is no verify command. See
[What it does not do](#what-it-does-not-do).

It is built on [gtb](https://gitlab.com/phpboyscout/go-tool-base), but your own
pipeline needs neither gtb nor Go. Install one binary and sign.

## What it does

- **`sigillum sign <input-file>`** produces a **detached** signature over a file
  using a configured backend. The format is armored OpenPGP
  (`--format openpgp`, the default) for checksum manifests, or minisign
  (`--format minisign`) for release artefacts. The private key never leaves the
  KMS or the local PEM file.
- **`sigillum keys generate`** generates a fresh keypair locally (Ed25519 or
  RSA) and writes both halves.
- **`sigillum keys mint`** mints an ASCII-armored OpenPGP public key from an
  existing signer, such as an AWS KMS key.
- **`sigillum keys wkd`** builds a Web Key Directory tree from your public keys,
  so verifiers can fetch them from your own domain.
- **`sigillum keys minisign`** prints the minisign public key that release
  consumers (cargo-binstall, rtb-update) pin.
- **`sigillum keys publish`** stages a minisign public key into a static keys
  site, with a machine-readable `keys.json` manifest.
- **`sigillum certificate`** assembles the OpenPGP certificate to publish at
  your security contact address, from a certification key and an encryption
  subkey that both live in a key service. The same `--created` and the same
  keys always give the same fingerprints, because the creation time is hashed
  into them. Byte-identical output also needs `--signed-at` and
  `--reproducible`.
- **`sigillum decrypt [message]`** reads a vulnerability report encrypted to
  that certificate, from a file or from stdin. A message addressed to a
  different certificate is refused before any key-service call is made.

## What it does not do

**There is no `sigillum verify`.** sigillum signs and decrypts. Verification
happens elsewhere: `gpg --verify` for OpenPGP output, `minisign -Vm` (or the
consumers themselves) for `.minisig` output, and the Go library
`gitlab.com/phpboyscout/go/signing/verify` for tools checking their own
downloads during self-update.

The OpenPGP and minisign paths also need **different key algorithms** (RSA and
Ed25519 respectively), and one key cannot serve both. The full list of limits is
in [`docs/explanation/what-sigillum-does-not-do.md`](docs/explanation/what-sigillum-does-not-do.md).

## Architecture

The signing logic is upstream in `go/signing`, and sigillum adds none of its
own. The encryption side is different. The cryptographic primitives and the
certificate assembler are upstream in `go/encryption`, but reading an OpenPGP
message for `decrypt` (the framing, the
walk over recipients, the size and compression bounds) lives in sigillum's
`internal/openpgp`, because nothing upstream does it.

```
sigillum
   ├─ sign, keys      →  go/signing-cli  →  go/signing  (+ openpgpkey, verify)
   │                         (cobra builders)   (all signing & verification logic)
   │       ├─ go/signing-aws-kms   AWS KMS backend   (blank-imported)
   │       └─ go/signing/local     local PEM backend (blank-imported)
   │
   ├─ decrypt         →  internal/openpgp  →  go/encryption
   │                      (message reading)     (certificate assembly and parsing,
   └─ certificate     →  go/encryption           ECDH key derivation, key unwrap)
       (both sigillum's own pkg/cmd)
           ├─ go/encryption-aws-kms   AWS KMS backend   (blank-imported)
           └─ go/encryption/local     local PEM backend (blank-imported)
```

The two sides are separate all the way down, including their key-service
registries. Signing needs a key that signs, decryption needs one that performs
ECDH key agreement, and `--backend` selects from whichever registry the command
uses.

- **`go/signing`** holds all signing and verification logic.
- **`go/signing-cli`** holds only the cobra command builders (`sign`, `keys`).
  It depends on `go/signing`, cobra and a few small toolkit modules, and on
  neither gtb nor sigillum, so there is no module cycle back to either.
- **`go/encryption`** holds the OpenPGP certificate assembler and parser, the
  RFC 6637 key derivation and the AES key unwrap. The `decrypt` and
  `certificate` commands live in sigillum's own `pkg/cmd` rather than upstream,
  because sigillum is their only consumer.
- **sigillum** attaches those commands to its root and blank-imports the backends
  it ships. Which backends are compiled in is a build-time decision. A regulated
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

Generate a local keypair, sign a file and verify it. No cloud account is needed:

```bash
# 1. Generate a keypair (algorithm is an explicit, required choice)
sigillum keys generate --algorithm rsa --rsa-bits 4096 \
    --name "Test Signer" --email test@example.org \
    --output release.asc --private-output release.pem

# 2. Sign a file with the local backend
sigillum sign --backend local --key-id ./release.pem \
    --public-key ./release.asc checksums.txt   # writes checksums.txt.sig

# 3. Verify with gpg
gpg --import release.asc
gpg --verify checksums.txt.sig checksums.txt
```

For the production AWS KMS path (`--backend aws-kms --kms-region … --key-id
alias/…`) and CI with OIDC, see
[Sign a release artefact](docs/how-to/sign-a-release-artefact.md).

## Documentation

The documentation site source lives in [`docs/`](docs/) and follows the
[Diátaxis](https://diataxis.fr/) framework:

- **[Tutorials](docs/tutorials/index.md)**: install, generate a key, sign and
  verify.
- **[How-to guides](docs/how-to/index.md)**: sign a release artefact, sign an
  artefact for Rust consumers, generate or mint a key, publish a WKD tree,
  receive an encrypted report.
- **[CLI reference](docs/reference/cli/index.md)**: every command, flag,
  default and failure mode.
- **[Configuration reference](docs/reference/config/index.md)**: the keys the
  framework reads, and the ones that do not exist.
- **[Explanation](docs/explanation/index.md)**: the architecture, its
  rationale, and
  [what sigillum does not do](docs/explanation/what-sigillum-does-not-do.md).

Serve the site locally with `just docs-serve`.

## Prerequisites

- **Go 1.27.2** or newer, to build and install from source. That is the
  module's `go` directive.

The following are only needed for **development** (each is invoked by a `just`
recipe): [`just`](https://github.com/casey/just),
[`golangci-lint`](https://golangci-lint.run),
[`pre-commit`](https://pre-commit.com), `zensical` (docs site), and
[`goreleaser`](https://goreleaser.com).

## Build and develop

This repository ships a [`justfile`](justfile) with the common tasks:

```bash
just            # tidy + generate + build → bin/sigillum
just build      # the same, explicitly
just install    # install the built binary into $GOPATH/bin

just test              # unit tests with coverage
just test-race         # tests under the race detector
just test-e2e          # behaviour suite (sets INT_TEST_E2E=1)
just test-integration  # integration tests (sets INT_TEST=1)
just lint              # golangci-lint
just check             # pre-commit hooks across the tree
just ci                # tidy, generate, test, test-race, lint
```

Run `just ci` before opening a merge request; it mirrors what CI runs. The e2e
and integration suites are gated by environment variables, and a bare
`go test` of them runs nothing and still reports `ok`, so use the `just`
recipes.

### Project layout

| Path | What lives there |
| --- | --- |
| `cmd/sigillum/` | The `main` entry point and the blank imports that decide what is compiled in: signing backends (`signing.go`), encryption backends (`encryption.go`), the OS keychain (`keychain.go`) and the GitLab release source (`forge.go`). |
| `pkg/cmd/root/` | The root command: wiring, config loading, and attaching `sign` and `keys` from `go/signing-cli` alongside `decrypt` and `certificate`. |
| `pkg/cmd/decrypt/`, `pkg/cmd/certificate/` | sigillum's own commands. |
| `internal/openpgp/` | Reading and decrypting an OpenPGP message for `decrypt`. |
| `internal/signguard/` | Refuses a `sign` run whose local key file is an armored OpenPGP secret key, and names the lane that takes it. |
| `internal/opfile/`, `internal/opdest/`, `internal/oprun/` | File handling and argument checks shared by `decrypt` and `certificate`. |
| `internal/version/` | Build-time version metadata (injected via ldflags). |
| `features/` | The Godog behaviour suite. |
| `docs/` | The documentation site source (built by `zensical`). |
| `.gtb/` | The gtb generator manifest and ignore rules. |

`pkg/cmd/root/cmd.go` is generated by gtb, including the lines that attach the
signing commands: `.gtb/manifest.yaml` lists `go/signing-cli` under
`external_commands`. Change it by re-running the generator, not by hand.

## Contributing

- Follow [Conventional Commits](https://www.conventionalcommits.org/) for every
  commit. The changelog and version bumps are computed from them.
- Run `just ci` before opening a merge request.

## Releasing

Releases are cut by colophon, the estate's release tool, which proposes a
release merge request from the Conventional Commits on `main`. Merging that
request tags the release, and the tag pipeline runs
[GoReleaser](https://goreleaser.com) to publish the build artefacts and deploys
the docs site.

## License and source

- Repository (source and issues): <https://gitlab.com/phpboyscout/sigillum>
- Framework docs (gtb): <https://gtb.phpboyscout.uk/>
