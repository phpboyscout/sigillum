# sigillum

**sigillum** is a standalone, pure command-line tool for **signing and
verifying release artefacts** in the phpboyscout ecosystem. It exposes the
ecosystem's `sign` and `keys` commands as first-class, top-level commands so
any release pipeline — Go or not, gtb-built or not — can produce and publish
OpenPGP signatures without pulling in a whole application framework.

The command surface is identical to `gtb sign` / `gtb keys`; sigillum simply
makes those commands the *whole* tool.

## What it does

- **Sign** a file into an ASCII-armored OpenPGP **detached** signature using a
  configured backend — the private key never leaves the HSM/KMS or the local
  PEM file.
- **Mint** an OpenPGP public key from an existing signer (e.g. an AWS KMS key).
- **Generate** a fresh keypair locally (Ed25519 or RSA).
- **Publish** a Web Key Directory (WKD) tree from your public keys, giving
  verifiers an externally-served trust anchor.

## Install

```bash
go install gitlab.com/phpboyscout/sigillum/cmd/sigillum@latest
```

Or download a released binary from the
[GitLab Releases](https://gitlab.com/phpboyscout/sigillum/-/releases) page.

## Sign a file in one command

```bash
sigillum sign \
    --backend aws-kms \
    --kms-region eu-west-2 \
    --key-id alias/release-signing-v1 \
    --public-key release.asc \
    checksums.txt
```

This writes `checksums.txt.sig` — an armored OpenPGP detached signature that
`gpg --verify` (and every other modern OpenPGP implementation) accepts. Swap
`--backend aws-kms` for `--backend local --key-id ./release.pem` to sign with an
on-disk key instead.

## Architecture at a glance

sigillum is deliberately thin. All real work lives upstream; sigillum wires the
pieces together and ships the backends:

```
sigillum  (this CLI — attaches the commands, ships the backends)
   │
   ├─ go/signing-cli   the sign / keys cobra command builders
   │       │
   │       └─ go/signing            the actual signing & verification logic
   │              └─ go/signing/openpgpkey, .../verify   OpenPGP + WKD helpers
   │
   ├─ go/signing-aws-kms   AWS KMS backend   (blank-imported)
   └─ go/signing/local     local PEM backend (blank-imported)
```

- **`go/signing`** holds all signing and verification logic.
- **`go/signing-cli`** holds only the cobra command builders (`sign`, `keys`);
  it depends on `go/signing` + cobra and nothing else.
- **sigillum** attaches those commands to its root and blank-imports the
  backends it ships (AWS KMS + local PEM). Which backends are compiled in is a
  build-time decision — a regulated build can drop a blank import and rebuild.

See [Explanation](explanation/index.md) for why this is a separate tool and how
the backend model works.

## Where to go next

The documentation follows the [Diátaxis](https://diataxis.fr/) framework:

- **[Getting Started](getting-started.md)** — install, generate a key, sign a
  file, and verify it.
- **[How-to guides](how-to/index.md)** — sign a release artefact, generate or
  mint a signing key, publish a WKD tree.
- **[Reference](reference/index.md)** — every command, flag, and argument.
- **[Explanation](explanation/index.md)** — the architecture and the reasoning
  behind it.
