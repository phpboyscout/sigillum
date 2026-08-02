---
title: sigillum
description: Sign and verify release artefacts from the command line, with the private key never leaving your KMS.
tags: [overview, introduction, signing]
hide:
  - navigation
---

<div class="hero">
  <div class="hero-mark">
    <img src="images/branding/logo_transparent.svg" alt="">
  </div>
  <div class="hero-body">
    <h1 class="hero-title">sigillum</h1>
    <p class="hero-tagline">Sign a release. Nothing else.</p>
    <p class="hero-description">
      A standalone command-line tool for signing release artefacts, as OpenPGP or
      as minisign. The private key never leaves your KMS, HSM or PEM file, the
      output is an ordinary detached signature the standard tools accept, and
      nothing about it cares what language your project is written in.
    </p>
    <div class="install-box">
      <span class="install-command">go install gitlab.com/phpboyscout/sigillum/cmd/sigillum@latest</span>
      <button class="install-copy" type="button" title="Copy to clipboard">copy</button>
    </div>
    <div class="hero-buttons">
      <a href="tutorials/sign-and-verify-your-first-release/" class="btn btn-primary">Get started</a>
      <a href="how-to/" class="btn btn-secondary">How-to guides</a>
    </div>
  </div>
</div>

<div class="cap-grid">
  <div class="cap">
    <h3>Sign</h3>
    <p>Turn any file into a detached signature — armored OpenPGP for checksum manifests, minisign for release artefacts. The key stays in the backend; only a digest is ever sent to it.</p>
  </div>
  <div class="cap">
    <h3>Mint</h3>
    <p>Build a real OpenPGP public key from a signer you already have, including an AWS KMS key that cannot export its private half.</p>
  </div>
  <div class="cap">
    <h3>Generate</h3>
    <p>Create a fresh Ed25519 or RSA keypair locally, when a hosted key is more ceremony than the job needs.</p>
  </div>
  <div class="cap">
    <h3>Publish</h3>
    <p>Lay out a Web Key Directory tree and a minisign keys site, so verifiers fetch your keys from your own domain rather than from whoever hosts your code.</p>
  </div>
</div>

## Why a separate tool

The signing commands began life inside [go-tool-base](https://gtb.phpboyscout.uk),
which is both a library and a CLI and could therefore carry both. That works
until something wants the *commands* without the framework: it ends up depending
on the whole of gtb, which depends on the signing module, and the dependency
graph stops being a graph.

sigillum is the leaf that resolves it — a pure CLI over
[`go/signing`](https://signing.go.phpboyscout.uk), depending on the framework and
depended on by nothing. The command surface is identical to `gtb sign` and
`gtb keys`; sigillum simply makes those commands the *whole* tool, so a release
pipeline that is not Go, and was never built with gtb, can still use them.

## Sign a file in one command

```bash
sigillum sign \
    --backend aws-kms \
    --kms-region eu-west-2 \
    --key-id alias/release-signing-v1 \
    --public-key release.asc \
    checksums.txt
```

That writes `checksums.txt.sig`, an armored detached signature that `gpg --verify`
(and every other modern OpenPGP implementation) accepts. Swap `--backend aws-kms`
for `--backend local --key-id ./release.pem` to sign with an on-disk key instead.

## How do I verify a signature?

Not with sigillum — it signs, and there is no `sigillum verify`. Use
`gpg --verify` for OpenPGP signatures and `minisign -Vm` for `.minisig` artefact
signatures, or let the consumers do it: cargo-binstall and rtb-update both
verify before installing. The reasoning, and the rest of the limits, are in
[What sigillum does not do](explanation/what-sigillum-does-not-do.md).

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

- **[Tutorials](tutorials/index.md)** — install, generate a key, sign a file and
  verify it, start to finish.
- **[How-to guides](how-to/index.md)** — sign a release artefact, sign an
  artefact for Rust consumers, generate or mint a signing key, publish a WKD
  tree.
- **[Reference](reference/index.md)** — every command, flag, default,
  configuration key and failure mode.
- **[Explanation](explanation/index.md)** — the architecture, the reasoning
  behind it, and [what sigillum does not
  do](explanation/what-sigillum-does-not-do.md).
