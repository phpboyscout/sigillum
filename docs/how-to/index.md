---
title: How-to guides
description: Task-oriented guides for signing and publishing with sigillum — OpenPGP manifests, minisign artefacts, key generation and trust-anchor publication.
tags: [how-to, signing, keys, publishing]
---

# How-to guides

Task-oriented guides. Each one walks through a single concrete task and assumes
you already know the basics — start with
[Sign and verify your first release](../tutorials/sign-and-verify-your-first-release.md)
if you do not.

## The OpenPGP lane — signing checksum manifests

- **[Sign a release artefact](sign-a-release-artefact.md)** — produce a detached
  OpenPGP signature with the AWS KMS or local PEM backend, dual-sign during a
  key rotation, and wire it into GitLab CI with AWS OIDC.
- **[Generate or mint a signing key](generate-or-mint-a-signing-key.md)** —
  generate a fresh keypair locally, or mint an OpenPGP public key from a signer
  that already exists in KMS.
- **[Publish a WKD tree](publish-a-wkd-tree.md)** — serve your public keys from
  your own domain so verifiers can cross-check them against an
  externally-administered copy.

## The minisign lane — signing release artefacts

- **[Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md)**
  — produce a `.minisig` artefact signature, emit the public key cargo-binstall
  and rtb-update pin, and publish it into a keys site with a manifest.

## Which lane do I need?

Both, if you publish a checksum manifest *and* downloadable artefacts. They use
different key algorithms — RSA for OpenPGP, Ed25519 for minisign — and one key
cannot serve both, so a project doing both runs two keys.

The [CLI reference](../reference/cli/index.md#which-key-algorithm-do-i-need)
has the compatibility table, and
[What sigillum does not do](../explanation/what-sigillum-does-not-do.md)
explains why the two cannot be merged.
