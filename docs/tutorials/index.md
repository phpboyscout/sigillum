---
title: Tutorials
description: Learning-oriented walkthroughs that take you from nothing to a signed, verified release with sigillum.
tags: [tutorials, learning, signing]
---

# Tutorials

Learning-oriented lessons. Each one starts from nothing, uses only the `local`
backend so it needs no cloud account, and ends with something you can check.

- **[Sign and verify your first release](sign-and-verify-your-first-release.md)**
  — install sigillum, generate an RSA keypair, produce an OpenPGP detached
  signature, and verify it with `gpg`. About ten minutes.

## Which tutorial covers the minisign path?

None. The minisign lane — Ed25519 keys, `.minisig` artefact signatures, and the
public keys that cargo-binstall and rtb-update pin — is written as a
task-oriented guide rather than a lesson:
[Sign an artefact for Rust consumers](../how-to/sign-an-artefact-for-rust-consumers.md).
It assumes you have already been through the tutorial above.

## Where to look once the tutorial is done

Tutorials teach; they are not the place to look things up.

- [How-to guides](../how-to/index.md) — one concrete task each, assuming you
  already know the basics.
- [Reference](../reference/index.md) — every command, flag, default and error.
- [Explanation](../explanation/index.md) — why sigillum is built this way, and
  [what it does not do](../explanation/what-sigillum-does-not-do.md).
