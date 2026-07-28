# How-to Guides

Task-oriented guides for signing and verifying release artefacts with sigillum.
Each guide assumes you already know the basics (see
[Getting Started](../getting-started.md)) and walks through one concrete task.

- **[Sign a release artefact](sign-a-release-artefact.md)** — produce a detached
  OpenPGP signature with the AWS KMS or local PEM backend, and verify it.
- **[Generate or mint a signing key](generate-or-mint-a-signing-key.md)** —
  generate a fresh keypair locally, or mint an OpenPGP public key from an
  existing signer (e.g. a KMS key).
- **[Publish a WKD tree](publish-a-wkd-tree.md)** — generate and deploy a Web
  Key Directory so verifiers can cross-check your public keys against an
  externally-served copy.
