---
title: sign command
description: Reference for `sigillum sign` — produce an ASCII-armored OpenPGP detached signature over a file using a configured backend.
date: 2026-07-28
tags: [reference, commands, sign, signing, openpgp]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `sign` Command

`sigillum sign <input-file>` produces an ASCII-armored OpenPGP **detached**
signature for a single file using a configured signing backend. See
[Sign a release artefact](../../how-to/sign-a-release-artefact.md) for the full
procedure and [Architecture](../../explanation/components/index.md) for the
backend model.

## Usage

```bash
sigillum sign <input-file> [flags]
```

Exactly one input file is required. The private key never leaves the backend;
signing is one round-trip via `crypto.Signer`. The signature is written next to
the input (or to `--output`). `sign` refuses to write the signature over its own
input file.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | Signing backend name. Compiled-in backends: `aws-kms`, `local`. |
| `--key-id` | *(required)* | Backend-specific key identifier. For `aws-kms`: a KMS key ID, ARN, or alias. For `local`: a PEM file path. |
| `--public-key` | *(required)* | Path to the armored OpenPGP public key (`.asc`) the signature identifies. The backend's public half must match it, or `sign` refuses to proceed. |
| `--output` | *(`<input>.sig`)* | Path to write the detached signature. |
| `--created` | *(now)* | Fixed signature creation timestamp (RFC3339) for byte-identical, reproducible signatures. |
| `--append` | `false` | Merge the new signature into an existing armored signature at `--output` instead of overwriting it, producing one armored block with multiple signature packets (dual-sign rotation overlap). No-op when `--output` does not exist yet. |

### Backend-contributed flags

When the `aws-kms` backend is compiled in (as it is in sigillum), it registers
additional flags on `sign`, notably:

| Flag | Description |
|------|-------------|
| `--kms-region` | AWS region the KMS key lives in. |

> Run `sigillum sign --help` for the complete, authoritative flag set, including
> all backend-contributed flags.
