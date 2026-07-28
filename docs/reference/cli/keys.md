---
title: keys command
description: Reference for `sigillum keys` — generate, mint, and publish OpenPGP keys for release-binary signing.
date: 2026-07-28
tags: [reference, commands, keys, signing, openpgp]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `keys` Command

`sigillum keys` manages OpenPGP keys used for release-binary signing. See
[Generate or mint a signing key](../../how-to/generate-or-mint-a-signing-key.md)
and [Publish a WKD tree](../../how-to/publish-a-wkd-tree.md) for the operational
procedures.

## Usage

```bash
sigillum keys <subcommand> [flags]
```

## Subcommands

| Subcommand | Purpose |
|---|---|
| `generate` | Generate a fresh keypair locally (Ed25519 or RSA) and emit both halves. |
| `mint` | Mint an ASCII-armored public key from an existing signer (e.g. a KMS key). |
| `wkd <public-key.asc>…` | Build a Web Key Directory tree from one or more public keys. |

### `keys generate`

Generate a new keypair locally. The algorithm is a required, explicit choice —
there is no silent default.

| Flag | Default | Description |
|------|---------|-------------|
| `--algorithm` | *(required)* | Key algorithm: `ed25519` or `rsa`. No default — must be supplied; omitting it errors and lists the valid choices. |
| `--rsa-bits` | `4096` | RSA modulus size when `--algorithm rsa` (2048/3072/4096 accepted; ignored for Ed25519). |
| `--name` | *(required)* | OpenPGP user-id real name. |
| `--email` | *(required)* | OpenPGP user-id email. |
| `--output` | `<algorithm>.asc` | Path to write the armored public key. |
| `--private-output` | *(derived from `--output`)* | Path to write the private half — `.asc` → `.priv.asc` for Ed25519, `.asc` → `.pem` for RSA. |
| `--created` | *(now)* | Fixed creation timestamp (RFC3339) for reproducible keys. |
| `--force` | `false` | Overwrite existing output files. |

### `keys mint`

Mint a public key from an existing signer; the private half never leaves its
HSM/KMS (or its PEM file).

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | Signing backend (`aws-kms`, `local`). |
| `--key-id` | *(required)* | Key id/ARN/alias (or PEM path for the `local` backend). |
| `--name` | *(required)* | OpenPGP user-id real name on the minted key. |
| `--email` | *(required)* | OpenPGP user-id email on the minted key. |
| `--output` | `release.asc` | Path to write the ASCII-armored public key. |
| `--created` | *(now)* | Fixed creation timestamp (RFC3339). |
| `--force` | `false` | Overwrite the output file. |

When `aws-kms` is compiled in, its backend flags (e.g. `--kms-region`) are also
registered on `keys mint`.

### `keys wkd`

Build a [Web Key Directory](../../how-to/publish-a-wkd-tree.md) tree. Takes one
or more public-key files as arguments.

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | *(required)* | DNS domain serving the WKD endpoint (e.g. `phpboyscout.uk`). |
| `--email` | *(all emails found in the input keys)* | Email(s) to publish (repeatable). |
| `--output` | `./wkd-staging` | Staging directory for the generated tree. |
| `--method` | `advanced` | URL layout: `advanced` (served from `openpgpkey.<domain>`) or `direct` (from `<domain>`). |
| `--submission-address` | *(none — file omitted)* | Address written to the WKD submission-address file. Empty omits the file; `auto` uses the first `--email`; an explicit address overrides. |

> Run any subcommand with `--help` for the complete, authoritative flag set.
