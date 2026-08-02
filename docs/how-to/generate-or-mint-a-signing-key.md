---
title: Generate or mint a signing key
description: Generate a fresh OpenPGP keypair locally with sigillum, or mint the ASCII-armored public key from an existing signer (AWS KMS or a local PEM file) — the file you ship and publish via WKD.
date: 2026-07-28
tags: [how-to, keys, generate, mint, aws-kms, local, signing]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Generate or mint a signing key

There are two ways to obtain the OpenPGP **public key** file (`release.asc`) that
identifies your signing key:

- **`keys generate`** — create a brand-new keypair locally (both halves), for
  development, air-gapped signing, or a rotation-authority key.
- **`keys mint`** — derive the armored public key from a private key that
  *already exists* elsewhere (an AWS KMS key, or a local PEM). The private half
  never leaves its HSM/KMS.

Both produce the same kind of `release.asc`: the identity source you pass to
[`sigillum sign --public-key`](sign-a-release-artefact.md) and publish via
[WKD](publish-a-wkd-tree.md).

## Generate a fresh keypair

`keys generate` emits both halves of a new keypair. The algorithm is a required,
explicit choice — a signing tool should not silently pick one for you:

```bash
sigillum keys generate \
    --algorithm ed25519 \
    --name "Release Signer" --email release@example.org \
    --output release.asc --private-output release.priv.asc
```

For RSA:

```bash
sigillum keys generate \
    --algorithm rsa --rsa-bits 4096 \
    --name "Release Signer" --email release@example.org \
    --output release.asc --private-output release.pem
```

Notes:

- `--algorithm` accepts `ed25519` or `rsa` and has **no default** — omitting it
  fails with `required flag(s) "algorithm" not set`.
- `--rsa-bits` (default `4096`; `2048`/`3072`/`4096` accepted) applies only to
  RSA and is ignored for Ed25519.
- `--private-output` defaults are derived from `--output`: `.asc` → `.priv.asc`
  for Ed25519, `.asc` → `.pem` for RSA. The RSA `.pem` is exactly what the
  `local` signing backend consumes.

### The Ed25519 private half is not a PEM by default

`--algorithm ed25519` writes its private half as an **armored OpenPGP
secret-key block** (`.priv.asc`) — the same wire format `gpg
--export-secret-keys` produces. The `local` signing backend cannot read that; it
reads PEM, and pointing `--key-id` at a `.priv.asc` fails with `no PEM block
found in file`.

Add `--private-format pem` when the key needs to sign locally:

```bash
sigillum keys generate \
    --algorithm ed25519 --private-format pem \
    --name "Artefact Signer" --email release@example.org \
    --output artefact.asc --private-output artefact.pem
```

That writes an unencrypted PKCS#8 PEM, and it is what makes
[minisign artefact signing](sign-an-artefact-for-rust-consumers.md) possible
without an HSM. `--private-format openpgp` is refused for RSA, whose private
half is always PKCS#1 PEM.
- `--created <rfc3339>` pins the creation timestamp for a reproducible key
  (the timestamp folds into the fingerprint).
- `keys generate` refuses to overwrite existing output; pass `--force` to
  clobber.

## Mint a public key from an existing signer

Use `keys mint` when the private key already lives in AWS KMS (production) or as
a local PEM file. Minting bridges "a `crypto.Signer` somewhere" to "a valid
OpenPGP public key on disk" — it does **not** generate a private key.

`keys mint` is **RSA-only**, because it builds an OpenPGP entity. Pointing it at
an Ed25519 key fails with `minting armored public key: got ed25519.PublicKey:
unsupported key type: only RSA is supported`. The minisign equivalent for an
Ed25519 key is
[`keys minisign`](sign-an-artefact-for-rust-consumers.md#emit-the-public-key-consumers-pin),
which emits a minisign public key rather than an OpenPGP one.

### AWS KMS (production)

```bash
sigillum keys mint \
    --backend aws-kms \
    --kms-region eu-west-2 \
    --key-id alias/release-signing-v1 \
    --name "Release Signer" --email release@example.org \
    --output release.asc
```

What happens:

1. `kms:GetPublicKey` learns the RSA public half.
2. An OpenPGP entity is built around it (v4 public-key packet, your User ID, and
   a positive-cert self-signature). **The self-signature is produced by exactly
   one `kms:Sign` call** — the only time the KMS private half is consulted.
3. The result is ASCII-armored to `--output` and the fingerprint is logged at
   INFO so you can record it in your runbook.

`keys mint` refuses to overwrite an existing `--output`; pass `--force` to
re-mint to the same path.

### Local PEM (development)

```bash
sigillum keys mint \
    --backend local \
    --key-id signing.pem \
    --name "Release Signer" --email release@example.org \
    --output release.asc
```

This reads `signing.pem` (unencrypted PKCS#1 or PKCS#8) and writes `release.asc`
the same way. It pairs naturally with `keys generate --algorithm rsa`, which
produces exactly that PEM format.

## Reproducibility: `--created`

Both commands use `time.Now()` for the OpenPGP creation timestamp by default,
and the timestamp folds into the fingerprint. If you must **re-derive** an
existing key (e.g. you lost `release.asc` but the KMS material is intact), pin
`--created` to the original creation time — same material + same UID + same
creation time yields the same fingerprint:

```bash
sigillum keys mint ... --created 2026-07-28T00:00:00Z
```

## Smoke-test the result

```bash
gpg --show-key --with-fingerprint release.asc
# pub   ...  <date> [SC]
#       <40-char fingerprint>
# uid   Release Signer <release@example.org>
```

## What to do with `release.asc`

- **Ship it** — embed the file in the tool that will verify your releases (its
  trust set), so verification has an in-binary anchor.
- **Publish it** — serve it via [WKD](publish-a-wkd-tree.md) so verifiers can
  cross-check the embedded copy against an externally-administered one.

Both copies must carry the **same fingerprint**; a verifier that cross-checks
them refuses to proceed if they disagree.

## Related

- [Sign a release artefact](sign-a-release-artefact.md)
- [Publish a WKD tree](publish-a-wkd-tree.md)
- [Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md)
  — the Ed25519/minisign counterpart to everything on this page
- [`keys` command reference](../reference/cli/keys.md) — every flag, default and
  failure mode
- [What sigillum does not do](../explanation/what-sigillum-does-not-do.md)
