---
title: sign command
description: Reference for `sigillum sign` — every flag, its default, which signature format it belongs to, and the exact error each wrong combination produces.
date: 2026-08-02
tags: [reference, commands, sign, signing, openpgp, minisign]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `sign` command

`sigillum sign <input-file>` produces a **detached** signature for exactly one
file using a configured signing backend, in one of two formats:

| `--format` | Output | Key algorithm | For |
|---|---|---|---|
| `openpgp` (default) | `<input>.sig` | RSA only | checksum manifests, verified by `gpg` and gtb-derived tools |
| `minisign` | `<input>.minisig` | Ed25519 only | release artefacts, verified by cargo-binstall and rtb-update |

The private key never leaves the backend: signing is one round-trip via
`crypto.Signer`. The signature is written next to the input unless `--output`
says otherwise.

## Usage

```bash
sigillum sign <input-file> [flags]
```

Exactly one input file. Zero or two arguments fails with
`accepts 1 arg(s), received 0` before any flag is looked at.

## Flags for both formats

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | Signing backend name. Compiled in: `aws-kms`, `local`. An unknown name fails with the available list. |
| `--key-id` | *(required)* | Backend-specific key identifier. For `aws-kms`: a KMS key ID, ARN or alias. For `local`: a PEM file path. |
| `--format` | `openpgp` | `openpgp` or `minisign`. Anything else fails with `unknown --format "ssh"; valid values are "openpgp" and "minisign"`. |
| `--output` | `<input>.sig` / `<input>.minisig` | Path to write the detached signature. The default follows `--format`. |
| `--created` | *(now)* | Signature creation time, RFC3339, truncated to whole seconds. Pin it for byte-identical re-runs. |

`--backend` and `--key-id` are marked required by cobra, so omitting either
fails with `required flag(s) "backend", "key-id" not set` before anything is
read from disk.

## Flags for `--format openpgp` only

| Flag | Default | Description |
|------|---------|-------------|
| `--public-key` | *(required for this format)* | Path to the armored OpenPGP public key (`.asc`) that identifies the signature. The backend's public half must match it, or `sign` refuses to proceed. |
| `--append` | `false` | Merge the new signature into an existing armored signature at `--output` instead of overwriting it, producing one armored block with multiple signature packets. A no-op when `--output` does not exist yet. |

`--public-key` is checked in the command body rather than marked required by
cobra, because the minisign path has to reject it. Omitting it fails with
`--public-key is required for --format openpgp` — and that check runs before the
backend is resolved, so a typo in `--backend` will not be the error you see
first.

## Flags for `--format minisign` only

| Flag | Default | Description |
|------|---------|-------------|
| `--project` | *(none)* | Project this artefact belongs to. Recorded in the signature's **signed** trusted comment, so tampering with it breaks verification. Omitted, minisign's own default comment is emitted. |

## Backend-contributed flags

A backend that needs its own flags registers them onto the same flag set, so
they appear in `--help` alongside the generic ones. With the AWS KMS backend
compiled in — as it is in sigillum — that adds:

| Flag | Default | Description |
|------|---------|-------------|
| `--kms-region` | `eu-west-2` | AWS region the KMS key lives in. |

The default matches the `terraform-aws-signing-kms` module's default region.
Consumers elsewhere override it.

## Which flag combinations are refused

Wrong combinations are hard errors, not ignored flags. Accepting one silently
would leave you believing something was in play that was not.

| What you passed | What happens |
|---|---|
| `--format minisign --public-key …` | `--public-key is not accepted for --format minisign: a minisign signature carries its own key identifier, so the identity comes from --backend / --key-id` |
| `--format minisign --append` | `--append is not supported for --format minisign; it is an OpenPGP dual-sign primitive` |
| `--format openpgp --project …` | `--project is only meaningful for --format minisign; an OpenPGP signature has no trusted comment to record it in` |
| `--format openpgp` with an Ed25519 key | `computing signature: DetachSign: ed25519.PublicKey: unsupported key type: only RSA is supported` |
| `--format minisign` with an RSA key | `minisign requires an Ed25519 signing key, but --key-id resolved to *rsa.PublicKey; RSA keys sign the OpenPGP manifest path (--format openpgp) instead` |
| `--output` naming the input file | `refusing to write signature to "art.txt" which equals the input path "art.txt"` |

The clobber guard is not fooled by a different spelling of the same path. It
compares cleaned paths first, then falls back to `os.SameFile` when both exist,
so a symlink, a hard link, or an absolute-versus-relative form is caught too.

## How the signature timestamp is chosen

`--created` takes an RFC3339 instant and truncates it to whole seconds — an
OpenPGP v4 signature packet stores creation time as a `uint32` of seconds, so a
sub-second value could not survive. An unparseable value fails with
`parsing --created "nope" as RFC3339`.

The two formats resolve an *unset* `--created` differently:

| Format | `--created` set | `--created` unset |
|---|---|---|
| `openpgp` | that instant | now, truncated to whole seconds |
| `minisign` | that instant | `SOURCE_DATE_EPOCH` if set (Unix seconds), else now |

`SOURCE_DATE_EPOCH` is the reproducible-builds convention, and it is honoured on
the minisign path only. A pipeline that already exports it gets byte-identical
artefact signatures without threading another flag through. A non-numeric value
fails with `parsing SOURCE_DATE_EPOCH "nope" as Unix seconds`.

Same content, same key and same timestamp produces a byte-identical signature in
both formats.

## What `--append` is for

During a key-rotation overlap window, one file can carry signatures from two
keys:

```bash
sigillum sign --backend aws-kms --key-id alias/release-signing-v1 \
    --public-key v1.asc --output checksums.txt.sig checksums.txt

sigillum sign --backend aws-kms --key-id alias/release-signing-v2 \
    --public-key v2.asc --output checksums.txt.sig --append checksums.txt
```

The result is one armored block holding both signature packets, in the order
they were written. Verifiers skip packets from issuers they do not know, so the
same file satisfies consumers trusting either key.

`--append` reads the existing file, merges packets and rewrites it. When
`--output` does not exist the fresh signature is written unchanged, so passing
`--append` on the first pass is safe. When the existing file is armored but is
not a signature block it fails with
`armored input 0 is "PGP PUBLIC KEY BLOCK", not "PGP SIGNATURE"`.

There is no minisign equivalent. Rotate minisign keys with `keys publish
--generation` instead — see the [`keys` reference](keys.md).

## What gets written, and with what permissions

Signature files are written mode `0644`. A signature is public by design — it is
distributed alongside the thing it signs — so world-readable is correct rather
than an oversight.

## What the log line tells you

A successful OpenPGP run emits one INFO line on stderr:

```
INFO Signed file backend=local key_id=./release.pem public_key=./release.asc input=checksums.txt output=checksums.txt.sig sig_creation_time=2026-08-02T20:56:22Z fingerprint=9458EAFEE4BB318B70A551461DE7F151A3EA2FBF
```

The fingerprint is parsed back out of the `--public-key` file, so it is a cheap
check that you signed with the identity you meant to. It is omitted if that file
does not parse as exactly one OpenPGP entity; the signature is still written.

The minisign run reports different fields, including the minisign key identifier
and the trusted comment's timestamp:

```
INFO Signed artefact format=minisign backend=local key_id=./artefact.pem minisign_key_id=846E063241A4289F input=tool.tar.gz output=tool.tar.gz.minisig project=mytool trusted_comment_time=2026-08-02T20:56:30Z
```

The trusted comment written into the `.minisig` looks like this, tab-separated,
and is covered by the signature:

```
trusted comment: timestamp:1785704190	file:tool.tar.gz	hashed	project:mytool	key:846E063241A4289F
```

## Related

- [Sign a release artefact](../../how-to/sign-a-release-artefact.md) — the
  OpenPGP procedure, including AWS KMS and CI
- [Sign an artefact for Rust consumers](../../how-to/sign-an-artefact-for-rust-consumers.md)
  — the minisign procedure
- [`keys` command reference](keys.md)
- [What sigillum does not do](../../explanation/what-sigillum-does-not-do.md)
