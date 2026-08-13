---
title: CLI reference
description: Every sigillum command, the global flags, the compiled-in signing backends, which key algorithm each signature format requires, and the exit codes.
tags: [reference, cli, commands, backends, flags]
---

# CLI reference

Command reference for sigillum. Run `sigillum <command> --help` for the
authoritative, always-current flag set — the pages here mirror it and add the
defaults, failure modes and flag combinations that `--help` has no room for.

## The commands sigillum exists for

| Command | Purpose |
|---------|---------|
| [`sign`](sign.md) | Produce a detached signature over one file — armored OpenPGP for checksum manifests, or minisign for release artefacts. |
| [`keys`](keys.md) | Manage signing keys: `generate`, `mint`, `wkd`, `minisign`, `publish`. |
| [`decrypt`](decrypt.md) | Read an OpenPGP message addressed to a KMS-backed certificate. |
| [`certificate`](certificate.md) | Assemble a publishable certificate whose keys both live in a key service. |

`sign` and `keys` are attached from
[`gitlab.com/phpboyscout/go/signing-cli`](https://signing-cli.go.phpboyscout.uk/)
as **top-level** commands rather than reimplemented, which is the point of
sigillum existing separately from gtb.

`decrypt` and `certificate` are sigillum's own, in `pkg/cmd`. The split matters
when something goes wrong: a signing defect belongs upstream in signing-cli, a
decryption defect belongs in this repository.

## Which framework built-ins are present

sigillum is generated from go-tool-base, so it also carries part of the
framework's command set. What is actually there, as `sigillum --help` reports:

| Command | What it does |
|---------|--------------|
| `changelog` | Show version history. |
| `completion` | Generate a shell completion script. |
| `config` | View, set and validate configuration — see the [configuration reference](../config/index.md). |
| `docs` | Browse the embedded documentation. |
| `doctor` | Check environment and configuration health. |
| `update` | Update to the latest available release, verifying its signature against the embedded key. |
| `version` | Print version, commit and build date. |

**`init` and `mcp` are disabled** in this tool and do not appear. They are
switched off in the root command's feature set, so no flag or configuration key
brings them back. Some framework help text still mentions `init` — `sigillum
config --help` suggests running `init <subsystem>` for guided reconfiguration —
and that suggestion does not apply here.

## Global flags

Registered on the root command; available to every subcommand.

| Flag | Default | Description |
|------|---------|-------------|
| `--ci` | `false` | Declare that the tool is running in a CI environment. |
| `--config` | `/etc/sigillum/config.yaml`, `~/.sigillum/config.yaml` | Config file(s) to use. Repeatable; only files that exist become layers. |
| `--debug` | `false` | Force debug-level log output regardless of `log.level`. |
| `--output` | `text` | Output format for commands that render structured results: `text` or `json`. |
| `-h`, `--help` | — | Help for the command. |

### Why `--output` means two different things

The global `--output` selects an output *format*. But `sign`, every `keys`
subcommand, `decrypt` and `certificate` all define their own local `--output`,
which is a *file path*, and a local flag shadows the global one — those commands
do not even list the global `--output` in their help.

`decrypt` is the one where this bites hardest. `sigillum decrypt --output json
…` does not produce JSON diagnostics; it writes the decrypted vulnerability
report to a file named `json` in the working directory.

So `sigillum --output json config list` prints JSON, while
`sigillum sign --output json …` writes a signature to a file named `json`. There
is no way to get JSON output from the signing commands; they report through
structured log lines on stderr instead.

## Backends

`--backend` selects a key service **compiled into the binary**, activated by
blank imports in the `main` package. There are two independent registries and
the same flag name selects from whichever the command needs:

| Commands | Registry | Backends shipped | `--backend` |
|---|---|---|---|
| `sign`, `keys mint`, `keys minisign` | signing | `aws-kms`, `local` | required |
| `decrypt`, `certificate` | encryption | `aws-kms`, `local` | required |

They are separate registries because the operations are: signing needs a key
that signs, and `decrypt` and `certificate` need one that performs ECDH key
agreement. A name present in one is not automatically present in the other —
they happen to ship the same two today, but that is a fact about this build
rather than a rule.

`--backend` is **required** for every one of these commands. It defaults only
when exactly one backend is compiled in, which is no longer the case for either
registry — and a default whose meaning changes as backends are linked into the
binary is a worse thing to rely on than an explicit flag.

### Signing backends

| Backend | `--key-id` is | Key algorithms accepted | Extra flags |
|---------|---------------|-------------------------|-------------|
| `aws-kms` | a KMS key ID, ARN or alias | RSA `SIGN_VERIFY`, `ECC_NIST_EDWARDS25519` | `--kms-region` (default `eu-west-2`) |
| `local` | a PEM file path | RSA (PKCS#1 or PKCS#8), Ed25519 (PKCS#8) | none |

An unrecognised name fails immediately and names the alternatives:

```
"vault" (available: aws-kms, local): unknown signing backend
```

`aws-kms` resolves credentials from the AWS SDK default chain — environment
variables, `~/.aws/credentials`, IAM Roles Anywhere, OIDC web identity. sigillum
adds nothing of its own: no `--profile` and no assume-role step. Set
`AWS_PROFILE`, or export session credentials, before invoking it.

`local` reads unencrypted PEMs only. Encrypted PKCS#8 is refused, and so is
ECDSA — see
[What sigillum does not do](../../explanation/what-sigillum-does-not-do.md).

A regulated build can drop the AWS KMS blank import and rebuild; linker
dead-code elimination then keeps that SDK out of the binary entirely.

## Which key algorithm do I need?

The signature format decides the key algorithm, and the two do not overlap:

| `sign --format` | Key algorithm | Output file | Identity comes from |
|---|---|---|---|
| `openpgp` (default) | **RSA only** | `<input>.sig` | `--public-key` (an armored `.asc`) |
| `minisign` | **Ed25519 only** | `<input>.minisig` | the signer itself |

`keys mint` builds an OpenPGP entity, so it is RSA-only for the same reason.
`keys minisign` derives a minisign public key, so it is Ed25519-only. A project
publishing both signature kinds runs two keys.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Any command error — bad flags, a missing file, an unknown backend, a signing failure. There are no per-failure codes; the message on stderr is what distinguishes them. |
| `130` | Terminated by SIGINT (128 + 2). |
| `143` | Terminated by SIGTERM (128 + 15). |

A signal cancels the command's context so it can shut down gracefully; a second
signal force-exits immediately.

## Which stream does output go to?

Diagnostics — every error, and the INFO lines that report fingerprints and
output paths — go to **stderr**. Only command output proper goes to stdout, such
as the bare public key from `keys minisign`. That split is what makes
`sigillum keys minisign … > key.b64` produce a usable file rather than an empty
one.
