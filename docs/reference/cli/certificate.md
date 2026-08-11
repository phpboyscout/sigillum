---
title: certificate command
description: Reference for `sigillum certificate` — every flag, and why the creation time must never change.
date: 2026-08-11
tags: [reference, commands, certificate, encryption, openpgp]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `certificate` command

`sigillum certificate` assembles a publishable OpenPGP certificate whose
certification primary and encryption subkey are both held by a key service.

Both signatures — the identity self-certification and the subkey binding — are
made remotely. No private key material exists in the process at any point.

## Usage

```bash
sigillum certificate --user-id <id> --certify-key <id> --encrypt-key <id> \
  --created <rfc3339> [flags]
```

## Flags

| Flag | Required | Default | Purpose |
|---|---|---|---|
| `--user-id` | **yes** | — | Identity to certify, as `Name <email>` |
| `--certify-key` | **yes** | — | Key service id for the certification primary |
| `--encrypt-key` | **yes** | — | Key service id for the encryption subkey |
| `--created` | **yes** | — | Creation time, RFC 3339. See below |
| `--backend` | when several are compiled in | the only one | Which key service to use |
| `--armor` | no | `false` | Emit ASCII armour instead of binary |
| `--output` | no | stdout | Write here, created mode `0644` |

## `--created` is required on purpose

The creation time is hashed into both fingerprints, and the key derivation
binds the subkey's. **The same key material with a different creation time is a
different certificate**, and nothing encrypted to the old one will open.

Defaulting it to the current time would mean every run produced a different
certificate. Record the value alongside the key aliases, and use the same one
every time you regenerate.

## Reproducibility

Assembly is not byte-reproducible: each signature carries a random salt, which
is a deliberate security measure. The *fingerprints* are stable, so a
regenerated certificate accepts exactly the same messages as the one it
replaces — which is the property that actually matters.

## Two keys, not one

An agreement key cannot sign its own binding signature, so a certificate needs
a separate signing-capable key. The primary must be RSA: an OpenPGP RSA
signature is PKCS#1 v1.5, which is what a KMS will produce.

## Errors

| Message contains | Means |
|---|---|
| `required flag not set` | A required flag is missing; `--created` explains why it has no default |
| `backend cannot expose the encryption key's public half` | The chosen key service cannot supply the subkey point |
| `unsupported curve` | The encryption key is not on P-256, P-384 or P-521 |
| `certification key is ...` | The certification key is not RSA |
| `wiring the certification key` | The key service refused or was unreachable |

## Verify before publishing

Do not publish a certificate that has only been checked by the code that
produced it. Import it into a throwaway GnuPG keyring, confirm both signatures
with `--check-sigs`, and confirm the advertised algorithm preferences:

```bash
gpg --list-packets certificate.asc | grep -E 'pref-sym|features'
```

Expect `pref-sym-algos: 9 8 7` and `features: 01`.

## Example

```bash
sigillum certificate \
  --user-id 'Security <security@phpboyscout.uk>' \
  --certify-key alias/security-contact-v1-certify \
  --encrypt-key alias/security-contact-v1-encrypt \
  --created 2026-08-10T00:00:00Z \
  --armor --output security-contact.asc
```

## See also

- [`decrypt`](decrypt.md) — read messages addressed to this certificate.
