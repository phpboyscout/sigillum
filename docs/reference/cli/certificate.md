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
| `--follow-symlinks` | no | off | Write *through* a symbolic link named by `--output` rather than refusing it |

`--help` is authoritative for the flags this build actually carries.

### `--follow-symlinks`

Off by default. Writing the output replaces the destination by renaming over it,
so a symbolic link named as `--output` would be removed and a regular file left
in its place. For a published certificate that is usually the *opposite* of what
was intended: a link from a web root to a canonical certificate elsewhere is a
publishing arrangement, and silently flattening it means the next publish writes
to the web root while everything else still reads the original.

Turning it on writes through the link and leaves the link in place. When the
resolved destination differs from what you typed, the command says so at `Info`
— silence is the failure mode of following, and that part is cheap to remove.

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
| `no key service backends are compiled into this binary` | A build with no backend linked in; nothing can be published |
| `backend cannot expose the encryption key's public half` | The chosen key service cannot supply the subkey point |
| `unsupported curve` | The encryption key is not on P-256, P-384 or P-521 |
| `point is N octets but this curve's are M` | The backend returned a point whose width does not match the curve it named |
| `hash algorithm id N as the KDF hash` | The key service asked for a KDF hash this build does not implement |
| `symmetric algorithm id N as the KEK algorithm` | The key service asked for a key-wrap cipher this build does not implement |
| `certification key is ...` | The certification key is not RSA |
| `cannot predate the key it covers` | `--created` is in the future relative to the clock signing the certificate. See below |
| `wiring the certification key` | The key service refused or was unreachable |
| `destination is not a regular file` | `--output` names a directory, a device or a socket |
| `symbolic link cannot be resolved` | `--follow-symlinks` was given and the link is broken, or the chain is too long |

### The parameters are checked before anything is published

The curve, the point width, the KDF hash and the KEK algorithm are all validated
before the subkey packet is built. Each of them is hashed into the fingerprint
and each is read back by every correspondent who encrypts to the result, so a
value this build cannot honour is not a local inconvenience — it is a published
certificate that fails at the far end, after somebody has already encrypted a
report to it.

The same checks exist on the decrypting side. Running them here as well is the
point: on that side they fire when it is far too late to change the answer.

### A signature that would predate its keys

`--created` stamps the key packets and is hashed into the fingerprint, so it is
yours to choose. The signatures over those packets are stamped from the clock at
the moment you run the command.

Choosing a `--created` in the future therefore produces a certificate whose
signatures are older than the keys they cover. GnuPG and other implementations
treat that as invalid and silently drop the encryption subkey on import — so the
certificate imports, looks fine, and nobody can encrypt to it. It is refused
here instead, because a certificate that fails at every correspondent is worse
than one that fails at you.

The remedy is to pass a `--created` that is not in the future.

### The output mode is exact

`--output` creates the file at `0644` regardless of the process umask. A
published certificate that a web server cannot read is a certificate nobody can
encrypt to, so the mode is set explicitly rather than left to whatever `umask`
happens to be in force.

On a filesystem that cannot change file modes — vfat or exfat, which is what a
USB stick is usually formatted as — the file is written at whatever the
filesystem allows and the difference is reported. It is never *broader* than
requested.

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
