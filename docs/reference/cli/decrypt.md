---
title: decrypt command
description: Reference for `sigillum decrypt` — every flag, what the certificate is for, and which failures cost a key-service call.
date: 2026-08-11
tags: [reference, commands, decrypt, encryption, openpgp]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `decrypt` command

`sigillum decrypt` reads an OpenPGP message addressed to a certificate whose
encryption subkey is held by a key service, and writes the plaintext out.

Exactly one operation needs the private key — the ECDH agreement, performed
remotely. The key derivation, the AES key unwrap and opening the
encrypted-data packet all happen locally, on public data.

## Usage

```bash
sigillum decrypt --certificate <file> --key <id> [message-file] [flags]
```

The message is read from the positional argument, or from stdin when it is
omitted or given as `-`. Armoured and binary messages are both accepted; you do
not have to know which you have.

!!! warning "Only one of them can come from stdin"

    `--certificate -` and a message from stdin are mutually exclusive. The
    certificate is read first and reading it consumes stdin entirely, so there
    is nothing left for the message. The command refuses the combination rather
    than failing later with an error about the report.

    ```bash
    # Refused: both want stdin
    cat security-contact.asc | sigillum decrypt --certificate - --key alias/x

    # Fine: the certificate is a file, the message comes from stdin
    cat report.asc | sigillum decrypt --certificate security-contact.asc --key alias/x

    # Fine: the certificate comes from stdin, the message is a file
    cat security-contact.asc | sigillum decrypt --certificate - --key alias/x report.asc
    ```

## Flags

| Flag | Required | Default | Purpose |
|---|---|---|---|
| `--certificate` | **yes** | — | The recipient certificate, or `-` for stdin |
| `--key` | **yes** | — | Key service identifier for the encryption subkey |
| `--backend` | when several are compiled in | the only one | Which key service to use |
| `--output` | no | stdout | Write plaintext here, created mode `0600` |

`--help` is authoritative for the flags this build actually carries.

## Why the certificate is a flag and the parameters are not

The key derivation binds the encryption subkey's fingerprint. Parameters that
did not come from the certificate the sender used cannot recover anything, so
they are read from the certificate rather than accepted individually — a flag
for the curve or the hash would only be a way to get it wrong.

## What costs a key-service call, and what does not

A message addressed to a different certificate is rejected **before** the key
service is contacted, and the backend is wired lazily so that no API call and
no credentials are needed to reach that conclusion. Several certificates in
play is a normal situation; rejecting a message that is not yours should be
free.

Malformed input and a certificate with no encryption subkey are likewise
decided locally.

## Errors

| Message contains | Means | Reached the key service? |
|---|---|---|
| `required flag not set` | `--certificate` or `--key` missing | no |
| `cannot both come from stdin` | `--certificate -` with the message also on stdin | no |
| `no key service "..."` | `--backend` names something not compiled in | no |
| `certificate has no ECDH encryption subkey` | Signing-only certificate | no |
| `key is revoked` | The certificate's holder has withdrawn its encryption subkey; fetch a current certificate | no |
| `message is not addressed to this certificate` | Encrypted to somebody else | **no** |
| `malformed message` | Not readable as OpenPGP | no |
| `deriving the shared secret` | The key service refused or was unreachable | yes |
| `checksum` | Session key unwrapped wrongly — usually the wrong certificate | yes |

## Example

```bash
sigillum decrypt \
  --certificate security-contact.asc \
  --key alias/security-contact-v1-encrypt \
  --output report.txt \
  report.asc
```

## See also

- [`certificate`](certificate.md) — publish the certificate this reads against.
- [Receiving encrypted reports](../../how-to/index.md) — the operational
  procedure around this command.
