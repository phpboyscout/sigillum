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
| `--follow-symlinks` | no | off | Write *through* a symbolic link named by `--output` rather than refusing it |

`--help` is authoritative for the flags this build actually carries.

### `--follow-symlinks`

Off by default, and the default is the safe half. Writing the output replaces
the destination by renaming over it, so a symbolic link named as `--output`
would be removed and a regular file left in its place — which for a decrypted
vulnerability report is a confidentiality question, not a tidiness one. An
operator who pointed through a link into an encrypted volume would find the
plaintext on local disk instead.

Turning it on writes through the link and leaves the link in place. When the
resolved destination differs from what you typed, the command says so at
`Info` — silence is the failure mode of following, and that part is cheap to
remove.

## Why the certificate is a flag and the parameters are not

The key derivation binds the encryption subkey's fingerprint. Parameters that
did not come from the certificate the sender used cannot recover anything, so
they are read from the certificate rather than accepted individually — a flag
for the curve or the hash would only be a way to get it wrong.

## What costs a key-service call, and what does not

A message whose recipients are all **named**, and none of them yours, is
rejected before the key service is contacted. The backend is wired lazily, so
no API call and no credentials are needed to reach that conclusion. Several
certificates in play is a normal situation, and rejecting a message that is
not yours should be free.

Malformed input, a certificate with no encryption subkey, and more than one
message named on the command line are likewise decided locally.

**A hidden recipient is not free**, and this is the one case where the rule
above does not hold. `gpg --hidden-recipient` — which disclosure advice
reasonably recommends, so that an intercepted message does not reveal who it
was for — writes an all-zero key id. A packet naming nobody can only be ruled
out by attempting it, and each attempt is one billed key-service call.

Two bounds keep that from being unbounded:

- Attempts are counted per **distinct ephemeral point**, not per packet. Any
  number of packets sharing a point cost one call between them, because the
  derivation depends on the point alone.
- At most **16** distinct points are derived for one message.

Reaching that ceiling stops the run with `stopped before trying every
recipient`, which is deliberately *not* "addressed to somebody else": packets
left untried might have been yours, and saying otherwise would send you looking
for a certificate that may not exist. The message names how many went untried.

## Errors

| Message contains | Means | Reached the key service? |
|---|---|---|
| `required flag not set` | `--certificate` or `--key` missing | no |
| `only one message can be decrypted at a time` | More than one message named; there is a single `--output` | no |
| `cannot both come from stdin` | `--certificate -` with the message also on stdin | no |
| `--output names a file this command is reading` | `--output` points at the certificate or the message — see below | no |
| `no key service backends are compiled into this binary` | A build with no backend linked in; nothing can be decrypted | no |
| `no key service "..."` | `--backend` names something not compiled in | no |
| `certificate has no ECDH encryption subkey` | Signing-only certificate, or one whose subkey is RSA | no |
| `certificate did not parse to its end` | Reported as a warning, not a failure — see below | no |
| `its holder withdrew this certificate` | A revocation over the **whole certificate**: every key in it is retired, not just the encryption subkey | no |
| `its holder withdrew this encryption subkey` | Only the encryption subkey is withdrawn; the certificate itself still stands | no |
| `key has expired` | The holder time-boxed the subkey and that date has passed | no |
| `message is not addressed to this certificate` | Every recipient was named, and none was you | no, unless the message also carried hidden recipients |
| `malformed message` | Not readable as OpenPGP | no |
| `message is larger than this will decrypt` (before decryption) | The message itself exceeds the 128 MiB bound | no |
| `message is larger than this will decrypt` (after decryption) | What it decompresses to exceeds the 64 MiB plaintext bound — a compression bomb | **yes** |
| `message has no integrity protection` | The legacy unprotected packet, which is refused rather than read | no |
| `stopped before trying every recipient` | The 16-derivation ceiling was reached with candidates left untried | yes |
| `deriving the shared secret` | The key service refused or was unreachable | yes |
| `key unwrap integrity check failed` | The wrong certificate or the wrong `--key` — the session key did not unwrap | yes |
| `session key checksum mismatch` | The unwrap succeeded but the payload underneath is wrong; a damaged packet rather than a wrong key | yes |
| `message integrity check failed` | The plaintext was altered in transit. Nothing is written out | yes |
| `destination is not a regular file` | `--output` names a directory, a device or a socket | no |
| `symbolic link cannot be resolved` | `--follow-symlinks` was given and the link is broken, or the chain is too long | no |
| `no unused name to stage content under` | The output directory is too full of leftovers to stage a temporary beside the target | no |

### `--output` will not name an input

`--output` is refused when it points at the certificate or at the message being
read. Both are plausible slips — `--certificate key.asc --output key.asc`, or an
`--output` that names the message so the report "replaces itself" — and both
used to succeed, because the destination is staged and only renamed into place
at the end. The read finished before the rename, so the run reported success and
the input was gone: the certificate replaced by a plaintext report, or the
encrypted message replaced by its own plaintext with no copy of the ciphertext
left.

The comparison is on cleaned paths, so `security.asc` and `./security.asc` are
recognised as the same file. It is deliberately not resolved through the
filesystem: a symbolic or hard link can make two different names the same file,
and catching those needs a stat of a destination that may not exist yet. This
catches the slip operators actually make, not every route to the same inode.

### Two different integrity checks

Three of the rows above concern integrity and they mean quite different things.
The distinction matters because the first is almost always an operator mistake
and the third is almost always an attacker.

- **`key unwrap integrity check failed`** is the AES key-wrap check on the
  session key. It fails when the key that unwrapped it is not the key that
  wrapped it — so in practice, the wrong `--certificate`, the wrong `--key`, or
  a rotation that moved the encryption subkey. It is not evidence of tampering.
- **`session key checksum mismatch`** means the unwrap succeeded, so the key was
  right, and the session key underneath is still wrong. That is a damaged
  packet.
- **`message integrity check failed`** is OpenPGP's modification detection code
  over the plaintext, verified after the whole message has been read. This is
  the one that means the report was altered on its way here, and the plaintext
  is deliberately not written out.

### Warnings

These are reported at `Warn` and do not stop the run, because they are findings
the tool has no standing to decide about:

| Warning contains | Means | What to do |
|---|---|---|
| `certificate carries a revocation this cannot evaluate` | The certificate holds a revocation-shaped signature of a version or algorithm this build cannot verify | Check out of band whether the key was withdrawn before relying on it |
| `certificate did not parse to its end` | The certificate stopped parsing before its input ran out; what was read is intact and usable | Re-fetch it — a later subkey may supersede the one used |
| `a later encryption subkey was refused, so this is not the newest one` | A newer encryption subkey exists but could not be used — its binding did not verify, it was buried under too many signatures, or its own parameters were rejected. The subkey actually used is an earlier, valid one | Re-fetch the certificate. If the newer subkey is genuine, the holder has rotated and this run used the key they have stopped using |

None of them refuses the certificate on purpose. A revocation-shaped packet costs
nothing to append to a published certificate and nothing verifies it before it
is counted, so honouring one that cannot be checked would let any stranger
retire a security contact's encryption key.

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
