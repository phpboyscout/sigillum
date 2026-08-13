---
title: Receive an encrypted report
description: Publish an OpenPGP certificate backed by KMS keys, advertise it in security.txt, and read the reports researchers encrypt to it.
tags: [how-to, encryption, security-txt, kms, vulnerability-reports]
---

# Receive an encrypted report

Give security researchers a way to send you a vulnerability report that nobody
else can read — including your ticket system, and including anyone with
repository access who is not on the rota.

The private key lives in AWS KMS and is never readable by this tool.

## What you need

Two KMS keys, because an agreement key cannot sign its own binding signature:

| Purpose | `KeyUsage` | `KeySpec` |
|---|---|---|
| Encryption subkey | `KEY_AGREEMENT` | `ECC_NIST_P256` |
| Certification primary | `SIGN_VERIFY` | `RSA_4096` |

The full provisioning steps, including the reader/certifier role split, are in
the provider's [Provision the keys][prov] guide.

[prov]: https://encryption.go.phpboyscout.uk/how-to/provision-kms-keys/

## 1. Assemble the certificate

```bash
sigillum certificate \
    --user-id 'Security <security@example.com>' \
    --certify-key alias/security-contact-v1-certify \
    --encrypt-key alias/security-contact-v1-encrypt \
    --created 2026-08-10T00:00:00Z \
    --armor --output security-contact.asc
```

Two `kms:Sign` calls happen inside that, and no private key material exists in
the process at any point.

**Record the `--created` value.** It is hashed into both fingerprints, and the
key derivation binds the subkey's — so the same keys with a different creation
time are a *different* certificate, and nothing encrypted to the old one will
open. It has no default for exactly that reason.

## 2. Verify before publishing

Never publish a certificate checked only by the tool that produced it:

```bash
export GNUPGHOME="$(mktemp -d)" && chmod 700 "$GNUPGHOME"
gpg --import security-contact.asc
gpg --check-sigs --with-colons | grep '^sig'
gpg --list-packets security-contact.asc | grep -E 'pref-sym|features'
```

Expect two `sig:!` lines, `pref-sym-algos: 9 8 7` and `features: 01`. That last
pair is what makes a sender choose AES-256 and integrity-protected encryption;
without them gpg quietly falls back to AES-128.

Clean up with `gpgconf --kill all && rm -rf "$GNUPGHOME"`.

## 3. Publish it

Serve the file over HTTPS and point `security.txt` at it:

```
Contact: mailto:security@example.com
Encryption: https://example.com/.well-known/security-contact.asc
Expires: 2027-01-01T00:00:00Z
```

`Encryption` must be a URI — [RFC 9116][rfc] forbids inlining the key itself.

[rfc]: https://www.rfc-editor.org/rfc/rfc9116.html

## 4. Read what arrives

A report usually arrives as an armoured blob in a confidential ticket. Save it
and open it:

```bash
sigillum decrypt \
    --certificate security-contact.asc \
    --key alias/security-contact-v1-encrypt \
    --output report.txt \
    report.asc
```

You need the **reader** role for this, and only that: it can derive a shared
secret and cannot sign. Assume it the way your estate expects — an SSO session
with MFA, not a CI credential.

`--output` writes mode `0600`. Without it the plaintext goes to stdout, which is
fine for reading and less fine for shell history and scrollback.

## What this protects, and what it does not

The report is unreadable in transit, unreadable at rest in the ticket system,
and unreadable by anyone without the reader role. That is a real boundary, and
it is enforced by IAM rather than by convention.

**It ends the moment someone pastes the plaintext into the ticket.** No amount
of key management fixes that, and it is worth saying out loud in your rota's
runbook: work the report in a confidential channel, and reference it rather than
quoting it.

## When it fails

| Message | Means |
|---|---|
| `addressed to ...` | Encrypted to a different certificate. No key-service call was made, unless the message also carried hidden recipients |
| `stopped before trying every recipient` | The message carried session-key packets on more than 16 distinct ephemeral points, so some were never tried. Not only hidden recipients: the ceiling applies to every packet however it is addressed, and anyone can compose packets naming your key id because it is the tail of your published fingerprint |
| `certificate has no ECDH encryption subkey` | A signing-only certificate |
| `malformed message` | Truncated paste, or not OpenPGP at all |
| `AccessDenied` | The role is missing a grant — check the reader policy |
| `integrity check failed` | The message was altered, or the wrong certificate was supplied |
