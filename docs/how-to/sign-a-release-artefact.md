---
title: Sign a release artefact
description: Produce an ASCII-armored OpenPGP detached signature over a release file with sigillum — using an AWS KMS key (production) or a local PEM key (development) — then verify it with gpg.
date: 2026-07-28
tags: [how-to, signing, kms, openpgp, release]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Sign a release artefact

`sigillum sign <input-file>` produces an ASCII-armored OpenPGP **detached**
signature over a single file using a configured signing backend. The private key
never leaves the backend — signing is one round-trip to the HSM/KMS (or a read
of the local PEM) via the `crypto.Signer` interface.

sigillum ships two backends: **`aws-kms`** (production, the key stays in KMS) and
**`local`** (development / air-gapped, an on-disk PEM key). This guide covers
both, plus verification.

This guide covers the **OpenPGP** lane only, which is RSA-only. For the minisign
lane that cargo-binstall and rtb-update verify, see
[Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md).

## Prerequisites

- sigillum installed (see
  [Sign and verify your first release](../tutorials/sign-and-verify-your-first-release.md)).
- The **public-key file** (`release.asc`) that corresponds to the signing key,
  already produced by [`keys mint`](generate-or-mint-a-signing-key.md) or
  `keys generate`. `sigillum sign` reads the signing identity (creation time,
  UID, fingerprint) from this file and refuses to proceed if the backend's
  public half does not match it.
- For the `aws-kms` backend: AWS credentials in the standard SDK chain. In a
  local terminal that means `aws configure export-credentials --format env`; in
  CI it means an OIDC assume-role step (see below).

## Sign with AWS KMS (production)

```bash
sigillum sign \
    --backend aws-kms \
    --kms-region eu-west-2 \
    --key-id alias/release-signing-v1 \
    --public-key release.asc \
    --output checksums.txt.sig \
    checksums.txt
```

- `--key-id` is the KMS key ID, ARN, or **alias** (aliases survive rotation —
  prefer them).
- `--kms-region` is contributed by the AWS KMS backend and is available on
  `sign` (and `mint`) because sigillum compiles that backend in.
- `--output` defaults to `<input>.sig` if omitted. `sign` refuses to write the
  signature over its own input — the guard compares cleaned paths and falls back
  to `os.SameFile`, so a different spelling of the same file (a symlink, an
  absolute vs relative form) is still refused.

The INFO log line includes the public-key fingerprint so you can confirm it
matches your trust anchor before the `.sig` ships.

### Reproducible signatures

Pass `--created <rfc3339>` to pin the signature's creation timestamp. Two runs
over the same content with the same key and the same `--created` produce
**byte-identical** `.sig` files — useful for a reproduce-from-scratch (SLSA)
chain:

```bash
sigillum sign \
    --backend aws-kms \
    --kms-region eu-west-2 \
    --key-id alias/release-signing-v1 \
    --public-key release.asc \
    --created 2026-07-28T15:11:32Z \
    checksums.txt
```

## Sign with the `local` backend (development)

For development, tutorials, or air-gapped builds, sign with an on-disk PEM key:

```bash
sigillum keys generate --algorithm rsa --rsa-bits 4096 \
    --name "Test Signer" --email test@example.org \
    --output release.asc --private-output release.pem

sigillum sign \
    --backend local \
    --key-id ./release.pem \
    --public-key ./release.asc \
    checksums.txt
```

The `local` backend accepts unencrypted PKCS#1 and PKCS#8 PEM private keys
holding either an **RSA** or an **Ed25519** key — but only the RSA ones are
usable here, because OpenPGP signing is RSA-only. An Ed25519 PEM fails with
`computing signature: DetachSign: ed25519.PublicKey: unsupported key type: only
RSA is supported`; that key belongs to the
[minisign lane](sign-an-artefact-for-rust-consumers.md).

The backend does not decrypt encrypted PEMs, and rejects ECDSA outright. Protect
the key file with filesystem-level encryption (LUKS, `age`) or use the `aws-kms`
backend so the key never leaves the HSM.

## Dual-sign during key rotation (`--append`)

During a key-rotation overlap window you can carry two signatures in one armored
file. Sign with the old key, then `--append` the new key's signature into the
**same** `--output` file:

```bash
sigillum sign --backend aws-kms --key-id alias/release-signing-v1 \
    --public-key v1.asc --output checksums.txt.sig checksums.txt

sigillum sign --backend aws-kms --key-id alias/release-signing-v2 \
    --public-key v2.asc --output checksums.txt.sig --append checksums.txt
```

The result is one armored block with multiple signature packets. Verifiers skip
signature packets from issuers they do not know, so a single file serves
consumers that trust either key. `--append` is a no-op when `--output` does not
yet exist.

## Verify

`sigillum sign` produces what `gpg --verify` consumes. Import the published
public key into a clean keyring and verify:

```bash
TMPGNUPG=$(mktemp -d)
gpg --homedir "$TMPGNUPG" --import release.asc
gpg --homedir "$TMPGNUPG" --verify checksums.txt.sig checksums.txt
# Expect: "Good signature from <UID>" with the published fingerprint.
rm -rf "$TMPGNUPG"
```

The same output also verifies under any modern OpenPGP implementation and under
the in-tool verifier in `gitlab.com/phpboyscout/go/signing/verify`, which
downstream tools use during self-update.

## CI integration: GitLab + AWS OIDC

sigillum knows nothing about OIDC — it reads whatever the AWS SDK default
credential chain provides. In CI, an assume-role step populates that chain
before `sigillum sign` runs:

```yaml
sign:
  id_tokens:
    AWS_WEB_IDENTITY_TOKEN:
      aud: sts.amazonaws.com
  variables:
    AWS_ROLE_ARN: arn:aws:iam::<account>:role/release-signing-v1-signer
  before_script:
    - |
      creds=$(aws sts assume-role-with-web-identity \
        --role-arn "$AWS_ROLE_ARN" \
        --role-session-name "release-${CI_COMMIT_TAG}" \
        --web-identity-token "$AWS_WEB_IDENTITY_TOKEN" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text)
      export AWS_ACCESS_KEY_ID=$(echo "$creds" | awk '{print $1}')
      export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | awk '{print $2}')
      export AWS_SESSION_TOKEN=$(echo "$creds" | awk '{print $3}')
  script:
    - sigillum sign --backend aws-kms --kms-region eu-west-2
        --key-id alias/release-signing-v1
        --public-key release.asc checksums.txt
```

This is what makes sigillum useful to **non-Go / non-gtb pipelines**: they
install one small binary and sign, with no framework build required.

## Related

- [Generate or mint a signing key](generate-or-mint-a-signing-key.md)
- [Publish a WKD tree](publish-a-wkd-tree.md)
- [Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md)
- [`sign` command reference](../reference/cli/sign.md) — every flag, default and
  refused combination
- [Architecture](../explanation/components/index.md)
- [What sigillum does not do](../explanation/what-sigillum-does-not-do.md)
