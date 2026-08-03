---
title: Sign an artefact for Rust consumers
description: Produce a minisign artefact signature with sigillum, emit the public key cargo-binstall and rtb-update pin, and publish it into a static keys site with a keys.json manifest.
date: 2026-08-02
tags: [how-to, minisign, ed25519, artefacts, cargo-binstall, rtb-update, publish]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Sign an artefact for Rust consumers

cargo-binstall and rtb-update verify release artefacts, and neither parses
OpenPGP. They speak **minisign**. `sigillum sign --format minisign` produces
what they expect: a prehashed `ED` minisign signature over the artefact itself,
written next to it as `<artefact>.minisig`.

This is a separate lane from the OpenPGP one, not an option on it. The two use
different key algorithms, different output files and different publication
paths, and a key from one lane cannot be used in the other. Work through the
whole guide once and the shape becomes obvious.

## What differs from the OpenPGP path

| | OpenPGP (`--format openpgp`) | minisign (`--format minisign`) |
|---|---|---|
| Key algorithm | RSA only | Ed25519 only |
| Signs | the checksum manifest | each release artefact |
| Output | `<input>.sig` | `<input>.minisig` |
| Identity comes from | `--public-key` (an `.asc`) | the signer itself |
| Published via | `keys wkd` (Web Key Directory) | `keys publish` (static keys site) |
| Verified by | `gpg`, `go/signing/verify` | `minisign`, cargo-binstall, rtb-update |

`--public-key` and `--append` are refused on the minisign path, and `--project`
is refused on the OpenPGP path. Those are hard errors rather than ignored flags,
so a wrong combination stops rather than silently doing something else.

## Prerequisites

- sigillum installed — see
  [Sign and verify your first release](../tutorials/sign-and-verify-your-first-release.md).
- An **Ed25519** signing key reachable through a backend. For production that is
  an AWS KMS `ECC_NIST_EDWARDS25519` key; for development it is a local PEM,
  created below.
- The `minisign` binary, if you want to verify with a reference implementation.
  Optional.

## Get an Ed25519 key the local backend can read

`keys generate --algorithm ed25519` writes its private half as an armored
OpenPGP secret-key block by default, and the `local` backend cannot read that —
it reads PEM. Pointing `--key-id` at the default `.priv.asc` fails with *no PEM
block found in file*.

Pass `--private-format pem` to get the PKCS#8 PEM the backend does read:

```bash
sigillum keys generate \
    --algorithm ed25519 --private-format pem \
    --name "Artefact Signer" --email release@example.org \
    --output artefact.asc --private-output artefact.pem
```

That single flag is what makes minisign signing possible without an HSM — for a
tutorial, a test, or a project with no cloud KMS.

For production, skip generation entirely: point `--backend aws-kms --key-id
alias/artefact-signing-v1` at a KMS Ed25519 key and the private half never
exists outside AWS.

The `artefact.asc` public half that `keys generate` also writes is an OpenPGP
key file. It has no role on this path — minisign identity comes from the signer.
You can delete it.

## Sign the artefact

```bash
sigillum sign \
    --format minisign \
    --backend local \
    --key-id ./artefact.pem \
    --project mytool \
    tool_1.2.3_linux_amd64.tar.gz
```

```
INFO Signed artefact format=minisign backend=local key_id=./artefact.pem minisign_key_id=846E063241A4289F input=tool_1.2.3_linux_amd64.tar.gz output=tool_1.2.3_linux_amd64.tar.gz.minisig project=mytool trusted_comment_time=…
```

The `.minisig` extension is load-bearing: rtb-update selects its parser by
extension. cargo-binstall's signature URL is configurable and can point at the
same file. Override the path with `--output` only if you know both consumers
will still find it.

`--project` is recorded in the signature's **signed** trusted comment, so it is
evidence rather than decoration — tampering with it breaks verification. The
resulting comment line looks like this:

```
trusted comment: timestamp:1785704190	file:tool_1.2.3_linux_amd64.tar.gz	hashed	project:mytool	key:846E063241A4289F
```

Omit `--project` and minisign's own default comment is emitted instead.

### Reproducible artefact signatures

Two runs over the same bytes with the same key and the same timestamp produce
byte-identical `.minisig` files. Pin the timestamp either way:

```bash
# Explicit flag
sigillum sign --format minisign --backend local --key-id ./artefact.pem \
    --created 2026-08-02T00:00:00Z tool_1.2.3_linux_amd64.tar.gz

# Or via the reproducible-builds convention, honoured when --created is unset
SOURCE_DATE_EPOCH=1785700000 sigillum sign --format minisign \
    --backend local --key-id ./artefact.pem tool_1.2.3_linux_amd64.tar.gz
```

`--created` wins over `SOURCE_DATE_EPOCH`; with neither set the signature
carries the current time truncated to whole seconds. `SOURCE_DATE_EPOCH` is
honoured on the minisign path only — the OpenPGP path reads `--created` and
nothing else.

## Emit the public key consumers pin

`keys minisign` resolves the signer's public half and prints the single base64
string that gets pinned. Nothing secret is involved: for a KMS key this is one
`GetPublicKey` call.

```bash
sigillum keys minisign --backend local --key-id ./artefact.pem
# RWSEbgYyQaQon9lZeNlDxKWq/UhdFdkIQgMCV9nVIJ8544IOLgx7Dtku
```

The key goes on **stdout**, deliberately — `sigillum keys minisign … > key.b64`
works, and the log lines go to stderr where they belong.

Where the value lands:

- **cargo-binstall** — the `pubkey` field of the crate's
  `[package.metadata.binstall.signing]` table. Paste the base64 string as
  printed.
- **rtb-update** — `ToolMetadata::update_public_keys`, which wants the **raw
  32-byte Ed25519 key**: the last 32 bytes of the decoded body, not the base64
  string itself.

The identifier derives from the public key, so re-running this against the same
key gives the same output on any machine. That makes it safe to re-derive rather
than store.

Add `--output artefact.pub` to write the two-line minisign public-key file
instead of printing the bare key. That file is what `keys publish` consumes.

## Publish the public key

`keys publish` stages a minisign public key into a static keys site and records
it in a machine-readable `keys.json`:

```bash
sigillum keys minisign --backend local --key-id ./artefact.pem --output artefact.pub
sigillum keys publish --output ./keys-staging --project mytool artefact.pub
```

```
keys-staging/
├── keys.json
└── minisign/
    └── mytool/
        └── v1.pub
```

```json
{
  "keys": [
    {
      "id": "846E063241A4289F",
      "project": "mytool",
      "generation": 1,
      "algorithm": "minisign-ED",
      "purpose": "artefact",
      "status": "active",
      "valid_from": "2026-08-02",
      "pubkey": "RWSEbgYyQaQon9lZeNlDxKWq/UhdFdkIQgMCV9nVIJ8544IOLgx7Dtku",
      "path": "minisign/mytool/v1.pub"
    }
  ]
}
```

`keys publish` reads a **file**, not a backend, on purpose: minting a key
touches your KMS, publishing it touches the trust anchor, and keeping those
apart means the publish step needs no cloud credentials. A compromised release
runner cannot rewrite what the world believes your keys are.

It composes with `keys wkd`, which writes into the same staging directory, so
one deploy publishes both trust anchors:

```bash
sigillum keys wkd     --output ./keys-staging --domain example.org release.asc
sigillum keys publish --output ./keys-staging --project mytool artefact.pub
wrangler pages deploy ./keys-staging
```

### Why re-running publish is safe

Publication is **add-only**. Re-running with identical content is a no-op, which
makes it usable as a check that a staging directory still matches production. A
key already published at the same path with **different** bytes is refused:

```
keys-staging/minisign/mytool/v1.pub already holds a different key — published
keys are add-only; publish a new generation instead: a different key is already
published at this path
```

Consumers pin these keys. Changing one under them is exactly what must never
happen.

The untrusted comment in the published `.pub` file is rewritten by `keys
publish` to a standard form, so a `--comment` you passed to `keys minisign` does
not survive publication. Only the key material is compared.

## Rotate without breaking anyone

Publish the new generation, then mark the old one retired. Never remove it — a
signature made under a key must stay checkable long after its private half is
destroyed.

```bash
sigillum keys publish --output ./keys-staging --project mytool \
    --generation 2 mytool-v2.pub
sigillum keys publish --output ./keys-staging --project mytool \
    --generation 1 --status retired mytool-v1.pub
```

`--status` accepts `active`, `retired` or `revoked` and nothing else. Re-running
`publish` for an existing project and generation replaces the manifest entry so
the status can move — but its `pubkey` may not change, for the same reason the
on-disk guard exists.

There is no `--append` equivalent here. A minisign signature file carries one
signature, so a rotation overlap is handled by publishing both generations'
public keys, not by dual-signing one artefact.

## Verify the result

sigillum has no verify command. Use the reference implementation:

```bash
minisign -Vm tool_1.2.3_linux_amd64.tar.gz -P "$(sigillum keys minisign --backend local --key-id ./artefact.pem)"
```

A tampered artefact, or a tampered `project:` field in the trusted comment,
fails this check — the global signature covers the trusted comment, which is why
recording the project there is evidence rather than a label.

## What this path will not do

- **An RSA key cannot sign minisign.** `sign --format minisign` against an RSA
  key fails with *minisign requires an Ed25519 signing key, but --key-id
  resolved to \*rsa.PublicKey*. Use a separate Ed25519 key.
- **An Ed25519 key cannot sign OpenPGP.** The reverse fails with *unsupported
  key type: only RSA is supported*. One key cannot serve both lanes; a project
  publishing both signs with two keys.
- **KMS caps the signed message at 4096 bytes.** That is why the artefact is
  hashed first; a caller that skipped the prehash gets a typed error rather than
  an opaque AWS `ValidationException`.

More at [What sigillum does not do](../explanation/what-sigillum-does-not-do.md).

## Related

- [`sign` command reference](../reference/cli/sign.md)
- [`keys` command reference](../reference/cli/keys.md) — full flags for
  `keys minisign` and `keys publish`
- [Sign a release artefact](sign-a-release-artefact.md) — the OpenPGP lane
- [Publish a WKD tree](publish-a-wkd-tree.md) — the OpenPGP trust anchor
