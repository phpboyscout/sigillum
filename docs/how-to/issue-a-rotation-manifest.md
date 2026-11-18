---
title: Issue a rotation manifest
description: Issue a signed rotation manifest with sigillum keys rotate, for the empty fire drill, a scheduled rotation to a new release key, and a compromise that revokes one, carrying every earlier manifest forward.
date: 2026-11-18
tags: [how-to, keys, rotation, minisign, signing]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Issue a rotation manifest

To change which release keys installed binaries trust, run `sigillum keys rotate`
with the rotation authority key, then publish the two files it writes as assets
of a **new** release. A rotation-capable binary fetches them on its next update.

```bash
sigillum keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
    --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
```

This guide covers the three runs you will make: the empty fire drill, a scheduled
rotation and a compromise. Every flag is in the
[`keys rotate` reference](../reference/cli/keys.md#keys-rotate).

## Before you start

- **An Ed25519 rotation authority key**, held by any signing backend: an AWS KMS
  key, or a PKCS#8 PEM file under the `local` backend. It is not a release key,
  and it never signs a release.
- **Binaries that embed the authority's minisign public key**, the `RW…` line
  `sigillum keys minisign` prints for it. A binary without it cannot apply a
  manifest, and keeps the trust it shipped with.
- **The armored public keys the binaries embed**, for `--anchor`. They let the
  command check the manifest exactly as an updater will.
- **The latest published `rotate-keys.json`** and its `.minisig`, for every run
  after the first.

## Run the fire drill first

The first manifest a project publishes should be empty. It changes nothing, and
it proves the authority key, the release pipeline and the updater all work
before the day a key is compromised.

```bash
sigillum keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
    --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
```

Check the `authority` line it prints against the key your binaries embed. Then
publish `out/rotate-keys.json` and `out/rotate-keys.json.minisig` on a new
release, and update a rotation-capable binary to it.

## Rotate to a new release key

A scheduled rotation adds the new key. The old key stays trusted until a later
manifest revokes it, so releases signed with either verify while the change rolls
out.

```bash
sigillum keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
    --previous ./published/rotate-keys.json \
    --add ./release-v2.asc \
    --anchor ./release-v1.asc \
    --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
```

`--previous` makes this epoch 2 and carries the fire drill forward. Sign the
next release with the new key.

## Respond to a compromise

A compromise revokes the stolen key, and adds a replacement if one is not already
trusted. `--revoke` takes the fingerprint, and `@<time>` sets when the key stopped
being trustworthy. Without it, `since` is the time of the run.

```bash
sigillum keys rotate --reason compromise --not-after 2027-11-18T00:00:00Z \
    --previous ./published/rotate-keys.json \
    --add ./release-v3.asc \
    --revoke 0123456789ABCDEF0123456789ABCDEF01234567@2026-11-17T09:00:00Z \
    --anchor ./release-v1.asc --anchor ./release-v2.asc \
    --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
```

Publish it on a new release signed with a key the manifest leaves trusted. A
binary that predates rotation cannot read the manifest, and still trusts the
revoked key, so tell those users to update by hand.

## Every later manifest carries the earlier ones

An updater replaces what it stored with each manifest it applies, so a manifest
that leaves out an earlier revoke makes every updater trust that key again. Always
pass the **latest published** manifest as `--previous`. The command refuses an
epoch that skips ahead, because the likeliest cause is an older manifest passed
by mistake. Pass `--allow-epoch-gap` only when the gap is deliberate.

Once a manifest revokes a key, every later manifest carries that revoke, so every
later one must be `--reason compromise`, even a routine rotation. If a manifest
revoked a key and added none, every later run needs `--anchor`, because nothing
else proves a release key remains.

## Replace the authority key

When the authority key itself changes, ship binaries that embed the new
authority's public key first. Then sign the next manifest with the new key, and
name the old one so the previous manifest still verifies. This example carries a
revoke, so it is a compromise manifest:

```bash
sigillum keys rotate --reason compromise --not-after 2027-11-18T00:00:00Z \
    --previous ./published/rotate-keys.json \
    --previous-authority RWRMTCwy9KhAalReu2jRMWyIaqAUrtkEgFZIA9FHNBZzyaQ089+PxvIG \
    --backend aws-kms --key-id alias/rotation-authority-2 --output-dir ./out
```

## Related

- [`keys rotate` reference](../reference/cli/keys.md#keys-rotate)
- [Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md), for `keys minisign`
- [go-tool-base spec 0101, signing key rotation](https://gitlab.com/phpboyscout/go-tool-base/-/wikis/specs/0101-signing-key-rotation)
