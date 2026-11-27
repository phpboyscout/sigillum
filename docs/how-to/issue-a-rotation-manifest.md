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

A release ships only its latest manifest, so an install that skipped earlier
releases learns of an add or a revoke only if the latest manifest carries it.
Always pass the **latest published** manifest as `--previous`. The command refuses an
epoch that skips ahead, because the likeliest cause is an older manifest passed
by mistake. Pass `--allow-epoch-gap` only when the gap is deliberate.

Once a manifest revokes a key, every later manifest carries that revoke. A carried
revoke doesn't make a manifest a compromise, so a routine rotation after one is
still `--reason scheduled`. Only a manifest that revokes a key afresh needs
`--reason compromise`.

An updater built on go/signing v0.15.x or earlier refuses a `scheduled` manifest
that carries a revoke, and applies nothing from it. While binaries that old are
still installed, issue a manifest that carries a revoke with `--reason compromise`
as before. Both reasons carry the same revokes. Only the label differs. If a manifest revoked a key and added none, every later run needs `--anchor`, because nothing
else proves a release key remains.

## When the previous manifest is refused for an added key

`keys rotate` will not build on a previous manifest with an add that go/signing
refuses, even one your authority signed. The error starts `the previous
manifest: added key <fingerprint>:`. There are two causes, and they need
opposite fixes, so check which one you have before you change anything.

- **The key leaked.** The add holds private key material.
- **The export is refused.** A manifest written with go/signing v0.15.0 or
  earlier can carry an add with a `Comment:` armour header, a photo ID or a gpg
  backup export. go/signing v0.15.1 refuses those. The key itself is sound.

Both can print the same message. **Treat the key as leaked unless you can show
it is not.** If the error says `holds private key material`, it leaked. Otherwise
run this check on the add, with the fingerprint from the error (it needs `jq` and
`gpg`):

```bash
fp='<fingerprint>'
armored=$(jq -r --arg fp "$fp" '.add[]
    | select((.fingerprint | ascii_upcase | gsub(" "; "")) == ($fp | ascii_upcase | gsub(" "; "")))
    | .armored' ./published/rotate-keys.json)
packets=$(gpg --list-packets <<<"$armored" 2>/dev/null)
if grep -q 'BEGIN PGP PUBLIC KEY BLOCK' <<<"$armored" && ! grep -q 'PRIVATE KEY' <<<"$armored" \
    && grep -q '^:public key packet:' <<<"$packets" && ! grep -q 'secret' <<<"$packets"; then
    echo "refused export: the key is sound"
else
    echo "treat the key as leaked"
fi
```

Only `refused export: the key is sound` means **do not revoke the key**. Any
other result means the key leaked, and that includes a wrong path or
fingerprint, which finds nothing.

In both cases an updater on go/signing v0.15.1 or later refuses that manifest
too, and stays on whatever it applied before it. An updater on v0.15.0 may have
applied it, and keeps what it stored after an upgrade. Both are put right by
the next manifest, which you build on the **last clean** manifest instead.

### The export is refused

1. Export the key again in a form go/signing accepts. See
   [what an added key's armored text may hold](https://signing.go.phpboyscout.uk/reference/file-formats/#what-an-added-keys-armored-text-may-hold).
2. Build on the last clean manifest, with an epoch above the refused one, and
   add the clean export:

   ```bash
   sigillum keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
       --previous ./published/epoch-4/rotate-keys.json \
       --epoch 6 --allow-epoch-gap \
       --add ./release-key-v3.asc \
       --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
   ```

   Here epoch 5 is the refused one. Use `--reason compromise` if you pass a
   `--revoke` the clean manifest doesn't already carry.

3. Pass every other add and revoke the refused manifest made with `--add` and
   `--revoke`, because nothing from it is carried.

### The key leaked

That key's private half is now public, so treat the key as compromised. An
install that applied the leaked manifest under go/signing v0.15.0 trusts the
leaked key until the next manifest reaches it, upgraded or not.

1. Stop publishing the leaked manifest, and sign nothing more with the leaked
   key.
2. Build on the last clean manifest, with an epoch above the leaked one, and
   revoke the leaked key:

   ```bash
   sigillum keys rotate --reason compromise --not-after 2027-11-18T00:00:00Z \
       --previous ./published/epoch-4/rotate-keys.json \
       --epoch 6 --allow-epoch-gap \
       --revoke <leaked fingerprint> \
       --backend aws-kms --key-id alias/rotation-authority --output-dir ./out
   ```

   Here epoch 5 is the leaked one. The gap is deliberate, which is what
   `--allow-epoch-gap` is for.

3. Pass every other add and revoke the leaked manifest made with `--add` and
   `--revoke`, because nothing from it is carried. For an add, use the public
   key file, not what the manifest holds.

Either way, pass the new manifest as `--previous` from then on.

## Replace the authority key

When the authority key itself changes, ship binaries that embed the new
authority's public key first. Then sign the next manifest with the new key, and
name the old one so the previous manifest still verifies. This example revokes
nothing afresh, so it stays scheduled even if the previous manifest carries a
revoke:

```bash
sigillum keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
    --previous ./published/rotate-keys.json \
    --previous-authority RWRMTCwy9KhAalReu2jRMWyIaqAUrtkEgFZIA9FHNBZzyaQ089+PxvIG \
    --backend aws-kms --key-id alias/rotation-authority-2 --output-dir ./out
```

## Related

- [`keys rotate` reference](../reference/cli/keys.md#keys-rotate)
- [Sign an artefact for Rust consumers](sign-an-artefact-for-rust-consumers.md), for `keys minisign`
- [go-tool-base spec 0101, signing key rotation](https://gitlab.com/phpboyscout/go-tool-base/-/wikis/specs/0101-signing-key-rotation)
