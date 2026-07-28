---
title: Publish a WKD tree
description: Generate a Web Key Directory tree from your public keys with sigillum keys wkd, and serve it from a dedicated subdomain so verifiers can cross-check your keys against an externally-administered copy.
date: 2026-07-28
tags: [how-to, keys, wkd, signing, openpgp]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Publish a WKD tree

Web Key Directory (WKD) lets a client fetch your public key from a well-known
URL derived from an email address. It serves as a **second, externally-served
trust anchor**: a verifier can fetch the WKD copy and refuse to trust a release
unless the embedded key and the WKD copy agree on the fingerprint. Compromising
just your code host, or just your WKD host, cannot poison verification.

`sigillum keys wkd` generates the directory tree the WKD spec mandates. Hosting
it is a plain static-file deploy.

## Generate the tree

`keys wkd` takes one or more armored public-key files as arguments and emits the
WKD layout:

```bash
sigillum keys wkd \
    --domain phpboyscout.uk \
    --email release@phpboyscout.uk \
    --submission-address release@phpboyscout.uk \
    --output ./wkd-staging \
    rotation-authority.asc signing-key-v1.asc
```

Result (advanced layout — the default):

```
wkd-staging/
└── .well-known/
    └── openpgpkey/
        └── phpboyscout.uk/
            ├── policy                (empty file, required by the spec)
            ├── submission-address    (the email you configured)
            └── hu/<z-base-32-hash>   (binary concatenated keys)
```

A successful run logs each `hu/` bucket's hash and every file written.

### Flags

- `--domain` (required) — the DNS domain serving the WKD endpoint.
- `--email` (required, repeatable) — the address(es) to publish. Each `--email`
  gets its own `hu/<hash>` bucket; keys are written in lexicographic fingerprint
  order so the output is reproducible across deploys.
- `--output` (default `./wkd-staging`) — the staging directory.
- `--method` (default `advanced`) — the URL layout: `advanced` (served from
  `openpgpkey.<domain>`) or `direct` (served from `<domain>`).
- `--submission-address` (default: omitted) — controls the optional
  submission-address file. Leave unset to omit it, pass `auto` to use the first
  `--email`, or pass an explicit address to override.

### The `openpgpkey.` subdomain

The `openpgpkey.<domain>` host in the advanced layout is fixed by the WKD spec —
every WKD client hardcodes that prefix when building the lookup URL, so you do
not choose it. Verifier configuration on the consumer side only ever takes the
**email**; the hostname falls out mechanically.

## Deploy

The staging directory is a plain static tree — deploy it to any static host that
serves the `.well-known/openpgpkey/...` paths over HTTPS. For a Cloudflare Pages
Direct Upload, for example:

```bash
export CLOUDFLARE_API_TOKEN=...   # a Pages-Edit-scoped token
wrangler pages deploy ./wkd-staging \
    --project-name=openpgpkey-phpboyscout-uk \
    --branch=main \
    --commit-dirty=true
```

To keep the WKD trust anchor independent of your code host and your KMS, host it
on an account and domain distinct from both.

## Verify the round-trip

```bash
gpg --auto-key-locate clear,wkd --locate-keys release@phpboyscout.uk
```

You should see every published fingerprint, matching what `keys mint` /
`keys generate` reported and what you embedded in the verifying tool. A direct
HTTP fetch of the logged `hu/<hash>` path also works for spot-checking.

## Per-rotation re-deploy

When you mint a new key, re-run `keys wkd` against the new public-key file set
(plus any keys you keep serving) and redeploy. The tree is fully reproducible
from the `.asc` files, so there is no manual surgery on the host.

## Related

- [Generate or mint a signing key](generate-or-mint-a-signing-key.md)
- [Sign a release artefact](sign-a-release-artefact.md)
- [`keys` command reference](../reference/cli/keys.md)
