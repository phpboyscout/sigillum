---
title: keys command
description: Reference for `sigillum keys` — every flag of generate, mint, wkd, minisign and publish, with defaults, output layouts, file permissions and failure modes.
date: 2026-08-02
tags: [reference, commands, keys, signing, openpgp, minisign, wkd, publish]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `keys` command

`sigillum keys` manages the keys used for release signing — OpenPGP for checksum
manifests, minisign for the artefacts themselves.

```bash
sigillum keys <subcommand> [flags]
```

`keys` on its own does nothing but print help.

## Subcommands at a glance

| Subcommand | Purpose | Key algorithm |
|---|---|---|
| [`generate`](#keys-generate) | Generate a fresh keypair locally and emit both halves. | Ed25519 or RSA |
| [`mint`](#keys-mint) | Build an armored OpenPGP public key from an existing signer. | RSA only |
| [`wkd`](#keys-wkd) | Build a Web Key Directory tree from one or more public keys. | n/a (reads `.asc` files) |
| [`minisign`](#keys-minisign) | Emit the minisign public key release consumers pin. | Ed25519 only |
| [`publish`](#keys-publish) | Stage a minisign public key into a keys site with a manifest. | n/a (reads a `.pub` file) |

The two families serve different verifiers. OpenPGP keys are published over WKD
and verify checksum manifests; minisign keys are published as plain files and
verify release artefacts for cargo-binstall and rtb-update, neither of which
parses OpenPGP.

## File permissions every subcommand uses

| Artefact | Mode | Why |
|---|---|---|
| Private-half key files | `0600` | The irreplaceable half. A fresh private key is never world-readable. |
| Public keys, WKD trees, `keys.json` | `0644` | Publishing them is the entire point. |

Output files are created with `O_EXCL`, so the "does it exist?" check and the
create are one atomic syscall — there is no window between them. `--force`
switches to truncate-and-rewrite.

---

## `keys generate` {#keys-generate}

Generate a fresh keypair entirely in-process — no shell-out, no `gpg` — and
write both halves.

| Flag | Default | Description |
|------|---------|-------------|
| `--algorithm` | *(required)* | `ed25519` or `rsa`. No default; omitting it fails with `required flag(s) "algorithm" not set`. |
| `--name` | *(required)* | OpenPGP user-id real name. |
| `--email` | *(required)* | OpenPGP user-id email. |
| `--rsa-bits` | `4096` | RSA modulus size. `2048`, `3072` or `4096`; anything else fails with `--rsa-bits must be 2048, 3072, or 4096 (got 1024)`. Ignored for Ed25519. |
| `--private-format` | *(algorithm default)* | Private-half encoding: `openpgp` or `pem`. See below. |
| `--output` | `<algorithm>.asc` | Path for the armored public key. |
| `--private-output` | *(derived from `--output`)* | Path for the private half. |
| `--created` | *(now)* | Creation time, RFC3339. Folds into the fingerprint. |
| `--force` | `false` | Overwrite existing output files. |

### Which private-key format do I get?

This is the flag most likely to catch you out, because the default for Ed25519
is *not* readable by the `local` signing backend.

| `--algorithm` | `--private-format` | Private half written as | Default `--private-output` | Readable by `--backend local`? |
|---|---|---|---|---|
| `ed25519` | *(unset)* or `openpgp` | armored OpenPGP secret-key block | `.asc` → `.priv.asc` | **No** |
| `ed25519` | `pem` | unencrypted PKCS#8 PEM | `.asc` → `.pem` | Yes |
| `rsa` | *(unset)* or `pem` | PKCS#1 PEM | `.asc` → `.pem` | Yes |
| `rsa` | `openpgp` | *refused* | — | — |

Pointing `--backend local --key-id` at an Ed25519 `.priv.asc` fails with
`no PEM block found in file`. Generate with `--private-format pem` when the key
is going to sign anything locally; that is what makes minisign artefact signing
possible without an HSM.

`--private-format openpgp` with `--algorithm rsa` fails with `--private-format
openpgp is not supported for --algorithm rsa; RSA private halves are written as
PKCS#1 PEM`. An unknown value fails with `unknown --private-format "x"`.

### Failure modes

| Situation | Message |
|---|---|
| `--output` equals `--private-output` | `--output (x.asc) must differ from --private-output (x.asc)` |
| An output file exists, no `--force` | `writing private-half output: "release.pem" (pass --force to overwrite): output file already exists` |

The private half is encoded and written **before** the public half, under the
no-clobber guard, so a failure cannot leave a lone public key behind whose
private half was never saved.

### What it logs

```
INFO Generated OpenPGP keypair algorithm=rsa public_output=release.asc private_output=release.pem creation_time=… fingerprint=9458EAFE…
WARN Move the private-half file to offline storage now. private_output=release.pem
```

---

## `keys mint` {#keys-mint}

Wrap a signer that already exists — a KMS key or a local PEM — in OpenPGP
framing and write the armored public half. It does **not** generate a private
key; the private half never leaves its backend.

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | `aws-kms` or `local`. |
| `--key-id` | *(required)* | Key ID/ARN/alias, or a PEM path for `local`. |
| `--name` | *(required)* | OpenPGP user-id real name on the minted key. |
| `--email` | *(required)* | OpenPGP user-id email on the minted key. |
| `--output` | `release.asc` | Path for the armored public key. |
| `--created` | *(now)* | Creation time, RFC3339. Pin it only when re-minting an existing key. |
| `--force` | `false` | Overwrite the output file. |
| `--kms-region` | `eu-west-2` | Contributed by the AWS KMS backend. |

### What minting actually does

1. Resolve the signer through the backend — for KMS, one `GetPublicKey` call.
2. Build a v4 OpenPGP entity around the public half with your user ID, and
   produce the positive-cert self-signature. That self-signature is **one**
   `kms:Sign` call — the only time the private half is consulted.
3. Armor the result to `--output` and log the fingerprint at INFO.

The creation time folds into the fingerprint, which is why `--created` exists:
same key material, same user ID and same creation time re-derives the same
fingerprint. Different creation times give different fingerprints for the same
underlying key.

### Failure modes

| Situation | Message |
|---|---|
| Ed25519 key | `minting armored public key: got ed25519.PublicKey: unsupported key type: only RSA is supported` |
| `--output -` | `--output "-" (stdout) is not supported; pass a file path` |
| Output exists, no `--force` | `writing output: "release.asc" (pass --force to overwrite): output file already exists` |

Stdout is refused because the armored bytes would interleave with log lines.

If the armored key is written but cannot be parsed back, mint logs
`WARN Wrote armored key but could not parse it back to read fingerprint` and
still succeeds — the file exists and `gpg --show-key` can recover the
fingerprint.

---

## `keys wkd` {#keys-wkd}

Build a [Web Key Directory](../../how-to/publish-a-wkd-tree.md) tree from one or
more armored public-key files, ready to upload to a static host.

```bash
sigillum keys wkd <public-key.asc> [<public-key.asc>...] [flags]
```

At least one key file is required.

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | *(required)* | DNS domain serving the WKD endpoint, e.g. `phpboyscout.uk`. |
| `--email` | *(every distinct email found in the input keys)* | Address(es) to publish under. Repeatable, and comma-separated values are also split. |
| `--output` | `./wkd-staging` | Staging directory receiving the `.well-known/openpgpkey/…` tree. |
| `--method` | `advanced` | URL layout: `advanced` (served from `openpgpkey.<domain>`) or `direct` (served from `<domain>`). |
| `--submission-address` | *(none — the file is omitted)* | Address written to the WKD submission-address file. `auto` uses the first `--email`; an explicit address is used verbatim. |

**`--email` is not required.** Only `--domain` is. With `--email` omitted, every
distinct email across the input keys gets its own bucket — which is usually what
you want and is why the flag has no `MarkFlagRequired`.

### What the tree looks like

```
wkd-staging/
└── .well-known/
    └── openpgpkey/
        └── phpboyscout.uk/
            ├── policy                (empty file, required by the spec)
            ├── submission-address    (only when --submission-address is set)
            └── hu/<z-base-32-hash>   (binary concatenated keys)
```

Keys matching an email are concatenated in **lexicographic fingerprint order**,
so the tree is reproducible across deploys. A key with several matching UIDs
lands in every matching bucket — standard WKD behaviour. A multi-entity key ring
file is split per entity, so no entity is cross-published into another's bucket.

### Failure modes

| Situation | Message |
|---|---|
| A requested email matches no key | `no input key matched --email security@example.org` |
| An input key has no parseable UID email | `key release.asc has no UID with a parseable email` |
| Input is not armored OpenPGP | `parsing release.asc as armored OpenPGP: …` |
| `--submission-address auto` with no resolvable email | `--submission-address auto requires at least one resolvable --email` |

---

## `keys minisign` {#keys-minisign}

Resolve an Ed25519 signing key through a backend and emit its minisign public
key — the base64 string release consumers pin. Nothing secret is involved: for a
KMS key this is one `GetPublicKey` call.

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | `aws-kms` or `local`. |
| `--key-id` | *(required)* | Key ID/ARN/alias, or a PEM path for `local`. |
| `--output` | *(none — print to stdout)* | Write the two-line minisign public-key file here instead of printing the bare key. |
| `--comment` | *(minisign's own wording)* | Untrusted comment for the public-key file. Nothing signs it. |
| `--force` | `false` | Overwrite `--output` if it exists. |
| `--kms-region` | `eu-west-2` | Contributed by the AWS KMS backend. |

With no `--output` the bare key goes to **stdout** and the log line to stderr, so
`sigillum keys minisign … > key.b64` produces a usable file. This is deliberate
and regression-tested: the value once went to stderr, which looked correct on a
terminal and produced an empty file when redirected.

The key identifier derives from the public key itself, so re-running against the
same key produces the same output on any machine. Re-derive rather than store.

### Where the value goes

| Consumer | Field | Form |
|---|---|---|
| cargo-binstall | `pubkey` in `[package.metadata.binstall.signing]` | the base64 string as printed |
| rtb-update | `ToolMetadata::update_public_keys` | the **raw 32 bytes** — the last 32 bytes of the decoded body, not the base64 string |

### Failure modes

| Situation | Message |
|---|---|
| Non-Ed25519 key | `minisign requires an Ed25519 signing key, but --key-id resolved to *rsa.PublicKey; RSA keys sign the OpenPGP manifest path (--format openpgp) instead` |
| `--output` exists, no `--force` | `writing artefact.pub: "artefact.pub" (pass --force to overwrite): output file already exists` |

---

## `keys publish` {#keys-publish}

Stage a minisign public key into a static keys site: write it to a stable path
and record it in a machine-readable `keys.json`.

```bash
sigillum keys publish <public-key.pub> [flags]
```

Exactly one `.pub` file, produced by `keys minisign --output`.

| Flag | Default | Description |
|------|---------|-------------|
| `--project` | *(required)* | Project whose artefacts this key signs. Used as a path segment. |
| `--output` | `./keys-staging` | Site root. Receives `minisign/<project>/v<N>.pub` and `keys.json`. |
| `--generation` | `1` | Key generation, incrementing on rotation. Must be ≥ 1. |
| `--status` | `active` | Lifecycle state: `active`, `retired` or `revoked`. |
| `--purpose` | `artefact` | What this key signs. Recorded in the manifest. |
| `--valid-from` | *(today, UTC)* | Date the key started signing, `YYYY-MM-DD`. Pin it for reproducible output. |

`--project` must match `^[a-z0-9][a-z0-9._-]{0,63}$` — lowercase alphanumeric
with dots, dashes or underscores. That constraint exists because the value
becomes a path segment: rejecting separators and traversal here is what stops
any input writing outside the site root.

It reads a **file** rather than a backend on purpose. Minting a key touches your
KMS; publishing it touches the trust anchor. Keeping them apart means the
publish step needs no cloud credentials, so a compromised runner cannot rewrite
what the world believes your keys are.

### What it writes

```
keys-staging/
├── keys.json
└── minisign/
    └── mytool/
        └── v1.pub
```

`keys.json` entries carry `id`, `project`, `generation`, `algorithm`
(`minisign-ED`), `purpose`, `status`, `valid_from`, `pubkey` and `path`, sorted
by project then generation so the file does not churn between runs. The
`pubkey` field is the exact string cargo-binstall pins, so the two can be
compared directly.

The manifest is an **audit and discovery record, never a trust input**.
Consumers verify against a key compiled into them or pinned in crate metadata;
`keys.json` exists so a pinned value can be checked against what was published.

The untrusted comment in the published `.pub` is rewritten to a standard form,
so a `--comment` passed to `keys minisign` does not survive publication. Only
the key material is compared.

### Why publishing is add-only

| Situation | Result |
|---|---|
| Same path, identical bytes | No-op, logged `new=false`. Safe to re-run as a check that staging still matches production. |
| Same path, different bytes | `… already holds a different key — published keys are add-only; publish a new generation instead: a different key is already published at this path` |
| Same project + generation in the manifest, different `pubkey` | `… records a different key for mytool generation 1` |
| Same project + generation, same `pubkey` | The entry is replaced, so `--status` can move from `active` to `retired`. |

Consumers pin these keys. Changing one under them is exactly what must never
happen. Retired and revoked keys stay published — a signature made under a key
must remain checkable long after its private half is destroyed — so rotation is
publishing a new generation, never removing an old one.

### Failure modes

| Situation | Message |
|---|---|
| Bad project name | `got "Bad Name": project name must be lowercase alphanumeric with dots, dashes or underscores` |
| `--generation 0` | `--generation must be 1 or greater, got 0` |
| Unknown `--status` | `got "old"; valid values are "active", "retired", "revoked": unknown status` |
| Bad `--valid-from` | `parsing --valid-from "02-08-2026" as YYYY-MM-DD: …` |

---

## Related

- [`sign` command reference](sign.md)
- [Generate or mint a signing key](../../how-to/generate-or-mint-a-signing-key.md)
- [Publish a WKD tree](../../how-to/publish-a-wkd-tree.md)
- [Sign an artefact for Rust consumers](../../how-to/sign-an-artefact-for-rust-consumers.md)
- [What sigillum does not do](../../explanation/what-sigillum-does-not-do.md)
