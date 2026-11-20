---
title: keys command
description: Reference for `sigillum keys`, with every flag of generate, generate-image, mint, wkd, minisign, publish and rotate, with defaults, output layouts, file permissions and failure modes.
date: 2026-08-02
tags: [reference, commands, keys, signing, openpgp, minisign, wkd, publish, rotation]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# `keys` command

`sigillum keys` manages the keys used for release signing: OpenPGP for checksum
manifests, minisign for the artefacts themselves, and ECDSA P-256 for container
images.

```bash
sigillum keys <subcommand> [flags]
```

`keys` on its own does nothing but print help.

## Subcommands at a glance

| Subcommand | Purpose | Key algorithm |
|---|---|---|
| [`generate`](#keys-generate) | Generate a fresh keypair locally and emit both halves. | Ed25519 or RSA |
| [`generate-image`](#keys-generate-image) | Generate an image-signing keypair locally, for tests and local registries. | ECDSA P-256 |
| [`mint`](#keys-mint) | Build an armored OpenPGP public key from an existing signer. | RSA only |
| [`wkd`](#keys-wkd) | Build a Web Key Directory tree from one or more public keys. | n/a (reads `.asc` files) |
| [`minisign`](#keys-minisign) | Emit the minisign public key release consumers pin. | Ed25519 only |
| [`publish`](#keys-publish) | Stage a minisign public key into a keys site with a manifest. | n/a (reads a `.pub` file) |
| [`rotate`](#keys-rotate) | Issue a signed rotation manifest that changes which release keys binaries trust. | Ed25519 authority |

The two families serve different verifiers. OpenPGP keys are published over WKD
and verify checksum manifests; minisign keys are published as plain files and
verify release artefacts for cargo-binstall and rtb-update, neither of which
parses OpenPGP.

## File permissions every subcommand uses

| Artefact | Mode | Why |
|---|---|---|
| Private-half key files | `0600` | The irreplaceable half. A fresh private key is never world-readable. |
| Public keys, WKD trees, `keys.json`, rotation manifests and their signatures | `0644` | Publishing them is the entire point. |

`generate`, `generate-image`, `mint`, `minisign` and `rotate` create their output with
`O_EXCL`, so the "does it exist?" check and the create are one atomic syscall,
with no window between them. With `--force` the new content is written to a
temporary file beside the target and renamed over it, so a failure part-way
leaves the old file intact. That needs write access to the directory, and the
replaced file's hard links, owner and ACLs are not carried over. These five set
their modes explicitly, so the umask does not narrow them.

`wkd` and `publish` have no `--force`. They write their trees in place, and the
umask applies. See their sections below.

---

## `keys generate` {#keys-generate}

Generate a fresh keypair entirely in-process, with no shell-out and no `gpg`,
and write both halves.

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

Pointing `--backend local --key-id` at an Ed25519 `.priv.asc` is refused as
`unsupported key type`, and the hints say which lane takes the key (see
[`sign`](sign.md#which-flag-combinations-are-refused)). Generate with
`--private-format pem` when the key is going to sign anything locally; that is
what makes minisign artefact signing possible without an HSM.

`--private-format openpgp` with `--algorithm rsa` fails with `--private-format
openpgp is not supported for --algorithm rsa; RSA private halves are written as
PKCS#1 PEM`. An unknown value fails with `unknown --private-format "x"`.

### Failure modes

| Situation | Message |
|---|---|
| `--output` equals `--private-output` | `--output (x.asc) must differ from --private-output (x.asc)` |
| An output file exists, no `--force` | `"release.pem" (pass --force to overwrite): output file already exists` |

Both halves are written through the same pair write as `keys generate-image`,
so a run writes both or neither. `--output` and `--private-output` are compared
as the files they resolve to, so `./a.asc` and `a.asc`, or a symlink from one
to the other, give the same refusal as identical paths. Under `--force` a
failed public half puts the old private half back, as described under
`keys generate-image`.

### What it logs

```
INFO Generated OpenPGP keypair algorithm=rsa public_output=release.asc private_output=release.pem creation_time=… fingerprint=9458EAFE…
WARN Move the private-half file to offline storage now. private_output=release.pem
```

---

## `keys generate-image` {#keys-generate-image}

`sigillum keys generate-image` generates an ECDSA P-256 keypair in the process
and writes both halves, for [`sign image`](sign.md#sign-image).

```bash
sigillum keys generate-image [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `image.pub` | Where to write the PEM public key (`PUBLIC KEY`, PKIX). |
| `--private-output` | `image.key` | Where to write the private key: unencrypted PKCS#8 PEM, mode `0600`. |
| `--force` | `false` | Overwrite the output files if they exist. |

The private key is what `--backend local` signs with, and anyone who can read
that file can sign. The public key is what `cosign verify --key` reads.

This command is for tests and local registries. Production image keys live in
a key service, such as an `ECC_NIST_P256` `SIGN_VERIFY` key in AWS KMS, and
their private half never leaves it.

### Failure modes

| Situation | Message |
|---|---|
| `--output` and `--private-output` name the same file | `"a.pem" and "a.pem": --output and --private-output name the same file` |
| An output file exists, no `--force` | `"image.key" (pass --force to overwrite): output file already exists` |

Both paths are checked before either file is written. The same-file check also
catches a symlink, a linked directory, and two names that differ only by case.
If writing the public half fails, the private half this run created is removed.
Under `--force`, both halves are staged first, and the old private half is held
in a hidden `.<name>.old.*` directory beside it until the public half is written.
If the public half then fails, the old private half is put back. If it cannot be
put back, the error says the private half was replaced, and names where the old
one is when it could be held.

### What it logs

```
INFO Generated image-signing keypair public=image.pub private=image.key
```

---

## `keys mint` {#keys-mint}

Wrap a signer that already exists (a KMS key or a local PEM) in OpenPGP
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

1. Resolve the signer through the backend. For KMS that is one `GetPublicKey` call.
2. Build a v4 OpenPGP entity around the public half with your user ID, and
   produce the positive-cert self-signature. That self-signature is **one**
   `kms:Sign` call, and it is the only time the private half is consulted.
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
still succeeds. The file exists, and `gpg --show-key` can recover the
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
| `--submission-address` | *(none; the file is omitted)* | Address written to the WKD submission-address file. `auto` uses the first `--email`; an explicit address is used verbatim. |

**`--email` is not required.** Only `--domain` is. With `--email` omitted, every
distinct email across the input keys gets its own bucket. That is usually what
you want, and it is why the flag has no `MarkFlagRequired`.

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
lands in every matching bucket, which is standard WKD behaviour. A multi-entity key ring
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
key: the base64 string release consumers pin. Nothing secret is involved: for a
KMS key this is one `GetPublicKey` call.

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | *(required)* | `aws-kms` or `local`. |
| `--key-id` | *(required)* | Key ID/ARN/alias, or a PEM path for `local`. |
| `--output` | *(none; print to stdout)* | Write the two-line minisign public-key file here instead of printing the bare key. |
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
| rtb-update | `ToolMetadata::update_public_keys` | the **raw 32 bytes**: the last 32 bytes of the decoded body, not the base64 string |

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

`--project` must match `^[a-z0-9][a-z0-9._-]{0,63}$`: lowercase alphanumeric
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
happen. Retired and revoked keys stay published, because a signature made under a key
must remain checkable long after its private half is destroyed. Rotation is
publishing a new generation, never removing an old one.

### Failure modes

| Situation | Message |
|---|---|
| Bad project name | `got "Bad Name": project name must be lowercase alphanumeric with dots, dashes or underscores` |
| `--generation 0` | `--generation must be 1 or greater, got 0` |
| Unknown `--status` | `got "old"; valid values are "active", "retired", "revoked": unknown status` |
| Bad `--valid-from` | `parsing --valid-from "02-08-2026" as YYYY-MM-DD: …` |

---

## `keys rotate` {#keys-rotate}

Write `rotate-keys.json` and its minisign signature, `rotate-keys.json.minisig`,
signed by the project's rotation authority. A rotation-capable binary that
fetches both from a release trusts the release keys the manifest adds and stops
trusting the ones it revokes. The format and the updater are
[go-tool-base spec 0101](https://gitlab.com/phpboyscout/go-tool-base/-/wikis/specs/0101-signing-key-rotation);
the flags and refusals below are
[sigillum spec 0008](https://gitlab.com/phpboyscout/sigillum/-/wikis/specs/0008-keys-rotate).

| Flag | Default | Description |
|------|---------|-------------|
| `--reason` | *(required)* | `scheduled` or `compromise`. Only a `compromise` manifest may revoke. |
| `--not-after` | *(required)* | RFC 3339 time after which an updater no longer applies the manifest for the first time. |
| `--epoch` | 1, or the previous epoch plus one | The manifest's epoch, at least 1. Without `--previous` only 1 is accepted. With it, a value past the next epoch needs `--allow-epoch-gap`, and one at or below the previous epoch is refused. |
| `--allow-epoch-gap` | `false` | Accept an `--epoch` that skips past the previous manifest's next epoch. |
| `--add` | *(none)* | Armored OpenPGP public key file of a release key to trust: one public key, in one armored block. Repeatable. The fingerprint is read from the key, and the key is re-armored before it is published. A file holding private key material is refused. |
| `--revoke` | *(none)* | 40-hex fingerprint of a release key to stop trusting, optionally `@<RFC 3339>` for when it stopped being trustworthy. `since` defaults to the time of the run. Repeatable. |
| `--previous` | *(none)* | The latest published `rotate-keys.json`. Its `.minisig` must sit beside it. Required above epoch 1. |
| `--previous-authority` | *(the signer's key)* | The minisign public key (`RW…`) that signed `--previous`, when the authority has been replaced. |
| `--anchor` | *(none)* | Armored release key the binaries embed. With it, the manifest is checked as an updater checks it. Repeatable. |
| `--anchor-only` | *(none)* | Armored key the binaries embed as anchor-only. Repeatable. |
| `--backend` | *(required)* | Signing backend holding the authority key, such as `aws-kms` or `local`. |
| `--key-id` | *(required)* | The authority key: a KMS key ID, ARN or alias, or a PKCS#8 PEM path for `local`. Must be Ed25519. |
| `--output-dir` | `.` | Directory to write the two files into. |
| `--force` | `false` | Overwrite existing output files. |

`issued_at` is always the time of the run, with no flag to set it.

### Carrying the previous manifest forward

Each manifest **replaces** what an updater stored. So a manifest must carry every
earlier add and revoke, or an updater trusts a revoked key again. With
`--previous`, the command verifies that manifest and copies its adds and revokes
into the new one, and this run's `--add` and `--revoke` apply on top. Revoking a
key an earlier manifest added removes it from `add`. Verifying `--previous`
refuses an add whose armored text is anything but one public key block, so a
previous manifest from another issuer that carries private key material is
refused, naming the key. Carried adds are then re-armored the same way as
`--add`. The refusal comes before this run's `--revoke`, so revoking the leaked
key in the same run does not get past it. Build on the last clean manifest
instead: see
[When the previous manifest published a private key](../../how-to/issue-a-rotation-manifest.md#when-the-previous-manifest-published-a-private-key).

Once a manifest revokes a key, every later one carries the revoke, so every later
one must be `--reason compromise`.

### What it writes and prints

Both files are written at `0644`, because they are published as release assets.
Without `--force`, an existing file at either path is refused before anything is
written. If the signature cannot be written, the manifest is put back as it was:
removed if it is new, or restored to the earlier manifest under `--force`. So a
run never leaves a manifest beside a signature that does not cover it. If the
undo itself fails, the error says what the manifest path now holds.

On success it prints the paths, the epoch and reason, every add and revoke, with
those taken from `--previous` marked `(carried)`, and the authority's minisign
public key:

```text
Wrote out/rotate-keys.json and out/rotate-keys.json.minisig
epoch      1 (scheduled)
not after  2027-11-18T00:00:00Z
authority  RWRMTCwy9KhAalReu2jRMWyIaqAUrtkEgFZIA9FHNBZzyaQ089+PxvIG
```

Check the `authority` line against the key your binaries embed. A manifest
signed by any other key is refused by every updater.

### Not an MCP tool

`keys rotate` is withheld from the MCP tool surface. Its key can rewrite the
trust of every installed binary, so it runs only from a terminal a person chose
to open.

### Failure modes

Every refusal exits non-zero and writes nothing.

| Situation | Message |
|---|---|
| `--epoch` above 1 with no `--previous` | `epoch 3: pass --previous with the latest published manifest: an epoch above 1 needs the previous manifest` |
| `--epoch` skips ahead | `epoch 5, previous is 1: a stale --previous drops later revokes; pass --allow-epoch-gap if the gap is deliberate: epoch skips past the previous manifest's next epoch` |
| `--epoch` at or below the previous | `epoch 1, previous is 1: epoch is not above the previous manifest's` |
| `--epoch` more than 1024 above the previous | `epoch is further above the previous manifest's than an updater accepts` |
| `--previous` does not verify | `the previous manifest: ...` with the verification error |
| `--revoke` with `--reason scheduled` | `pass --reason compromise: a manifest that revokes must have reason compromise` |
| A carried revoke with `--reason scheduled` | `the previous manifest revokes keys, and every later manifest must carry them, so pass --reason compromise: ...` |
| One key in both `--add` and `--revoke` | `<fingerprint>: a key is both added and revoked` |
| Revokes and no adds, with no `--anchor` | `pass --anchor with the release keys the binaries embed: a manifest that revokes and adds nothing needs the anchors to prove a release key remains` |
| An updater would refuse it against the anchors | the updater's own refusal: the reason, then `rotation manifest refused` |
| A malformed fingerprint | `"ABCD": not a 40-character hex fingerprint` |
| `--add` names a file holding private key material | `--add v2.priv.asc: holds private key material, which a published manifest must never carry` |
| `--previous` carries an add holding private key material | As a `PGP PRIVATE KEY BLOCK`: `the previous manifest: added key <fingerprint>: the armored text must be one PGP PUBLIC KEY BLOCK with no armour headers and nothing around it: rotation manifest is malformed`. Inside a `PGP PUBLIC KEY BLOCK`: `the previous manifest: added key <fingerprint>: holds private key material: rotation manifest is malformed`. |
| `--add` names a file with no key, or more than one | `--add <file>: ...: not exactly one armored OpenPGP public key` |
| `--epoch 0` | `--epoch must be at least 1` |
| `--not-after` not after the time of the run | `not_after must be after issued_at: rotation manifest is malformed` |
| A non-Ed25519 authority | `the rotation authority signs with minisign, so --key-id must be an Ed25519 key: ...` |
| An output file exists, no `--force` | `".../rotate-keys.json" (pass --force to overwrite): output file already exists` |

---

## Related

- [`sign` command reference](sign.md)
- [Generate or mint a signing key](../../how-to/generate-or-mint-a-signing-key.md)
- [Publish a WKD tree](../../how-to/publish-a-wkd-tree.md)
- [Sign an artefact for Rust consumers](../../how-to/sign-an-artefact-for-rust-consumers.md)
- [Sign a container image](../../how-to/sign-a-container-image.md)
- [Issue a rotation manifest](../../how-to/issue-a-rotation-manifest.md)
- [What sigillum does not do](../../explanation/what-sigillum-does-not-do.md)
