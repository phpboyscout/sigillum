---
title: "KMS-Ed25519 minisign artefact signing"
description: "Implementation spec for the capability sigillum was created to deliver: per-artefact minisign signatures over release binaries, verifiable by cargo-binstall (install-time) and rtb-update (self-update), produced by a KMS-held Ed25519 key with full HSM custody. The design is settled in go-tool-base's 2026-07-28-ed25519-kms-signing.md design spike; nothing has been implemented. minisign's prehashed 'ED' variant is ed25519(BLAKE2b-512(file)) — ordinary Ed25519 over a 64-byte digest computed outside the signer — so the KMS Sign 4096-byte message cap never binds and no software key is needed. This spec resolves the details the spike left open (minisign key_id derivation for a KMS-held key, public-key encoding, the crypto.Signer contract for a digest-as-message signer, trusted-comment determinism), assigns the work across go/signing, go/signing-aws-kms, go/signing-cli, sigillum, rust/cli's rtb-update and terraform-aws-signing-kms, and corrects the D-3 cutover sequencing now that the v2 rekey has published and the dual-sign window is open rather than closed."
status: IN PROGRESS
date: 2026-07-29
tags:
  - specification
  - sigillum
  - signing
  - ed25519
  - minisign
  - cargo-binstall
  - kms
  - rust
  - cross-repo
  - security
author:
  - name: Matt Cockayne
    email: matt@phpboyscout.uk
  - name: Claude Opus 5
    role: AI drafting assistant
---

# KMS-Ed25519 minisign artefact signing

Authors
:   Matt Cockayne, Claude Opus 5 *(AI drafting assistant)*

Date
:   2026-07-29

Status
:   IN PROGRESS — reviewed and approved 2026-07-29. The *design* is settled
    (go-tool-base `2026-07-28-ed25519-kms-signing.md`, decisions D-1..D-6 all
    resolved 2026-07-28); this spec turns it into assigned, testable work and
    resolves four details the spike deferred (§4).

    **§6.1–6.3 are implemented and merged** (2026-07-29): the minisign
    assembler in `go/signing` v0.3.0, the KMS Ed25519 branch in
    `go/signing-aws-kms`, and the CLI surface in `go/signing-cli`.

    **OQ-1 and OQ-2 are resolved (§8).** No release has ever published an
    artefact signature of any kind, so D-3's `ED`-only break has nothing to
    break and §7's rekey gate is withdrawn — the remaining work is unblocked in
    full. cargo-binstall **is** a served target: distributing signed binaries to
    Rust users is the goal of the programme, which adds §6.8 and freezes the
    public-key encoding as a permanent compatibility surface.

    Only OQ-3 remains open, and it is a small scope call.

Related
:   go-tool-base `docs/development/specs/2026-07-28-ed25519-kms-signing.md`
    (the design spike — the authoritative source for this design; **on gtb
    `main` as of commit `c958c890`**),
    [`2026-07-28-sigillum-bootstrap.md`](2026-07-28-sigillum-bootstrap.md)
    (this repo — records the completed extraction and carries D-2..D-6),
    infra `docs/development/specs/2026-07-24-prod-rebuild-and-rekey.md`
    (the trust-root rekey this cutover must coordinate with — §6.5),
    `rust/cli` `crates/rtb-update/src/verify.rs` (consumer contract),
    rust-tool-base `docs/how-to/secure-releases.md` (producer contract),
    cargo-binstall `SIGNING.md` (the other consumer contract),
    [minisign format specification](https://jedisct1.github.io/minisign/)

Scope note
:   This spec covers **artefact** signing only — the per-artefact
    `.minisig` consumed by cargo-binstall and rtb-update. GTB's own Go
    self-update **manifest** path (KMS-RSA over OpenPGP, `checksums.txt`)
    is explicitly unchanged and out of scope. Both algorithms stay
    supported everywhere; nothing forces an existing RSA key or an
    in-field binary to move except the coordinated cutover in §6.5.

---

## 1. Why this spec exists

sigillum exists to deliver one capability that go-tool-base could not: sign
precompiled binary artefacts in the form the Rust ecosystem verifies. The
extraction that made that possible is **complete**, and the capability itself is
**entirely unimplemented**.

**Done** (verified against `origin/main` in each repo, 2026-07-29):

| | |
|---|---|
| `go/signing-cli` extracted, props-decoupled behind `Logger` | ✅ v0.1.0 |
| sigillum attaches `sign` / `keys`, ships both backends | ✅ v0.2.1 |
| gtb re-imports `go/signing-cli`, internal copies deleted | ✅ merged (`cb73d1cf`) |
| `keys generate --algorithm ed25519\|rsa`, no implicit default (D-6) | ✅ `signing-cli/generate.go` |

**Not started.** No file in `go/signing`, `go/signing-aws-kms`, `go/signing-cli`,
sigillum, or `iac/terraform-aws-signing-kms` contains the string `minisig` or
`blake2`. `go/signing-aws-kms` is RSA-only and refuses any non-RSA KMS key.
`rtb-update`'s verifier still rejects the `ED` variant this design produces.

This spec closes that gap. It also **relocates ownership**: the design currently
lives only in go-tool-base — the repo the work was moved *out of*. sigillum owns
the capability, so sigillum owns its implementation spec.

## 2. What must be true

Two independent Rust consumers must verify **the same file** for each published
artefact:

1. **cargo-binstall** — *install-time*. Verifies a per-artefact **minisign**
   signature against the `pubkey` pinned in the crate's
   `[package.metadata.binstall.signing]`. Its signature URL is configurable via
   the `file` template.
2. **rtb-update** — *self-update*. Verifies a per-artefact Ed25519 detached
   signature against any one of `ToolMetadata::update_public_keys`
   (`Vec<[u8; 32]>`, any-one-verifies). It selects format **by extension**:
   `.minisig` → minisign parse, anything else → raw 64 bytes.

Publishing a single `<artefact>.minisig` and pointing cargo-binstall's `file`
template at it satisfies both.

## 3. Ground truth

Carried from the design spike, re-verified for this spec. The spike's own history
matters here: its **first** conclusion — that the KMS 4096-byte cap forces a
software signing key and a custody downgrade — was **wrong and is retracted**.
Do not reintroduce it.

### 3.1 The KMS message cap does not bind (the load-bearing fact)

AWS KMS `Sign` caps `Message` at 4096 bytes, and `ED25519_SHA_512` requires
`MessageType: RAW`. So minisign's **legacy / pure `Ed`** variant —
`ed25519(<whole file>)` — genuinely cannot be produced by KMS for a real archive.

The **prehashed `ED`** variant is a different shape entirely. Per the minisign
specification:

> `signature (legacy): ed25519(<file data>)` — tag **`Ed`**
> `signature (prehashed): ed25519(Blake2b-512(<file data>))` — tag **`ED`**

The `ED` signature is **ordinary Ed25519 over the 64-byte BLAKE2b-512 digest**,
computed *outside* the signer and handed in as the message. It is **not**
Ed25519ph / HashEdDSA. Therefore:

- `d = BLAKE2b-512(artefact)` → **64 bytes**, computed locally.
- `kms:Sign(Message = d, MessageType = RAW, SigningAlgorithm = ED25519_SHA_512)`
  → 64 bytes is trivially under the cap, and RAW is exactly standard Ed25519
  over the supplied message.

> **A KMS-held Ed25519 key can produce a complete minisign `ED` signature.**
> Full HSM custody is preserved: no software leaf key, no offline attestation
> root, no custody downgrade.

`ED25519_PH_SHA_512` is **never used** — it is Ed25519ph over a SHA-512 prehash
and KMS re-hashes the input. Using it would silently produce signatures neither
consumer can verify.

### 3.2 The consumers agree on `ED`

| Tag | Variant | Signed | KMS-signable |
|-----|---------|--------|--------------|
| `Ed` | legacy / pure | `ed25519(<file bytes>)` | **No** — file > 4096 B |
| `ED` | prehashed (minisign's modern default) | `ed25519(BLAKE2b-512(<file bytes>))` | **Yes** — 64-byte digest |

- **cargo-binstall requires `ED`.** Its `SIGNING.md` states *"The legacy
  signature format is not supported"*; it runs `minisign-verify` with
  `allow_legacy = false`, which returns `Error::UnexpectedAlgorithm` for `Ed`.
- **rtb-update requires `Ed` today** — `verify.rs`: `if decoded[0..2] != *b"Ed"
  { return None }`. This is the one thing we change, and we own it.

So `ED` is simultaneously cargo-binstall's mandate, the KMS-signable variant, and
the only choice that can serve both consumers with one file. There is no
trade-off to weigh.

### 3.3 The go-crypto Ed25519 gap — real, current, and bypassed

`github.com/ProtonMail/go-crypto` **v1.4.1** (checked 2026-07-29 — this is the
latest published version, not a stale pin) hard-asserts a concrete
`*ed25519.PrivateKey` in its OpenPGP Ed25519 signing branch, with no
`crypto.Signer` fall-through. An opaque KMS signer therefore cannot drive
OpenPGP-Ed25519.

This design **does not route the artefact signature through OpenPGP** — it
assembles the minisign container directly from the raw KMS signature. The gap is
documented, bypassed, and must not resurface as a blocker. It does mean a
KMS-Ed25519 signer must **refuse** `openpgpkey` with a clear typed error rather
than fail obscurely inside go-crypto (§5.2).

### 3.4 Dependency footprint

`golang.org/x/crypto` is already an indirect dependency of `go/signing` (v0.53.0)
and supplies `blake2b`. Promoting it to direct is the **only** new dependency on
the Go side. On the Rust side, rtb-update gains `blake2`.

## 4. Details the design spike left open

These are new to this spec. Each is a place the implementation can be
plausible-but-wrong, so each carries a test obligation.

### 4.1 minisign `key_id` for a KMS-held key — **derive it deterministically**

minisign's wire formats embed an 8-byte `key_id`, and `minisign-verify` rejects a
signature whose `key_id` differs from the public key's (`Error::KeyIdMismatch`).
The reference implementation generates it randomly at keygen — but a KMS key has
no keygen step we control and we want no local state to lose.

**Resolution:** derive it from the public half.

```
key_id = SHA-256(raw 32-byte Ed25519 public key)[0..8]
```

Deterministic, stateless, and reproducible by anyone holding the public key —
so a lost or rebuilt signing host recomputes the identical `key_id`, and the
published `pubkey` string can be re-derived and audited from the KMS public key
alone. It is an opaque identifier, not a security control (verification rests on
the Ed25519 key, not the ID), so a hash prefix is entirely appropriate.

The bytes are emitted **in the order produced**, with no endianness
reinterpretation. minisign's C implementation treats the field as a `uint64_t`
and prints it byte-reversed in comments; that affects only the human-readable
comment text, never the bytes on the wire. Producer and verifier compare raw
bytes, so as long as we write the same 8 bytes into both the public-key file and
every signature, both consumers agree.

**Test obligation:** a golden-file test asserting the derivation is stable, and
a round-trip asserting `minisign-verify` accepts our pubkey + signature pair
without a `KeyIdMismatch`.

### 4.2 Public-key file encoding — and the tag asymmetry

cargo-binstall pins a base64 `pubkey` string. Its body is:

```
base64( signature_algorithm(2) ‖ key_id(8) ‖ public_key(32) )   = 42 bytes
```

**The algorithm tag in the *public key* is `Ed`, even when the signatures it
verifies are `ED`.** The `Ed`/`ED` distinction describes *what was signed*, and
lives in the **signature** file. A public key tagged `ED` is not what minisign
emits and risks rejection.

This asymmetry is the single most likely source of a subtle, late-discovered
failure in this work, so it is **not** asserted here on reasoning alone.

**Test obligation:** an executable conformance test that verifies our emitted
pubkey + `.minisig` pair with `minisign-verify` at `allow_legacy = false`, plus —
where the binary is available in CI — a cross-check against upstream `minisign
-V`. If the empirical result contradicts the paragraph above, the empirical
result wins and this section is corrected.

### 4.3 The `crypto.Signer` contract for a digest-as-message signer

`go/signing`'s backends return a `crypto.Signer`. For Ed25519 the stdlib
convention is `opts.HashFunc() == crypto.Hash(0)`, meaning *"sign `message`
directly, unhashed."* That is exactly our semantics: the BLAKE2b digest **is**
the message as far as Ed25519 is concerned.

The KMS Ed25519 signer therefore:

- accepts `opts.HashFunc() == crypto.Hash(0)` and passes `message` through
  untouched as KMS's `Message` with `MessageType: RAW`;
- returns a **typed** error for any non-zero `HashFunc()` — a caller asking for
  a pre-hashed Ed25519 signature has misunderstood the scheme, and silently
  ignoring the request would produce a signature over the wrong bytes;
- returns a **typed** error when `len(message) > 4096`, naming the cap and
  pointing at the prehash — this is the guard rail that stops someone
  accidentally reintroducing whole-file signing;
- `Public()` returns `ed25519.PublicKey`.

This keeps the Ed25519 branch a peer of the RSA branch rather than a special
case, and means the minisign assembler is backend-agnostic: the **local** PEM
backend must satisfy the identical contract, so the whole path is testable
end-to-end without AWS.

### 4.4 Trusted comment and reproducibility

minisign's default trusted comment is
`timestamp:<unix>\tfile:<basename>\thashed`. We match that format for
interoperability with the upstream tooling.

The embedded timestamp makes signatures **non-reproducible by default**. The
existing `sign` command already solves this shape of problem with `--created`;
the artefact path takes the same approach — a flag pinning the trusted comment's
timestamp (and honouring `SOURCE_DATE_EPOCH` when set), so a rebuild can produce
a byte-identical `.minisig`.

The global signature's message is `signature(64 bytes) ‖ trusted_comment_bytes`,
where the comment bytes are the text **after** `trusted comment: ` with **no**
trailing newline. Off-by-one here produces a file that parses fine and fails
verification only in the global-signature check — so this needs a dedicated
test, not just an end-to-end one.

## 5. Design

### 5.1 Custody

The artefact signing key is a **KMS-held Ed25519 key**
(`ECC_NIST_EDWARDS25519`) with the *same* custody model as the existing KMS-held
RSA key: the private half never leaves the HSM boundary, the signer role is
OIDC-assumed, and the key policy is the single grant surface. No software leaf,
no attestation root (D-1).

### 5.2 Producing a `.minisig`

Per artefact:

1. `d = BLAKE2b-512(artefact)` — 64 bytes, computed locally, streamed so memory
   stays constant regardless of artefact size.
2. `S = Sign(d)` via the `crypto.Signer` — 64 bytes. *(KMS call #1.)*
3. Build the trusted comment (§4.4).
4. `G = Sign(S ‖ trusted_comment)` — the global signature. *(KMS call #2.)*
5. Emit `<artefact>.minisig`:

   ```
   untrusted comment: <text>
   base64( "ED" ‖ key_id ‖ S )
   trusted comment: <trusted_comment>
   base64( G )
   ```

Two KMS `Sign` calls per artefact, both `RAW`/`ED25519_SHA_512`, both on tiny
messages. Budget for this in the release pipeline's retry/timeout allowance and
KMS request quota when signing a wide target matrix.

Feeding a KMS **Ed25519** signer to `openpgpkey` must fail fast with a typed
error naming the go-crypto v1.4.1 limitation (§3.3) — never reach go-crypto's
type assertion.

### 5.3 Verification

- **cargo-binstall** verifies natively: `algorithm = "minisign"`,
  `pubkey = <our 42-byte base64 public key>`,
  `file = "…/<artefact>.minisig"`.
- **rtb-update** verifies the same file once its verifier accepts `ED`: parse the
  74-byte body, compute `BLAKE2b-512(artefact)`, `vk.verify(digest, &sig)`.

Because the `.minisig` is self-describing and per-artefact, rtb-update needs no
manifest path for artefacts (D-3). Its independent SHA-256 `.sum` check is
retained as defence-in-depth.

## 6. Work breakdown

Ordered by dependency. With §7's gate withdrawn, **every step below is
unblocked**; §6.1–6.3 are done.

| § | Work | State |
|---|---|---|
| 6.1 | minisign assembler in `go/signing` | **DONE** — v0.3.0 |
| 6.2 | Ed25519 branch in `go/signing-aws-kms` | **DONE** |
| 6.3 | `sign --format minisign` + `keys minisign` | **DONE** |
| 6.4 | sigillum E2E + docs | pending |
| 6.5 | `rtb-update` verifies `ED` | pending |
| 6.6 | terraform `ECC_NIST_EDWARDS25519` | pending |
| 6.7 | provision, publish, wire the pipelines | pending |
| 6.8 | cargo-binstall distribution (crate metadata + hosted artefacts) | pending |

### 6.1 `go/signing` — the minisign assembler *(new sub-package)*

A `minisign` sub-package, backend-agnostic, driven by any `crypto.Signer` whose
`Public()` is an `ed25519.PublicKey`:

- streaming BLAKE2b-512 digest of an `io.Reader`;
- `key_id` derivation (§4.1);
- public-key encoding/decoding (§4.2), so `keys` can emit the string
  cargo-binstall pins;
- `.minisig` assembly (§5.2) with pinnable trusted-comment timestamp (§4.4);
- a **verifier** for the `ED` variant, including the global-signature check —
  needed for our own conformance tests and useful to `go/signing/verify`.

**No raw-64-byte `.sig` sink** *(decided 2026-07-29, superseding the spike)*. It
would have no supported consumer — D-3 removes raw-64-byte acceptance from
rtb-update — and it is pure Ed25519 over the whole file, which KMS physically
cannot produce (>4096 bytes), making it software-key-only and so ruled out by the
custody model. Building it would ship a sink producing files nothing verifies.

Promote `golang.org/x/crypto` to a direct dependency. Keep the OpenPGP path
untouched.

**Tests:** golden `.minisig` files; global-signature message-construction test
(§4.4); `key_id` stability; round-trip sign→verify against a software Ed25519
key so the whole path runs without AWS; conformance against `minisign-verify`
semantics (§4.2); constant-memory assertion on a large input.

### 6.2 `go/signing-aws-kms` — the Ed25519 branch *(additive)*

- accept `ECC_NIST_EDWARDS25519`; type-switch on the parsed public key instead of
  the current unconditional `*rsa.PublicKey` assertion (`signer.go:70`);
- `Public()` → `ed25519.PublicKey`; `Sign()` → `ED25519_SHA_512` / `RAW`;
- the typed errors and contract from §4.3;
- confirm empirically that KMS returns the Ed25519 signature as **raw 64 bytes**
  (`R ‖ S`), not DER-wrapped. AWS documents DER only for the ECDSA algorithms,
  but a DER wrapper would break both consumers, so this is verified, not assumed;
- RSA behaviour byte-for-byte unchanged;
- **correct the three stale comments** asserting KMS has no Ed25519 —
  `awskms.go:45-46`, `awskms.go` `ErrUnsupportedKMSKeyType` text, `signer.go:51`.
  They are now actively misleading.

### 6.3 `go/signing-cli` — expose it

- `sign` gains `--format openpgp|minisign|raw` (default `openpgp`, preserving
  today's behaviour exactly);
- `--format minisign` requires an Ed25519 signer and defaults `--output` to
  `<input>.minisig`;
- the trusted-comment timestamp flag (§4.4);
- `keys` gains a way to emit the minisign-format public key for a configured
  signer — the string pasted into `[package.metadata.binstall.signing]` and
  derived into rtb-update's `update_public_keys`;
- flag combinations that cannot work (`--format minisign` with an RSA key;
  `--format openpgp` with a KMS Ed25519 key, §3.3) fail with actionable errors.

### 6.4 sigillum — expose and prove

The commands arrive automatically via `go/signing-cli`. What sigillum owes:

- **E2E coverage — the repo currently has zero test files.** Gherkin/Godog
  scenarios per the ecosystem convention: sign an artefact with a local Ed25519
  key, verify the `.minisig`, assert the pubkey encoding, assert reproducibility
  under a pinned timestamp, assert the error paths in §6.3.
- Docs: a how-to for signing a release artefact for cargo-binstall + rtb-update,
  with the `[package.metadata.binstall.signing]` snippet; update the existing
  `docs/how-to/sign-a-release-artefact.md` and the `sign` reference page.

### 6.5 `rust/cli` — `rtb-update` verifies `ED` *(unblocked — §7 gate withdrawn)*

`crates/rtb-update/src/verify.rs`: accept the `ED` tag, compute BLAKE2b-512
before `vk.verify`, add the `blake2` dependency. Per D-3 the end state is
**`ED`-only** — legacy pure-`Ed` and raw-64-byte acceptance removed, per-artefact
manifest dropped.

Because nothing has ever been published (§8, OQ-1), this goes straight to the end
state: **no accept-both transition step**, and no coordination with the rekey.
Update the module docs (they currently document `Ed`-only as deliberate) and
rust-tool-base's `docs/how-to/secure-releases.md`, which still describes *"an
Ed25519 detached signature over the archive."*

### 6.6 `iac/terraform-aws-signing-kms` — allow the key spec

Add `ECC_NIST_EDWARDS25519` to the `key_spec` validation list (`variables.tf:26`)
and rewrite the variable description, which currently asserts *"AWS KMS does not
expose Ed25519 for asymmetric signing"* — false since the Edwards-curve GA.
Document Ed25519 as preferred for new signing keys with RSA_4096 retained.
Confirm the OIDC signer role's `kms:Sign` grant is algorithm-agnostic.

### 6.7 Provision and publish

Mint the artefact-signing KMS Ed25519 key; publish its minisign public key;
wire `.minisig` emission into the release pipelines; pin the key in
cargo-binstall metadata (§6.8) and rtb-update's `update_public_keys`; add the
end-to-end test that a published `.minisig` verifies under both a
`minisign-verify` (`allow_legacy = false`) check and an
`ed25519-dalek` + BLAKE2b-512 check.

**Order matters here.** The public key must be final before the first crate
version carrying it is published, because that pin is immutable (OQ-2).

### 6.8 cargo-binstall distribution

Serving cargo-binstall (OQ-2) is a distribution change as well as a signing one,
and the mechanism is easy to picture wrongly:

> **crates.io hosts source, not binaries.** Publishing a crate does not publish a
> compiled artefact. cargo-binstall reads `[package.metadata.binstall]` from the
> *published crate*, which templates a **URL pointing at wherever the prebuilt
> archives and their signatures are actually hosted** — for us, GitLab release
> assets or the generic package registry. So "publishing signed binaries to
> crates.io" is, concretely: **binaries and `.minisig` files go to GitLab; the
> crate on crates.io carries the metadata that points at them.**

The work is therefore:

1. **Host the artefacts.** Publish each target's archive and its `<archive>.minisig`
   at a stable, templatable URL. The existing release pipeline already publishes
   archives; this adds the signature beside each one.
2. **Add `[package.metadata.binstall]`** to each binary crate (`rtb-cli-bin`
   today) — `pkg-url`, `pkg-fmt`, `bin-dir`, and a `signing` table carrying
   `algorithm = "minisign"` and the `pubkey` from `keys minisign`. Point the
   signature `file` template at the published `.minisig` so **one file serves
   cargo-binstall and rtb-update both** (§2).
3. **Publish the crate version** carrying that metadata. From this point the
   `pubkey` is pinned for that version forever.

**Two consequences to confirm before the first publish**, since both are
operational rather than cryptographic and neither is settled by this spec:

- **Key rotation.** Versions published under the old `pubkey` keep pinning it.
  Rotating the artefact key does not retroactively change them, so either the old
  public key stays valid for those versions' artefacts, or those versions stop
  being binstall-installable. Decide which before the key is minted, because it
  shapes how long a retired artefact key must remain published.
- **Failure behaviour.** Confirm empirically what cargo-binstall does when
  signature verification fails — whether it falls back to building from source or
  fails hard. That determines the blast radius of a signing mistake, and it should
  be observed rather than assumed.

## 7. Sequencing — no gate remains (WITHDRAWN 2026-07-29)

An earlier revision of this section argued that D-3's `ED`-only break had to be
deferred to the rekey's B3 window closure. **OQ-1 (§8) has since been settled
empirically, and it removes the premise that argument rested on.**

The reasoning was: D-3 justified an `ED`-only clean break by *"riding the Friday
rekey"* so that `Ed`→`ED` adds *"no incremental breakage — one clean break, not
two"*, which requires both breaks to land simultaneously. With the v2 keys
already published and the dual-sign window open, they would not — so switching
producers to `ED`-only would land a second break on binaries mid-migration.

**That population does not exist.** No release has ever published an artefact
signature of any kind (§8, OQ-1), and rtb-update's self-update fails closed when
`update_public_keys` is empty — which it always has been. There is no deployed
binary that can verify an artefact signature today, so there is nothing for a
cutover to break.

**Consequently:**

- **All remaining work is unblocked**, including §6.5's `ED`-only removal. There
  is no need to ship an accept-both transition step, and no coordination with the
  rekey's B3 closure.
- **The artefact path starts from a clean slate.** `ED`-only can be the first and
  only form ever published, so no legacy acceptance is inherited into the
  verifier.
- **The rekey remains relevant only to the OpenPGP manifest path**, which this
  spec does not change.

D-3's decision stands unchanged and is now simply cheaper than it looked.

## 8. Open questions

- **OQ-1 — Has any release ever shipped a pure-`Ed` `.minisig` or a raw-64-byte
  `.sig`? RESOLVED (2026-07-29) — no. Nothing has ever been published.**

  Checked across every distribution channel, over all 99 projects in the
  `phpboyscout` group:

  | Evidence | Result |
  |---|---|
  | GitLab release assets, all projects (808 asset links) | **zero** `.minisig`; **zero** `.sig` other than `checksums.txt.sig`; **zero** `.sum` |
  | `rust-tool-base` releases (82 of them) | **zero** asset links — source-only crate tags |
  | GitLab package registry for `rust-tool-base`, `rust/cli`, `rust/app` | no packages |
  | `[package.metadata.binstall]` in the published `rtb-cli-bin` v0.8.0 | **absent** — the only cargo-binstall references are CI *using* it to install `cargo-semver-checks` |
  | `update_public_keys` populated anywhere | **never** — only type definitions and docs |

  The crates *are* published to crates.io (`rtb-cli-bin` 0.8.0, `rtb-update`
  0.7.1 and others), but with no binstall metadata cargo-binstall builds from
  source rather than fetching a signed binary. And rtb-update's
  `preflight_required_fields` returns `NoPublicKey` when `update_public_keys` is
  empty — it **fails closed**, so signed self-update has never been operable.

  Every existing signature in the wild is a `checksums.txt.sig` on the OpenPGP
  manifest path, which this spec does not touch.

  **Consequence:** §7's rekey gate is withdrawn, no accept-both transition step
  is needed, and `ED`-only can be the first and only artefact signature form
  ever published.

- **OQ-2 — Is cargo-binstall a served target? RESOLVED (2026-07-29) — yes.**
  Distributing signed binaries to Rust users via cargo-binstall is the stated
  goal of this programme, not an optional extra. It is therefore a first-class
  target from the first published signature, and §6.7 carries the work (§6.8).

  **This makes the public-key encoding a permanent compatibility surface.** A
  crates.io version is immutable, so the `pubkey` string baked into a published
  crate is pinned forever for that version. Both the `key_id` derivation (§4.1)
  and the public-key encoding (§4.2) are frozen the moment the first crate
  version carrying a `pubkey` is published — after that, changing either breaks
  `cargo binstall` for every version already out there. Get them right before the
  first publish; they cannot be retrofitted.

- **OQ-3 — Does `keys generate --algorithm ed25519` need a minisign output
  mode?** Today it emits an armored OpenPGP public half and a software private
  key. A local Ed25519 key is the natural way to test and demo the artefact path
  without AWS (and §6.1's tests need one). Emitting the minisign key pair format
  alongside would make sigillum genuinely useful for projects that do not have a
  KMS at all — a plausible scope expansion worth deciding deliberately rather
  than by omission.

## 9. Acceptance criteria

- [ ] `go/signing` emits a spec-correct prehashed `ED` `.minisig` from any
      Ed25519 `crypto.Signer`, with a streaming digest and constant memory.
- [ ] The emitted pubkey + `.minisig` pair verifies under `minisign-verify`
      semantics at `allow_legacy = false`, proven by an executable conformance
      test — not by inspection (§4.2).
- [ ] `key_id` derivation is deterministic, documented, and golden-tested (§4.1).
- [ ] Signing twice with a pinned timestamp yields byte-identical `.minisig`
      files.
- [ ] `go/signing-aws-kms` signs with a KMS `ECC_NIST_EDWARDS25519` key, returns
      raw 64-byte signatures (**verified against live KMS, not assumed**), errors
      typed-ly above 4096 bytes and on a non-zero `HashFunc()`, and leaves the
      RSA path byte-for-byte unchanged.
- [ ] No stale "KMS does not expose Ed25519" claim remains in `go/signing-aws-kms`
      or `terraform-aws-signing-kms`.
- [ ] `sigillum sign --format minisign` produces a file that verifies under both
      an `ed25519-dalek` + BLAKE2b-512 check and a `minisign-verify` check.
- [ ] `sigillum sign` with no `--format` behaves exactly as v0.2.1 does today.
- [ ] sigillum has E2E coverage for the signing workflows (from zero today).
- [ ] `rtb-update` verifies a sigillum-produced `.minisig`; the `ED`-only removal
      lands per §7's sequencing.
- [ ] The `key_id` derivation and public-key encoding are final **before** the
      first crate version carrying a `pubkey` is published — they are immutable
      thereafter (OQ-2).
- [ ] One `.minisig` per artefact serves both consumers: cargo-binstall's `file`
      template and rtb-update's asset resolver point at the same file.
- [ ] A published artefact is verified end-to-end by a real `cargo binstall` and
      a real `rtb-update` self-update.
