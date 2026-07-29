---
title: "Bootstrap sigillum: a standalone signing & verification CLI over go/signing"
description: "sigillum is a pure CLI — a gtb-generated application that exposes the phpboyscout ecosystem's artefact signing and verification commands (sign, keys) as first-class top-level commands. The real logic already lives in gitlab.com/phpboyscout/go/signing and its backend modules; today the cobra command builders are gtb-internal (internal/cmd/sign, internal/cmd/keys) and coupled to gtb's Props container. This spec records the completed repo bootstrap and defines the roadmap: extract the command builders into a new tiny gitlab.com/phpboyscout/go/signing-cli module (props-decoupled), attach them in sigillum, and re-attach them in gtb — dropping gtb's internal copies. That removes duplication and the module-cycle risk, since go/signing-cli depends only on go/signing + cobra, never on gtb or sigillum."
status: IMPLEMENTED
date: 2026-07-28
tags:
  - specification
  - sigillum
  - signing
  - cli
  - architecture
  - bootstrap
author:
  - name: Matt Cockayne
    email: matt@phpboyscout.uk
  - name: Claude Fable 5
    role: AI drafting assistant
---

# Bootstrap sigillum: a standalone signing & verification CLI over go/signing

Authors
:   Matt Cockayne, Claude Fable 5 *(AI drafting assistant)*

Date
:   2026-07-28

Status
:   IMPLEMENTED (2026-07-29) — all four phases are done and verified on
    `main` across the three repos; the only outstanding acceptance criterion
    is sigillum's E2E coverage (§6), which moves to the implementation spec
    that follows this one. The **capability** this extraction was performed
    to enable — KMS-Ed25519 minisign artefact signing — is specified
    separately in
    [`2026-07-29-kms-ed25519-minisign-artifact-signing.md`](2026-07-29-kms-ed25519-minisign-artifact-signing.md).

Related
:   go-tool-base spec `2026-07-28-ed25519-kms-signing.md` (the #5 design spike —
    KMS-custody-preserving signing; carries decisions D-2..D-6 this project
    consumes; **merged to gtb `main` in `c958c890`**),
    [`2026-07-29-kms-ed25519-minisign-artifact-signing.md`](2026-07-29-kms-ed25519-minisign-artifact-signing.md)
    (this repo — the implementation spec that delivers D-2..D-6, and the owner
    of that design going forward),
    `gitlab.com/phpboyscout/go/signing` and `go/signing-aws-kms` (the logic
    these commands drive)

---

## 1. Purpose & context

The phpboyscout ecosystem signs and verifies release artefacts. The signing
*logic* is already an extracted, reusable module family —
`gitlab.com/phpboyscout/go/signing` (v0.2.2) with backends such as
`go/signing-aws-kms` (v0.2.5) and helpers `go/signing/openpgpkey`,
`go/signing/verify`. What is **not** shared is the *command surface*: the cobra
commands that expose signing to operators live inside go-tool-base as
`internal/cmd/sign` and `internal/cmd/keys`, private to gtb and wired to gtb's
`Props` DI container.

gtb is deliberately *both* a library and a CLI, so hosting these commands
internally made sense while gtb was the only consumer. sigillum changes that:
it is a **pure CLI** whose entire reason to exist is signing/verification, and
it should own the top-level `sign` / `keys` commands as first-class citizens
with all real work delegated to `go/signing`. Copying gtb's internal commands
into sigillum would duplicate them; importing gtb wholesale would pull the
entire framework and risk a module cycle if gtb ever needs a sigillum-side
capability. The resolution is a small shared command module (§3).

## 2. Phase 0 — repo bootstrap (DONE)

Completed and verified on 2026-07-28:

- **Generated** with the current gtb generator (post the generator-template
  version-tracking fix), so every pin is at head — no manual patching:
  `gtb generate project --name sigillum --repo phpboyscout/sigillum
  --host gitlab.com --git-backend gitlab --features
  init,update,docs,doctor,changelog,keychain,config`.
- **Pins at head:** phpboyscout/cicd components v0.33.0, releaser-pleaser
  v0.9.0, pre-commit golangci-lint v2.12.2 / pre-commit-hooks v6.0.0, Go
  toolchain from the build environment, `go-tool-base` v0.33.0.
- **Dependencies refreshed** (`go get -u ./... && go mod tidy`) to latest.
- **Builds and runs:** `go build ./...` clean; the `sigillum` binary lists the
  scaffolded commands (`init`, `update`, `docs`, `doctor`, `changelog`,
  `config`, `version`). Repo git-initialised; scaffold committed.

The `sign` / `keys` commands were **not** present at bootstrap — they arrived in
Phase 2 (see §4, all phases now complete).

## 3. Target architecture

```
                    gitlab.com/phpboyscout/go/signing   (logic: sign, verify,
                          ▲            ▲                  openpgpkey, backends)
                          │            │
        gitlab.com/phpboyscout/go/signing-aws-kms  (KMS backend)
                          ▲
                          │  (real work)
        gitlab.com/phpboyscout/go/signing-cli   ← NEW tiny module
              (cobra command builders: sign, keys {generate,mint,wkd};
               props-decoupled — depends only on go/signing + cobra)
                     ▲                    ▲
                     │ attach             │ re-attach (drops internal copies)
              sigillum (pure CLI)    go-tool-base (library + CLI)
```

**`go/signing-cli` is a new, dedicated, tiny module** (decision below). It holds
*only* the cobra command constructors and their flag wiring. It must **not**
import gtb's `props` package. Because it depends only on `go/signing` (+ cobra),
there is no path back to gtb or sigillum, so no module cycle is possible.

**The `Deps` seam — resolved (from the current gtb code).** The coupling turns
out to be tiny: the command *logic* functions already take only
`props.LoggerProvider`, and the sole logger methods called across `sign` and
all of `keys` are `Info` and `Warn`. The only other gtb type in play is the
`*setup.Command` return type (gtb's feature-middleware wrapper). So:

- `go/signing-cli` declares its own narrow logger interface — a slog-shaped
  subset, `Logger interface { Debug/Info/Warn/Error(msg string, args ...any) }`.
  gtb's `logger.Logger` and sigillum's logger both satisfy it **structurally**;
  no adapter, no gtb import.
- Constructors take that `Logger` and return **plain `*cobra.Command`**, not
  `*setup.Command`. The gtb-specific `setup.Wrap` stays **caller-side**:
  - gtb: `setup.Wrap("", signingcli.NewCmdSign(p.GetLogger()))`;
  - sigillum: attaches the returned `*cobra.Command` directly to its root.
- `go/signing-cli` imports only cobra, pflag, `go/signing`, `go/signing-aws-kms`.

This makes the extraction a near-mechanical move plus a return-type/param change,
not a redesign.

### Command surface to share (as it exists in gtb today)

| Command | Purpose |
|---------|---------|
| `sign <input-file>` | Produce an ASCII-armored OpenPGP detached signature via a configured backend |
| `keys` | Manage OpenPGP keys for release-binary signing (parent) |
| `keys generate` | Generate a fresh keypair locally (Ed25519 or RSA), emit both halves |
| `keys mint` | Mint an ASCII-armored OpenPGP public key from an existing signer |
| `keys wkd <public-key.asc>...` | Generate a Web Key Directory tree from public keys |

All five already call into `go/signing` / `go/signing/openpgpkey` /
`go/signing/verify`; the extraction moves the *cobra wrappers*, not the logic.

## 4. Roadmap

**All four phases are complete as of 2026-07-29** — `go/signing-cli` v0.1.0,
sigillum v0.2.1, and gtb's re-attachment (merged in `cb73d1cf`, with
`internal/cmd/{sign,keys}` deleted). The KMS-Ed25519 → prehashed-minisign sink
referenced in Phase 1 was correctly deferred and now has its own spec
([`2026-07-29-kms-ed25519-minisign-artifact-signing.md`](2026-07-29-kms-ed25519-minisign-artifact-signing.md)),
which also revises that spec's rekey gating.

- **Phase 0 — bootstrap** (DONE, §2).
- **Phase 1 — `go/signing-cli` module** (DONE — v0.1.0). Create the repo (per the module
  extraction playbook: public, `<name>.go.phpboyscout.uk` docs, cicd at head).
  Move the command builders out of gtb's `internal/cmd/{sign,keys}`, decoupling
  them via the resolved `Deps` seam above (narrow `Logger` interface;
  constructors return `*cobra.Command`; `setup.Wrap` moves caller-side). Port
  the existing tests. The KMS-Ed25519 → prehashed-minisign sink from #5 lands
  here (or in `go/signing`) as the follow-on; it is gated on the rekey.
- **Phase 2 — sigillum attaches** (DONE — v0.2.1; E2E coverage still
  outstanding). Depend on `go/signing-cli`; attach `sign`
  and `keys` to sigillum's root; provide sigillum's adapter for the `Deps`
  seam; add E2E/Gherkin coverage for the signing workflows.
- **Phase 3 — gtb re-attaches** (DONE — `cb73d1cf` on gtb `main`). Replace gtb's `internal/cmd/{sign,keys}` with
  `go/signing-cli` attachments through a Props→Deps adapter; delete the
  internal command packages; keep gtb's behaviour byte-compatible for its
  users. (Extraction cut-over ⇒ `feat`, not `refactor`, so releaser-pleaser
  cuts a release — see the ecosystem convention.)

## 5. Decisions (all resolved 2026-07-28)

- **Name** — `sigillum` (wax-seal theme, market-checked). [#5 D-4]
- **`sign`/`keys` command home** — a dedicated tiny `go/signing-cli` module
  (not gtb `pkg/`, not duplicated), props-decoupled.
- **D-2 — minisign format: prehashed "ED".** Producers emit the prehashed
  **"ED"** form (`ed25519(BLAKE2b-512(<file>))` — a 64-byte digest, within
  KMS's 4096-byte RAW Sign limit, so HSM custody is preserved) and never pure
  "Ed". "ED" is also the form cargo-binstall requires. Two KMS Sign calls per
  artefact (main signature over the digest + the minisign global signature).
- **D-3 — rtb-update: "ED"-only, clean break, drop the manifest.**
  `verify.rs` accepts only prehashed "ED" (legacy pure-"Ed" and raw-64-byte
  acceptance removed); the separate manifest goes away, so a single
  self-describing `.sig` serves both rtb-update and cargo-binstall.
  **Sequencing:** an "ED"-only producer switch means already-deployed
  "Ed"-only binaries cannot self-update across the cutover. This is coordinated
  with the **Friday rekey**, which is *itself* a hard trust-root cutover
  (deployed binaries pin the old public keys and cannot verify new-key
  signatures regardless of Ed/ED). Doing Ed→ED in the same rotation therefore
  adds **no incremental breakage** — one clean break, not two. The ED-capable
  rtb-update ships as part of the rekeyed release set; anyone on a pre-rekey
  binary re-establishes trust and reinstalls once, as the rekey already
  requires.
- **D-5 — key rotation.** Held; Matt completes the prod rebuild/rekey himself
  (Friday window). Now also the coordination point for the D-3 cutover.
- **D-6 — key-generation algorithm: no implicit default.** `keys generate`
  requires an explicit `--algorithm ed25519|rsa` (or config equivalent) and
  errors, listing valid choices, when unset — no silent default, an
  informed-choice posture appropriate to a signing tool. (Signing with an
  existing key needs no choice; the algorithm is fixed by the key.)

## 6. Acceptance criteria

- [x] sigillum generated from the current generator, all pins/deps at head,
      builds and runs.
- [x] `go/signing-cli` exists, props-decoupled, with the five commands and
      their ported tests green; docs microsite live. *(v0.1.0)*
- [x] sigillum exposes `sign` and `keys` at the top level, delegating entirely
      to `go/signing`. *(v0.2.1)*
- [ ] **…with E2E coverage.** Outstanding — sigillum has no test files. Carried
      into the implementation spec (§6.4 there).
- [x] gtb re-attaches the shared commands and deletes
      `internal/cmd/{sign,keys}` with no user-visible behaviour change.
      *(`cb73d1cf`)*
- [x] No module cycle: `go/signing-cli`'s `go.mod` requires `go/signing` only —
      no gtb, no sigillum, and not even a backend module (backends are
      blank-imported by the host binary).
