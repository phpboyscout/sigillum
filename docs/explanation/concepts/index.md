---
title: Concepts
description: Why sigillum is a standalone CLI separate from gtb, and how the build-time backend blank-import model decides which signing and encryption backends a binary carries.
date: 2026-07-28
tags: [explanation, concepts, signing, encryption, backends]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Concepts

## Why a separate, standalone CLI

The signing *logic* has been a reusable module family for a while
(`go/signing` and its backends). The signing *commands*, however, lived inside
gtb — a framework that is deliberately both a library and a CLI. That was fine
while gtb was the only consumer, but it meant you could only get a `sign` /
`keys` command surface by building a whole gtb application.

sigillum exists to remove that constraint. Its entire reason to be is signing,
so it makes `sign` and `keys` the **whole tool**, exposed as top-level commands
rather than sub-commands of a larger app.

Signing, note, and not verifying: there is no `sigillum verify`. The
verification half of `go/signing` is linked in — sigillum's own `update` command
uses it to check the release it downloads — but it is not exposed as a command.
[What sigillum does not do](../what-sigillum-does-not-do.md) covers why, and
what to use instead.

The practical payoff is for **non-Go and non-gtb release pipelines**. A Rust
project, a shell-driven release, or any CI job that just needs to produce and
publish OpenPGP signatures can `go install` (or download) one small binary and
sign — with no framework build, no gtb dependency, and no bespoke signing
script. It is a purpose-built utility, sized to one job.

Keeping sigillum thin is what makes this honest: it holds no signing logic of
its own. All of that stays in `go/signing`, shared with gtb, so the two tools
can never drift in how they sign. See
[Components & architecture](../components/index.md) for the module stack.

## The build-time backend model

A signing backend (AWS KMS, local PEM, or a third party) implements
`go/signing`'s `crypto.Signer`-based contract and **registers itself** in that
module's registry. The command layer never hard-codes a backend; `--backend`
simply selects a registered one, and `sigillum sign --help` lists whichever
backends are present.

Which backends a given binary carries is decided **at build time** by blank
imports in sigillum's `main` package:

```go
// cmd/sigillum/signing.go
import (
    _ "gitlab.com/phpboyscout/go/signing-aws-kms"
    _ "gitlab.com/phpboyscout/go/signing/local"
)
```

Each blank import runs the backend package's `init`, which registers it. sigillum
ships the full set: **AWS KMS + local PEM**.

### The encryption side has its own registry

`decrypt` and `certificate` resolve `--backend` against a **separate** registry
in `go/encryption`, populated by a separate file:

```go
// cmd/sigillum/encryption.go
import (
    _ "gitlab.com/phpboyscout/go/encryption-aws-kms"
    _ "gitlab.com/phpboyscout/go/encryption/local"
)
```

Two registries rather than one, because the two sides want different things from
a backend. A signing backend supplies a `crypto.Signer`. An encryption backend
must derive a shared secret from a sender's ephemeral point *and* hand back its
own public half so a certificate can be published — neither of which a signing
backend has any reason to implement. Merging them would let `--backend` offer a
name that cannot serve the command it was passed to.

The same build-time property holds on both sides, and independently: a build can
carry AWS KMS for signing and local PEM only for encryption, or drop either side
entirely.

This model has a security dividend. A **regulated or hardened build** can drop a
blank import — say, remove the AWS KMS line and rebuild. The Go linker's
dead-code elimination then keeps that backend's SDK (and its transitive
dependencies) entirely out of the linked binary. The backend set is thus a
compile-time policy decision, not a runtime flag that could be toggled by
config. (sigillum uses the same pattern for OS-keychain support via
`cmd/sigillum/keychain.go`.)
