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
gtb, a framework that is deliberately both a library and a CLI. That was fine
while gtb was the only consumer, but it meant you could only get a `sign` /
`keys` command surface by building a whole gtb application.

sigillum exists to remove that constraint. It exposes `sign` and `keys` as
**top-level** commands rather than sub-commands of a larger app. It has since
gained `decrypt` and `certificate`, its own commands for the other job a
project's keys do: receiving encrypted vulnerability reports.

Signing, note, and not verifying: there is no `sigillum verify`. The
verification half of `go/signing` is linked in (sigillum's own `update` command
uses it to check the release it downloads), but it is not exposed as a command.
[What sigillum does not do](../what-sigillum-does-not-do.md) covers why, and
what to use instead.

The practical payoff is for **non-Go and non-gtb release pipelines**. A Rust
project, a shell-driven release, or any CI job that just needs to produce and
publish OpenPGP or minisign signatures can `go install` (or download) one
binary and sign. There is no framework build, no gtb dependency, and no bespoke
signing script to maintain.

sigillum holds no signing logic of its own. All of it stays in `go/signing`,
shared with gtb, so the two tools cannot drift in how they sign. See
[Components & architecture](../components/index.md) for the module stack.

## The build-time backend model

A signing backend (AWS KMS, local PEM, or a third party) implements
`go/signing`'s `crypto.Signer`-based contract and **registers itself** in that
module's registry. The command layer never hard-codes a backend; `--backend`
selects a registered one, and `sigillum sign --help` lists whichever
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

There are two registries rather than one because the two sides want different
things from a backend. A signing backend supplies a `crypto.Signer`. An
encryption backend must derive a shared secret from a sender's ephemeral point
and hand back its own public half so a certificate can be published. A signing
backend has no reason to implement either. Merging them would let `--backend` offer a
name that cannot serve the command it was passed to.

The same build-time property holds on both sides, and independently: a build can
carry AWS KMS for signing and local PEM only for encryption, or drop either side
entirely.

This model also limits what a build can reach. A **regulated or hardened
build** can drop a blank import (remove the AWS KMS line, say) and rebuild. The
Go linker's dead-code elimination then keeps that backend's SDK, and its
transitive dependencies, out of the linked binary. The backend set is a
compile-time decision, not a runtime flag that configuration could toggle. (sigillum uses the same pattern for OS-keychain support via
`cmd/sigillum/keychain.go`.)
