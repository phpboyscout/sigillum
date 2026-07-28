---
title: Components & architecture
description: How sigillum is assembled — the module stack from the sigillum CLI down through go/signing-cli to go/signing and its backends, and where each responsibility lives.
date: 2026-07-28
tags: [explanation, architecture, signing, cli]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Components & architecture

sigillum is a thin composition layer. Its job is to *assemble* the signing
command surface and *ship* the backends — not to implement signing. Everything
substantive lives in upstream modules.

## The module stack

```
sigillum  (this repo — a gtb-generated pure CLI)
   │  attaches the commands to its root; blank-imports the backends
   │
   ├─ gitlab.com/phpboyscout/go/signing-cli
   │     the cobra command builders: sign, keys {generate, mint, wkd}
   │     depends only on go/signing + cobra/pflag — no gtb, no sigillum
   │        │
   │        └─ gitlab.com/phpboyscout/go/signing
   │              all signing & verification logic; the crypto.Signer
   │              backend registry; helpers go/signing/openpgpkey (packet
   │              assembly, WKD) and go/signing/verify (client-side checks)
   │
   ├─ gitlab.com/phpboyscout/go/signing-aws-kms   AWS KMS backend
   └─ gitlab.com/phpboyscout/go/signing/local     local PEM backend
```

Read that top to bottom: **sigillum → go/signing-cli → go/signing (+ backends)**.

## Who owns what

**`go/signing`** — the logic. Signing, verification, the OpenPGP packet
assembly (`openpgpkey`), the WKD tree writer, and the `crypto.Signer` backend
registry. A backend registers itself here; the command layer never hard-codes
one.

**`go/signing-cli`** — the command surface, and *only* that. It holds the cobra
constructors (`NewCmdSign`, `NewCmdKeys`) and their flag wiring, and delegates
every real operation to `go/signing`. It depends on `go/signing`, cobra, and
pflag — deliberately nothing else. It defines its own minimal `Logger`
interface (`Debug`/`Info`/`Warn`/`Error(msg string, args ...any)`) that both a
`*slog.Logger` and gtb's logger satisfy structurally, so it needs no adapter and
never imports gtb's `props` container. The constructors return plain
`*cobra.Command` values, leaving any framework-specific wrapping to the caller.

**sigillum** — the composition. It is a gtb-generated application, but its root
command attaches the `sign` and `keys` commands from `go/signing-cli` as
**top-level** commands:

```go
rootCmd := gtbRoot.NewCmdRoot(p,
    setup.Wrap("", signingcli.NewCmdSign(p.GetLogger())),
    setup.Wrap("", signingcli.NewCmdKeys(p.GetLogger())),
)
```

It also blank-imports the backends it ships (see
[Concepts](../concepts/index.md)), so those backends register themselves in
`go/signing`'s registry at startup and appear as valid `--backend` values.

## Why the command layer is a separate module

The command builders could have lived inside gtb (where they originated as
`internal/cmd/{sign,keys}`) or been copied into sigillum. Both were rejected:

- Copying into sigillum would **duplicate** the commands and their tests.
- Importing gtb wholesale would pull the entire framework into a tool whose only
  job is signing, and risk a **module cycle** if gtb ever needed something from
  sigillum.

Extracting the builders into a tiny, props-decoupled `go/signing-cli` module
solves both: gtb and sigillum both attach the *same* commands, and because
`go/signing-cli` depends only on `go/signing` there is no path back to gtb or
sigillum — no cycle is possible. `go mod graph` shows `go/signing-cli`
depending on `go/signing` only.

## No cycle, by construction

The dependency arrows only ever point *down* the stack. sigillum and gtb both
sit at the top and depend on `go/signing-cli`; neither is depended on by
anything below. That is what lets the same command code serve a full framework
CLI (gtb) and a single-purpose CLI (sigillum) without either constraining the
other.
