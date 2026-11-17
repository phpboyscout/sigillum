---
title: Components & architecture
description: How sigillum is assembled, from the sigillum CLI down to go/signing, go/signing-sigstore and their backends, and where each responsibility lives.
date: 2026-07-28
tags: [explanation, architecture, signing, cli]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Components & architecture

On the signing side sigillum is a thin command layer. It owns the `sign` and
`keys` commands and ships the backends, but it does not implement signing.
The decryption side is not empty: `internal/openpgp` holds the code that reads
an OpenPGP message, which exists nowhere upstream. Everything else of substance
lives in upstream modules.

## The module stack

```
sigillum  (this repo: a gtb-generated CLI)
   │  owns the commands in pkg/cmd; blank-imports the backends
   │
   ├─ sign, keys {generate, generate-image, mint, wkd, minisign, publish}
   │     └─ gitlab.com/phpboyscout/go/signing
   │           all signing & verification logic; the crypto.Signer
   │           backend registry; helpers go/signing/openpgpkey (packet
   │           assembly, WKD), go/signing/keyfile (key-file writes) and
   │           go/signing/verify (client-side checks)
   │
   ├─ sign image
   │     └─ gitlab.com/phpboyscout/go/signing-sigstore
   │           cosign signature and Sigstore bundle, pushed to the registry
   │
   ├─ gitlab.com/phpboyscout/go/signing-aws-kms   AWS KMS backend
   └─ gitlab.com/phpboyscout/go/signing/local     local PEM backend
```

The encryption side sits beside it and is covered under
[Who owns what](#who-owns-what) below.

Read that top to bottom: **sigillum → go/signing (+ go/signing-sigstore for
images) → backends**.

## Who owns what

**`go/signing`** holds the logic. Signing, verification, the OpenPGP packet
assembly (`openpgpkey`), the WKD tree writer, the key-file writer
(`keyfile`), and the `crypto.Signer` backend registry. A backend registers
itself here, and the command layer never hard-codes one.

**`go/signing-sigstore`** signs container images. It takes a
`crypto.Signer` from the same registry, so an image is signed by the same
backends as a file, and it pushes the signature in both cosign forms.

**sigillum** owns the commands. Its root attaches four top-level commands from
its own `pkg/cmd`: `sign`, `keys`, `decrypt` and `certificate`. From
`pkg/cmd/root/cmd.go`:

```go
rootCmd := gtbRoot.NewCmdRoot(p, decrypt.NewCmdDecrypt(p), certificate.NewCmdCertificate(p), sign.NewCmdSign(p), keys.NewCmdKeys(p))
```

The signing commands share `internal/signcmd`. It turns each backend's settings
into flags, resolves `--backend` to a signer, and writes key files with the
`--force` hint in the refusal. Each command's handler parses its flags, calls
`go/signing` or `go/signing-sigstore`, and reports the result.

The `sign` and `keys` commands began in gtb and were then moved into a separate
`go/signing-cli` module, so that gtb and sigillum could share them. sigillum
spec 0007 moved them here. gtb is dropping its copies, and `go/signing-cli` is
deprecated. Their error texts and error kinds are unchanged, so a log filter
written against the old commands still matches.

The split is deliberate and it is not symmetric. Signing logic is entirely
upstream, so sigillum's signing commands only parse, resolve and write.
Decryption is not:
`internal/openpgp` (message framing, the walk over candidate recipients, the
size and compression bounds) lives here, because it exists nowhere upstream and
`go/encryption` deliberately stops at the packet and certificate layer.

It also blank-imports the backends it ships (see
[Concepts](../concepts/index.md)), so those backends register themselves at
startup and appear as valid `--backend` values.

There are **two registries, not one** (`go/signing`'s and `go/encryption`'s),
and sigillum keeps a blank-import file per side (`cmd/sigillum/signing.go` and
`cmd/sigillum/encryption.go`). They are deliberately separate: the two sides ask
different things of a backend. Signing needs a key that signs; encryption needs
one that derives a shared secret and can hand back its own public half, which
a signing backend has no reason to offer. A single registry would make every
backend claim both, and `--backend` would list names that cannot serve the
command they were given to.

## Why the commands live here

The commands were in a shared module so that gtb and sigillum could both mount
them without either depending on the other. Spec 0007 takes them out of gtb,
which leaves that module one consumer. Keeping it would mean releasing a second
module for every flag or message change, with nothing gained, so sigillum
took the commands over.

The boundary that still matters is the one between the commands and the
signing logic. A command parses flags and writes files. Everything that
decides what a signature contains is in `go/signing` or
`go/signing-sigstore`, where other tools can reuse it without a CLI.

## No cycle, by construction

The dependency arrows only ever point down the stack. sigillum sits at the top
and nothing depends on it. `go/signing` and its backends depend on neither gtb
nor sigillum, so any tool can sign with them.
