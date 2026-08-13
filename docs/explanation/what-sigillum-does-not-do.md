---
title: What sigillum does not do
description: The deliberate limits of sigillum — no verify command, no key-algorithm crossover between the OpenPGP and minisign paths, no encrypted private keys, no runtime backend selection, and no configuration file for signing options.
date: 2026-08-02
tags: [explanation, limitations, constraints, signing]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# What sigillum does not do

sigillum is a small tool with a narrow job, and most of the questions people ask
about it are really questions about its edges. This page is the list of things it
will not do, why, and what to use instead. Every entry here is behaviour of the
current release, not a roadmap.

## There is no `sigillum verify` command

sigillum signs, and it decrypts. It does not verify. `sigillum --help` lists
`sign`, `keys`, `decrypt` and `certificate` of its own, and none of them checks
a signature.

This is not an oversight, but it is a genuine asymmetry, and the project
description ("signing and verification CLI") reads more broadly than the command
surface does. Verification happens in three other places:

- **`gpg --verify <sig> <file>`** for OpenPGP detached signatures. sigillum's
  output is an ordinary armored OpenPGP signature, so any implementation works.
- **`minisign -Vm <artefact> -P <pubkey>`** for `.minisig` artefact signatures,
  or the consumers themselves — cargo-binstall and rtb-update both verify before
  installing.
- **[`gitlab.com/phpboyscout/go/signing/verify`](https://signing.go.phpboyscout.uk)**,
  a Go library, for tools that check their own downloads during self-update.
  sigillum links it for its *own* `update` command; it does not expose it.

The reason is that verification belongs where the trust anchor lives. A verifier
needs to already know which key it trusts; a general-purpose `verify` subcommand
that takes the key as an argument proves only that a file and a signature agree,
which is the least interesting half of the question.

## One key cannot serve both signature formats

`sign` has two formats and they need different key algorithms. There is no key
that does both.

| Format | Key algorithm | What fails otherwise |
|---|---|---|
| `openpgp` | RSA only | `computing signature: DetachSign: ed25519.PublicKey: unsupported key type: only RSA is supported` |
| `minisign` | Ed25519 only | `minisign requires an Ed25519 signing key, but --key-id resolved to *rsa.PublicKey; RSA keys sign the OpenPGP manifest path (--format openpgp) instead` |

`keys mint` inherits the RSA-only constraint, because minting builds an OpenPGP
entity: pointing it at an Ed25519 key fails with *minting armored public key:
got ed25519.PublicKey: unsupported key type: only RSA is supported*.

The cause is upstream and structural rather than a policy choice. go-crypto's
OpenPGP Ed25519 branch requires a concrete `*ed25519.PrivateKey` and offers no
`crypto.Signer` fall-through, so an opaque KMS-held Ed25519 key cannot drive it
at all. Rather than support it for local keys and not for KMS ones, the OpenPGP
path rejects every non-RSA signer up front.

A project that publishes both a signed checksum manifest and signed artefacts
therefore runs **two keys**: one RSA for OpenPGP, one Ed25519 for minisign.

## ECDSA keys are refused outright

Both backends reject ECDSA:

- `local` — *PKCS#8 holds \*ecdsa.PrivateKey: PEM key is neither RSA nor
  Ed25519; only those are supported*.
- `aws-kms` — *KMS key is neither RSA nor Ed25519; only RSA SIGN_VERIFY and
  ECC_NIST_EDWARDS25519 keys are supported*.

Nothing in the phpboyscout estate verifies ECDSA signatures, so accepting the
key type would produce signatures no consumer could check.

## Private keys on disk are never encrypted

`keys generate` writes unencrypted private halves, and the `local` backend reads
only unencrypted PEMs. An encrypted PEM — a file whose block header reads
`-----BEGIN ENCRYPTED PRIVATE KEY-----` — gets *encrypted PEM private keys are
not supported in v0.1; decrypt out-of-band first or use the aws-kms backend*.

The Go standard library exposes no PKCS#8 encryption or decryption, and a clean
OpenPGP s2k path is additive work nobody has asked for yet. Until it exists,
there are two honest answers: use the `aws-kms` backend so the private half
never lands on a disk at all, or encrypt the file at the filesystem layer with
LUKS, FileVault or `age`.

Private-half files are written mode `0600`; public halves and signatures are
`0644` because publishing them is the point.

## The backend set is fixed at build time, not chosen at run time

`--backend` selects from the backends **compiled into the binary**. There is no
plugin directory, no `--backend-path`, and no configuration key that adds one.

There are two independent registries, and the same flag name selects from
whichever the command needs — signing for `sign` and `keys`, encryption for
`decrypt` and `certificate`. The distributed sigillum ships `aws-kms` and
`local` in both, and `--backend` is required rather than defaulting, because
more than one is present.

An unknown name fails immediately and lists what is available:

```
"vault" (available: aws-kms, local): unknown signing backend
```

Adding GCP KMS, Vault or an HSM means implementing `go/signing`'s `Backend`
contract in a module, blank-importing it in a `main` package, and building. That
is a rebuild, and deliberately so: a regulated build proves what it can talk to
by what it links, and dropping a blank import is what keeps that SDK out of the
binary entirely. See [Concepts](concepts/index.md) for the model.

## Signing options cannot be set in a configuration file

Every signing decision — backend, key identifier, public key, output path,
format, timestamp — is a command-line flag. There are no `sign.*` or `keys.*`
configuration keys, and adding them to `~/.sigillum/config.yaml` does nothing.

Only the framework's own settings (`log.level`, `update.*`) are configurable.
The [configuration reference](../reference/config/index.md) lists what actually
exists, including the environment-variable behaviour, which is not what you
would expect.

## One input file per run

`sign` takes exactly one input file. There is no glob expansion, no
`--recursive`, and no manifest mode. Two artefacts means two invocations.

For a release with many artefacts the usual shape is to sign a single checksum
manifest with OpenPGP — one signature covering everything — and to sign each
downloadable artefact with minisign in a loop, because the consumers fetch one
artefact and want a signature beside it.

`sign` also refuses to write its signature over its own input, and the guard is
not fooled by a different spelling of the same path: it compares cleaned paths
first and falls back to `os.SameFile`, so a symlink or an absolute-versus-
relative form is caught too.

## Only OpenPGP dual-signing is supported, not minisign

`--append` merges a second signature into an existing armored OpenPGP block, for
a key-rotation overlap window where one file must satisfy verifiers trusting
either key. It has no minisign equivalent, and asking for one is an error:
*--append is not supported for --format minisign; it is an OpenPGP dual-sign
primitive*.

Rotate minisign keys by publishing a new generation alongside the old one with
`keys publish`, and marking the old one retired.

## Published minisign keys cannot be changed

`keys publish` is add-only. A key already published at a path with different
bytes is refused rather than overwritten, and the same guard applies to the
`keys.json` manifest entry. Re-publishing identical content is a no-op.

Retired and revoked keys stay published. A signature made under a key must
remain checkable after the private half is destroyed, so removal is never the
rotation mechanism.

## The `init` and `mcp` commands are switched off

sigillum is generated from the go-tool-base framework, which offers an `init`
subsystem-configuration command and an MCP server command. Both are disabled in
this tool, so neither appears in `--help` and neither can be enabled at run
time. `sigillum config --help` still mentions `init` in its prose; that text
comes from the framework and does not apply here.

`config`, `changelog`, `completion`, `docs`, `doctor`, `update` and `version`
are present. See the [CLI reference](../reference/cli/index.md).

## sigillum knows nothing about your CI, your cloud or your deploy

Three things people reasonably expect to find here live outside it:

- **AWS credentials.** The `aws-kms` backend reads the AWS SDK default
  credential chain and nothing else. There is no `--profile`, no
  `--role-arn`, and no OIDC support in sigillum — a CI job populates the chain
  before sigillum runs. `--kms-region` (default `eu-west-2`) is the only
  AWS-specific flag.
- **Deploying a keys site.** `keys wkd` and `keys publish` write a staging
  directory. Getting it onto a host is your deploy tool's job.
- **Timestamping and notarisation.** No RFC 3161 timestamps, no transparency-log
  submission, no Apple notarisation, no Windows Authenticode. sigillum produces
  detached signatures, and that is the whole surface.

## Where the reasoning lives

This page states limits. The reasoning behind the architecture that produces
them is in [Components & architecture](components/index.md) and
[Concepts](concepts/index.md).
