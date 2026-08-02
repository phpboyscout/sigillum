---
title: Sign and verify your first release
description: Install sigillum, generate an RSA keypair, sign a checksum file with the local backend, and verify the detached OpenPGP signature with gpg — no cloud account needed.
tags: [tutorial, getting-started, openpgp, local, signing]
---

# Sign and verify your first release

By the end of this you will have a signing keypair on disk, an ASCII-armored
OpenPGP detached signature over a file, and a `gpg --verify` run that says
*Good signature*. Allow about ten minutes.

Everything here uses the `local` backend, which signs with a private key file on
your own disk. That keeps the tutorial free of cloud accounts. It is also the
wrong choice for a real release — a key on disk is a key that can be copied — so
when you move to production, swap it for AWS KMS as described in
[Sign a release artefact](../how-to/sign-a-release-artefact.md).

## What you need before you start

- **Go 1.26.5 or newer**, if you install from source. That version is pinned in
  the module's `go` directive, and an older toolchain will refuse to build.
- **`gpg`**, to verify the signature with an implementation that is not
  sigillum. Any GnuPG 2.2 or later will do.
- A scratch directory you do not mind filling with key material.

Work in a throwaway directory. A later step writes a private key, and you do not
want it landing in a repository:

```bash
mkdir -p /tmp/sigillum-tutorial && cd /tmp/sigillum-tutorial
```

## Install sigillum

```bash
go install gitlab.com/phpboyscout/sigillum/cmd/sigillum@latest
```

The `main` package lives at `cmd/sigillum/`, so the install path ends in
`/cmd/sigillum`. If you would rather not build, download a pre-built binary for
your platform from the
[GitLab Releases](https://gitlab.com/phpboyscout/sigillum/-/releases) page and
put it on your `PATH`.

Check it runs:

```bash
sigillum --help
```

You should see `sign` and `keys` in the command list, alongside framework
built-ins like `config`, `doctor`, `update` and `version`. If the shell cannot
find `sigillum`, `$(go env GOPATH)/bin` is probably not on your `PATH`.

## Generate a keypair

`keys generate` creates a fresh OpenPGP keypair in-process and writes both
halves. The algorithm is a required choice — a signing tool should not pick one
for you quietly:

```bash
sigillum keys generate \
    --algorithm rsa --rsa-bits 4096 \
    --name "Test Signer" --email test@example.org \
    --output release.asc --private-output release.pem
```

RSA 4096 takes a few seconds. You get two files and two log lines:

```
INFO Generated OpenPGP keypair algorithm=rsa public_output=release.asc private_output=release.pem creation_time=… fingerprint=9458EAFE…
WARN Move the private-half file to offline storage now. private_output=release.pem
```

- `release.asc` is the ASCII-armored OpenPGP **public** key. This is the
  identity you publish and that verifiers trust.
- `release.pem` is the PKCS#1 PEM **private** key, written mode `0600`. This is
  what the `local` backend signs with.

Write the fingerprint down. Every later step reports the same one, and that is
how you catch signing with the wrong key.

RSA is deliberate here. RSA keys drive the OpenPGP path; Ed25519 keys drive the
minisign path and cannot produce an OpenPGP signature at all. Pick
`--algorithm ed25519` instead and the signing step below fails with *unsupported
key type: only RSA is supported*. The
[minisign guide](../how-to/sign-an-artefact-for-rust-consumers.md) covers that
other lane.

## Sign a file

Real releases sign a checksum manifest rather than each artefact, so make
something shaped like one:

```bash
echo "hello sigillum" > checksums.txt
```

Then sign it. `--key-id` points at the private key, and `--public-key` points at
the armored public key that names the signing identity:

```bash
sigillum sign \
    --backend local \
    --key-id ./release.pem \
    --public-key ./release.asc \
    checksums.txt
```

```
INFO Signed file backend=local key_id=./release.pem public_key=./release.asc input=checksums.txt output=checksums.txt.sig sig_creation_time=… fingerprint=9458EAFE…
```

sigillum wrote `checksums.txt.sig` — the default output is `<input>.sig` — as an
ASCII-armored OpenPGP detached signature. The fingerprint on that log line is
read back out of `release.asc`, so it is the cheapest possible check that you
signed with the identity you meant to.

Both key flags are needed for one signature because they do different jobs:
sigillum takes the signing identity from `--public-key` and refuses to continue
if the backend's public half disagrees with it.

## Verify with gpg

sigillum produces exactly what `gpg --verify` consumes. Import the public key
into a throwaway keyring so you are not touching your real one:

```bash
TMPGNUPG=$(mktemp -d)
gpg --homedir "$TMPGNUPG" --import release.asc
gpg --homedir "$TMPGNUPG" --verify checksums.txt.sig checksums.txt
```

```
gpg: Good signature from "Test Signer <test@example.org>"
```

gpg also prints a "This key is not certified with a trusted signature" warning.
That is expected and is not a failure — you imported a key without certifying
it, so gpg has no basis for trusting the binding between the key and the name.
The signature itself is good.

Prove the check is real by breaking it:

```bash
echo "tampered" >> checksums.txt
gpg --homedir "$TMPGNUPG" --verify checksums.txt.sig checksums.txt
# gpg: BAD signature from "Test Signer <test@example.org>"
```

## Clean up

The private key is the reason to bother:

```bash
rm -rf "$TMPGNUPG"
cd / && rm -rf /tmp/sigillum-tutorial
```

If you keep the directory instead, treat `release.pem` as a secret. sigillum
writes private halves mode `0600`, but it cannot stop you copying one into a git
repository.

## Where to go next

- [Sign a release artefact](../how-to/sign-a-release-artefact.md) — the same
  command against an AWS KMS key, plus reproducible signatures and CI wiring.
- [Sign an artefact for Rust consumers](../how-to/sign-an-artefact-for-rust-consumers.md)
  — the minisign lane, for cargo-binstall and rtb-update.
- [Publish a WKD tree](../how-to/publish-a-wkd-tree.md) — serve `release.asc`
  from your own domain as an external trust anchor.
- [CLI reference](../reference/cli/index.md) — every command, flag, default and
  failure mode.
- [What sigillum does not do](../explanation/what-sigillum-does-not-do.md) — the
  limits, including why there is no `sigillum verify`.
