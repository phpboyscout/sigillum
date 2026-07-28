# Getting Started

This walkthrough installs sigillum, generates a local keypair, signs a file, and
verifies the signature. It uses the `local` backend end to end, so it needs no
cloud account — for the production AWS KMS path, see
[Sign a release artefact](how-to/sign-a-release-artefact.md).

## Prerequisites

- **Go 1.26.5** or newer if you install from source.
- `gpg` (optional) if you want to verify with a reference OpenPGP
  implementation as well as sigillum's own output.

## Install

Install the latest release with `go install`:

```bash
go install gitlab.com/phpboyscout/sigillum/cmd/sigillum@latest
```

The `main` package lives at `cmd/sigillum/`, so the install path ends in
`/cmd/sigillum`. Alternatively, download a pre-built binary for your platform
from the [GitLab Releases](https://gitlab.com/phpboyscout/sigillum/-/releases)
page and put it on your `PATH`.

Confirm it runs:

```bash
sigillum --help
sigillum sign --help
sigillum keys --help
```

## 1. Generate a keypair

`keys generate` creates a fresh OpenPGP keypair locally and writes both halves.
The algorithm is a required, explicit choice — there is no silent default:

```bash
sigillum keys generate \
    --algorithm rsa --rsa-bits 4096 \
    --name "Test Signer" --email test@example.org \
    --output release.asc --private-output release.pem
```

This writes:

- `release.asc` — the ASCII-armored OpenPGP **public** key (the identity).
- `release.pem` — the PEM-encoded **private** key the `local` backend signs
  with.

For an Ed25519 key, use `--algorithm ed25519` (the `--rsa-bits` flag is then
ignored and the private half is written as `.priv.asc`).

## 2. Sign a file

Create something to sign, then produce a detached signature with the `local`
backend, pointing `--key-id` at the PEM private key and `--public-key` at the
armored public key:

```bash
echo "hello sigillum" > checksums.txt

sigillum sign \
    --backend local \
    --key-id ./release.pem \
    --public-key ./release.asc \
    checksums.txt
```

sigillum writes `checksums.txt.sig` (the default is `<input>.sig`) — an
ASCII-armored OpenPGP detached signature. The INFO log line includes the
public-key fingerprint so you can spot-check it against your trust anchor.

## 3. Verify

sigillum produces exactly what `gpg --verify` consumes. Import the public key
into a throwaway keyring and verify:

```bash
TMPGNUPG=$(mktemp -d)
gpg --homedir "$TMPGNUPG" --import release.asc
gpg --homedir "$TMPGNUPG" --verify checksums.txt.sig checksums.txt
# Expect: "Good signature from Test Signer <test@example.org>"
rm -rf "$TMPGNUPG"
```

A "Good signature" line with the fingerprint that `keys generate` reported means
the round trip works.

## Next steps

- [Sign a release artefact](how-to/sign-a-release-artefact.md) — the production
  AWS KMS path and CI integration.
- [Generate or mint a signing key](how-to/generate-or-mint-a-signing-key.md) —
  minting a public key from a KMS-held signer, and reproducible keys.
- [Publish a WKD tree](how-to/publish-a-wkd-tree.md) — serve your public keys as
  an external trust anchor.
- [CLI reference](reference/cli/index.md) — every command and flag.
