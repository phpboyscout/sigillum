# CLI Reference

Command reference for sigillum. Run `sigillum <command> --help` for the
authoritative, always-current flag set — the pages here mirror it.

sigillum's reason to exist is two top-level commands, attached from
`gitlab.com/phpboyscout/go/signing-cli`:

| Command | Purpose |
|---------|---------|
| [`sign`](sign.md) | Produce an ASCII-armored OpenPGP detached signature over a file using a configured backend. |
| [`keys`](keys.md) | Manage OpenPGP keys for release-binary signing (`generate`, `mint`, `wkd`). |

The scaffolded framework built-ins (`init`, `update`, `docs`, `doctor`,
`changelog`, `config`, `version`) are also present; run `sigillum --help` for
the full list.

## Backends

`--backend` on `sign` and `keys mint` selects a signing backend compiled into
the binary. sigillum ships two, activated by blank imports in its `main`
package:

| Backend | `--key-id` is | Notes |
|---------|---------------|-------|
| `aws-kms` | a KMS key ID, ARN, or alias | Private key stays in KMS; adds `--kms-region`. Uses the AWS SDK default credential chain. |
| `local` | a PEM file path | Unencrypted PKCS#1 / PKCS#8 RSA private key on disk. |

A regulated build can drop the AWS KMS blank import and rebuild; linker
dead-code elimination then keeps that SDK out of the binary.
