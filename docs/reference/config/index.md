# Configuration Reference

sigillum's signing surface — `sign` and `keys` — is **flag-driven**. The
backend, key identifier, public-key path, output path, and every other signing
option are passed as command-line flags (and, for `aws-kms`, read from the AWS
SDK's own credential/region environment); see the
[CLI reference](../cli/index.md). There are no signing-specific configuration
keys to set in a config file.

The configuration that does apply is the standard set provided by the underlying
gtb framework — logging, update checks, and the like. It is layered (highest
precedence first): command-line flags → environment variables → project-local
config file → embedded defaults. Any setting can be overridden from the
environment using the `SIGILLUM_` prefix (for example, `log.level` becomes
`SIGILLUM_LOG_LEVEL`).

Use the built-in `config` command to inspect the effective configuration:

```bash
sigillum config --help
```
