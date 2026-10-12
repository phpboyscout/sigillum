---
title: Reference
description: Every sigillum command, flag, default, configuration key and failure mode.
tags: [reference, cli, configuration]
---

# Reference

Exhaustive, factual descriptions of sigillum's surfaces: what each thing is,
what it defaults to, and what happens when it is wrong.

- **[CLI reference](cli/index.md)**: the command set, global flags, the
  compiled-in backends, which key algorithm each signature format needs, and the
  exit codes.
    - **[`sign`](cli/sign.md)**: every flag, which format it belongs to, and
      the refused combinations.
    - **[`keys`](cli/keys.md)**: `generate`, `mint`, `wkd`, `minisign` and
      `publish`, with output layouts, file permissions and failure modes.
    - **[`decrypt`](cli/decrypt.md)**: every flag, the error table, and which
      failures cost a key-service call.
    - **[`certificate`](cli/certificate.md)**: every flag, why `--created` has
      no default, and how to get byte-identical output.
- **[Configuration](config/index.md)**: where config files live, how layers
  resolve, every key the framework reads, and why the `SIGILLUM_` environment
  prefix does nothing.

## What is not in the reference

Signing behaviour is set entirely by flags, not configuration, so there is no
signing section in the configuration reference.

Constraints, such as which key algorithm works with which signature format and
what is refused outright, are stated in
[What sigillum does not do](../explanation/what-sigillum-does-not-do.md), with
the exact error each one produces.
