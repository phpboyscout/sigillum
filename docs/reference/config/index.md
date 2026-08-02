---
title: Configuration reference
description: Every configuration key sigillum reads, where config files are looked for, how layers resolve, why the SIGILLUM_ environment prefix does nothing, and what config trust protects.
tags: [reference, configuration, config, layers, environment]
---

# Configuration reference

## Signing is not configurable — it is all flags

Every signing decision — backend, key identifier, public-key path, output path,
format, timestamp — is a command-line flag on `sign` or `keys`. There are no
`sign.*` or `keys.*` configuration keys. Putting them in a config file has no
effect and produces no warning: the file is accepted, and the keys are never
read.

The only AWS-related configuration sigillum honours is whatever the AWS SDK's
own default chain picks up (`AWS_PROFILE`, `AWS_REGION`, `~/.aws/credentials`,
OIDC web identity), plus the `--kms-region` flag.

What is configurable is the surrounding framework: logging, self-update, and
telemetry. That is the whole of it.

## Where configuration files are looked for

| Path | Role |
|---|---|
| `/etc/sigillum/config.yaml` | System-wide. |
| `~/.sigillum/config.yaml` | Per-user, and the **writable** target — this is where `config set` lands. |
| `.sigillum.yaml` in the working directory or above | Project-local, discovered automatically. Sits above the user's files. |
| Anything passed to `--config` | Explicit. Repeatable. |

Only files that **exist** become layers. A non-existent path contributes
nothing and is not a candidate write target, which is why `config set` never
tries to write into `/etc`.

Check what is actually in play:

```bash
sigillum config path   # the resolved files and which one is writable
sigillum config list   # the effective values
```

With no config file anywhere, `config path` reports where a future write would
land and says `no config file is currently loaded`. That is a normal state —
sigillum needs no configuration to sign anything.

## How layers resolve

Highest precedence first:

1. **Command-line flags** — only flags you actually changed. A flag sitting at
   its default never clobbers a configured value.
2. **Project-local `.sigillum.yaml`** — above the user's files, below flags.
3. **`--config` files and the default file paths**, in the order declared.
4. **Embedded defaults** shipped in the binary's assets.

## Why `SIGILLUM_LOG_LEVEL` does nothing

There is **no environment-variable layer**. Setting `SIGILLUM_LOG_LEVEL=debug`,
or any other `SIGILLUM_`-prefixed variable, changes nothing:

```console
$ SIGILLUM_LOG_LEVEL=debug sigillum config get log.level
info
```

The framework supports an environment layer, but it is only installed when the
tool declares an environment prefix, and sigillum does not declare one. Without
it, no environment variable is consulted for configuration at all.

Earlier versions of this page said any setting could be overridden with a
`SIGILLUM_` prefix. That was never true of this binary. Use `--config`, a
project-local `.sigillum.yaml`, or the relevant flag instead.

The environment still matters in two places that are *not* the config store:
the AWS SDK credential chain used by the `aws-kms` backend, and
`SOURCE_DATE_EPOCH` on the minisign signing path.

## Logging keys

| Key | Default | Values | What it does |
|---|---|---|---|
| `log.level` | `info` | `debug`, `info`, `warn`, `error`, `fatal` | Minimum level written to stderr. An unparseable value is ignored and the level is left alone. |
| `log.format` | *(charm console)* | `json`, `logfmt` | Switches the log formatter. Any other value leaves the default human-readable format. |

`--debug` overrides `log.level` for the run regardless of configuration.

## Self-update keys

sigillum checks for a newer release on most invocations and verifies what it
downloads against the signing key embedded in the binary.

| Key | Default in sigillum | What it does |
|---|---|---|
| `update.policy` | `disabled` | `disabled` logs that an update exists; `prompt` asks and continues if declined; `enabled` blocks the command until updated. An unknown value falls back to `disabled`. |
| `update.check_interval` | `24h` | Any Go duration. `0` checks on every invocation. An invalid or negative value falls back to the default. |
| `update.key_source` | `embedded` | Where the verification key comes from. sigillum pins this to `embedded` at build time, rather than the framework's `both`. |
| `update.require_signature` | `false` | Refuse to update unless the release signature verifies. |
| `update.require_checksum` | `false` | Refuse to update unless the checksum manifest verifies. |
| `update.require_external_crosscheck` | `false` | Refuse to update unless the embedded key also matches a WKD-served copy. |
| `update.external_key_email` | *(empty)* | Email whose WKD entry is used for that cross-check. |

The last check time is recorded in `~/.sigillum/last_checked`; deleting that
file forces the next run to check.

## Telemetry keys

| Key | Default | What it does |
|---|---|---|
| `telemetry.enabled` | *(unset — off)* | Whether telemetry is collected. |
| `telemetry.consent` | *(unset)* | Records the consent decision. |

## Which keys a cloned repository cannot set

A project-local `.sigillum.yaml` is honoured for workflow-tuning keys — logging,
output, feature toggles — as soon as it is discovered. Security-sensitive keys
are **stripped from that layer** until the file is explicitly trusted:

```bash
sigillum config trust            # trust the project file found from the cwd
sigillum config trust --list     # list trusted project files
sigillum config trust --forget   # revoke
```

The protected set is:

- `update.require_signature`, `update.require_checksum`,
  `update.require_external_crosscheck`, `update.policy`, `update.key_source`,
  `update.external_key_email`
- `telemetry.enabled`, `telemetry.consent`
- any key with an `auth` segment, plus `anthropic.api`, `openai.api`,
  `gemini.api`, `bitbucket.app_password`

The reason is straightforward: a repository you clone must not be able to
silently weaken self-update verification or flip telemetry consent just by
shipping a dotfile.

Trust is bound to the file's exact content. Editing a trusted file revokes
trust until you run `config trust` again.

## Managing configuration from the CLI

| Command | What it does |
|---|---|
| `sigillum config list` | Print every effective key and value. Honours the global `--output json`. |
| `sigillum config get <key>` | Print one value. An absent key fails with `config key "update.policy" not found`. |
| `sigillum config set <key> <value>` | Write to the user's config file, creating it if needed. |
| `sigillum config unset <key>` | Remove a key. |
| `sigillum config path` | Show the resolved file paths and which is writable. |
| `sigillum config edit` | Open the config file in `$EDITOR`. |
| `sigillum config validate` | Check the current configuration. Prints `configuration is valid`. |
| `sigillum config trust` | Trust a project-local file's protected keys. |
| `sigillum config migrate-credentials` | Move literal credentials into env-var references or the OS keychain. |

### `config set` does not check that a key exists

The store is schemaless. `sigillum config set nonsense.key 1` succeeds and
writes the key; nothing reads it. A misspelled key is therefore silent — it
will not error, and it will not take effect. `config list` after a `set` is the
way to catch a typo.

`config --help` suggests running `init <subsystem>` for guided reconfiguration.
That command is **disabled in sigillum** and does not exist; the text comes from
the framework.

## Related

- [CLI reference](../cli/index.md) — global flags, including `--config` and
  `--debug`
- [What sigillum does not do](../../explanation/what-sigillum-does-not-do.md)
