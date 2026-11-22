# `sigillum mcp`

`sigillum mcp start` serves a fixed set of sigillum's commands as MCP tools over
standard input and output. The set covers commands that report state or work
with public key material. Nothing on it signs, decrypts, publishes a key,
runs a config command that changes anything, or replaces the binary. The key
generators do write files, which can include the config file: see
[Served tools](#served-tools).

## Subcommands

| Command | What it does |
|---------|--------------|
| `mcp start` | Serve the tools over stdio. Standard output carries the protocol, and logs go to standard error. |
| `mcp stream` | Withheld: it refuses to run. See [`mcp stream` is withheld](#mcp-stream-is-withheld). |
| `mcp tools` | Write the full tool definitions to a file, `mcp-tools.json` by default (`-o` to change it). |
| `mcp claude`, `mcp cursor`, `mcp vscode` | Add sigillum to, list it in, or remove it from that client's MCP configuration (`enable`, `list`, `disable`). |

The server publishes compactly. A client sees three tools, `search_tools`,
`get_tool_details` and `call_tool`, and finds sigillum's commands through
`search_tools`.

## Served tools

| Tool | Command |
|------|---------|
| `sigillum_changelog` | `changelog` |
| `sigillum_config_list` | `config list` |
| `sigillum_config_path` | `config path` |
| `sigillum_config_validate` | `config validate` |
| `sigillum_doctor` | `doctor` |
| `sigillum_doctor_report` | `doctor report` |
| `sigillum_keys_generate` | [`keys generate`](keys.md) |
| `sigillum_keys_generate-image` | [`keys generate-image`](keys.md) |
| `sigillum_keys_minisign` | [`keys minisign`](keys.md) |
| `sigillum_version` | `version` |

Three of these write files, and one reads from KMS:

- **`keys generate`, `keys generate-image` and `keys minisign` write files** at
  the paths their arguments name, and `--force` overwrites an existing file. An
  agent can write anywhere the server process can. That includes a trust key:
  an agent could swap a public key that something on the machine trusts, such
  as an `.asc` a build embeds or a key a verifier pins, for one whose private
  half it holds. It can also overwrite sigillum's own config file. Point
  sigillum at an agent only from an account that cannot write those files.
  `--force` comes off these tools once gtb can withhold a single flag
  ([go-tool-base#193](https://gitlab.com/phpboyscout/go-tool-base/-/work_items/193)).
- **`keys minisign` with `--backend aws-kms`** reads the public key from KMS
  using the credentials the server process holds. That call reads a public key
  and cannot sign.

## Withheld commands

These stay fully runnable on the command line. Over MCP, `call_tool` and
`get_tool_details` answer `unavailable` for each of them.

| Command | Why |
|---------|-----|
| `sign`, `sign image` | Makes a signature with the real key. |
| `keys mint` | Its self-signature is a `kms:Sign` call with the real key. |
| `keys rotate` | Signs a rotation manifest, which changes what every installed binary trusts. |
| `keys publish`, `keys wkd` | Write what consumers pin against. |
| `decrypt` | Spends a KMS credential and reveals report plaintext. |
| `certificate` | Its signatures are made by `kms:Sign`. |
| `update` | Replaces the binary the agent is driving. |
| `config get` | Its `--unmask` flag prints a credential in clear. `config list` stays served, because it masks every credential sigillum reads. |
| `config set`, `unset`, `edit`, `trust`, `convert`, `migrate-credentials` | Change configuration or move credentials. |
| `docs` | An interactive terminal browser. |

`completion` and `help` are never served, because they are shell plumbing.

## `mcp stream` is withheld

`sigillum mcp stream` refuses to run:

```text
mcp stream is withheld: it would serve sigillum's tools over HTTP without authentication; use mcp start
```

Its listener binds every interface by default and has no authentication, so
anyone who can reach the port could call the tools with the server's
credentials. sigillum serves MCP over stdio only, until the listener defaults
to loopback ([go/mcp#9](https://gitlab.com/phpboyscout/go/mcp/-/work_items/9)).

## The set is fixed at build time

No flag or configuration key changes what the server serves. The decision is
compiled in, as a marker on each sigillum command and as a withhold list for
the framework's built-ins, so a config file cannot widen it. To see what a
given binary serves:

```bash
sigillum mcp tools -o tools.json
jq -r '.[].name' tools.json
```

The behaviour suite (`features/mcp.feature`) compares the served list against
the table above exactly. A new command therefore fails the build until someone
decides whether to serve it.
