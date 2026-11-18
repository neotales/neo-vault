---
title: CLI
description: Commands and flags implemented by nvault.
---

Global flags, accepted before or after the subcommand:

| Flag | Argument | Meaning |
| --- | --- | --- |
| `--config`, `-c` | `FILE` | configuration file |
| `--provider` | `NAME` | provider profile |
| `--prefix` | `PATH` | default key prefix for list, search, exec, and env |

## `ls`

```sh
nvault ls [PREFIX] [--json]
```

Lists key names under the prefix. Prints names only. Vaultwarden's `bw list items` returns full items and Proton's `pass-cli item list` downloads and decrypts each item, but both adapters keep only names and print no value. `--json` prints a JSON array of objects with a `key` field.

## `get`

```sh
nvault get KEY [--field FIELD] [--newline]
```

Prints the exact value to stdout. No trailing newline unless `--newline` is set. `--field` is an alternative to `KEY#field`. Both forms together are an error.

## `set`

```sh
nvault set KEY [--field FIELD] [--stdin]
```

Reads the value from stdin, or from a hidden prompt when stdin is a terminal. `--stdin` forces stdin even on a terminal. There is no value argument. An empty value is refused. This command can replace an existing value. It holds the same-user write lock for the call.

## `ensure`

```sh
nvault ensure KEY [--field FIELD] [--stdin] [--json]
```

Creates the key only through a provider path that cannot replace an existing key. A successful atomic create confirms absence; a provider-confirmed duplicate is reported present. An existing key is left unchanged. There is no delete. `--json` prints `{"status":"created"}` or `{"status":"present"}` and no value. Default stdout is empty. Stderr says `created` or `present` plus the key. Auth, network, and other ambiguous errors are failures, not absence. Providers without a race-safe create-if-absent path exit non-zero. See [Providers](/reference/providers/).

## `search`

```sh
nvault search QUERY [--limit N] [--json]
```

Case-insensitive name search over the provider listing. Default limit is 50. It uses the same listing path as `ls`, so the Vaultwarden and Proton item fetches apply; no value is printed.

## `exec`

```sh
nvault exec [--env-prefix PREFIX] [--only KEYS] -- CMD [ARGS...]
nvault x -- CMD [ARGS...]
```

Maps each selected key's basename to an environment variable in the child. `apps/prod/db` becomes `DB`. `db#password` becomes `DB_PASSWORD`. Collisions fail. The value is not placed in `argv`.

## `env`

```sh
nvault env [--shell bash|zsh|fish|powershell|pwsh|nu] [--env-prefix PREFIX] [--only KEYS]
```

Prints shell exports for the current directory. Default shell is bash.
`powershell` and `pwsh` print `$env:NAME = 'value'` with quotes doubled; both
editions accept the output. `nu` has no `eval`, so it prints a JSON object to
pipe into `from json | load-env`.

## `completion`

```sh
nvault completion bash|zsh|fish|powershell|elvish
```

Prints a static completion script. It does not complete key names from the provider.

## `hook`

```sh
nvault hook bash|zsh|fish|powershell|pwsh|nu
```

Prints a directory hook that sets `NVAULT_DIR`. It does not fetch secrets on
`cd` unless `NVAULT_AUTOLOAD=1`. PowerShell wraps the existing `prompt`
function; Nushell registers a `pre_prompt` hook and loads JSON with
`load-env`. Installation snippets and the exact evidence for what was executed
are in the project README.

## `dir`

```sh
nvault dir
```

Prints the directory of the nearest configuration file, or nothing.

## `providers`

```sh
nvault providers
```

Prints configured profiles. It does not read credentials. A missing helper command is marked `command unavailable`.

Exit status `0` is success. A provider error exits `1` and writes `nvault: ...` to stderr. The message names a key and a status, not a response body and not a value.
