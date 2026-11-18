---
title: Use nvault from an agent
description: Exact commands, what touches a secret, and what must not land in a log.
---

Call the binary. Do not invent a value flag. Do not log stdout from `get`.

## Cheat sheet

| Command | Reads a secret? | Puts a secret in argv? | Stdout |
| --- | --- | --- | --- |
| `nvault ls [PREFIX]` | no, except Vaultwarden and Proton* | no | key names, one per line |
| `nvault ls --json [PREFIX]` | no, except Vaultwarden and Proton* | no | JSON array of `{ "key" }` |
| `nvault search QUERY` | no, except Vaultwarden and Proton* | no | matching names |
| `nvault get KEY` | yes | no | exact value, no added newline |
| `nvault get KEY --newline` | yes | no | value plus a newline |
| `nvault set KEY` | writes one | no | empty |
| `nvault ensure KEY` | writes only if absent | no | empty |
| `nvault ensure --json KEY` | writes only if absent | no | `{"status":"created"}` or `{"status":"present"}` |
| `nvault exec -- CMD` | yes, into the child env | no | the child's stdout |
| `nvault providers` | no | no | profile rows, no credentials |
| `nvault dir` | no | no | config directory, or empty |

`exec` has the alias `x`. A leading `--` before the child command is accepted.

\* `ls` and `search` print names only, but the Vaultwarden adapter runs `bw list items`, which returns full items, and the Proton adapter runs `pass-cli item list`, which downloads and decrypts each item. Both discard everything except the name. Every other adapter reads metadata only for these commands. See [Providers](/reference/providers/) and [Limitations](/explanation/limitations/).

## Pass a value

```sh
printf '%s' 'not-a-real-secret' | nvault set apps/production/db
printf '%s' 'not-a-real-secret' | nvault ensure apps/production/db
```

Do not put the value after the key. An empty value is refused. `set` prints `nvault: stored <key>` on stderr. `ensure` prints `created` or `present` and the key on stderr. Neither prints the value.

## Do not log

- stdout of `get`
- the child environment after `exec` or `env`
- provider response bodies (the tool already omits them from errors)
- `VAULT_TOKEN` or any other credential variable

`search` and `ls` print no value, so their stdout is safe to capture. For Vaultwarden and Proton the underlying CLI did fetch item bodies (see the note above), so treat that process as secret-bearing and do not capture its debug or trace output. `providers` is safe to capture. It does not open the credential file or variable.

## Global flags

| Flag | Effect |
| --- | --- |
| `--config FILE` | use this file; wins over `NVAULT_CONFIG` and discovery |
| `--provider NAME` | profile name; default is `provider` in the file |
| `--prefix PATH` | default prefix for list, search, exec, and env |

There is no `--value`, no `--password`, and no `remove`.
