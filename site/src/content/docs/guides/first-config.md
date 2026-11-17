---
title: Configure a fake profile
description: Point nsvault at a loopback-shaped Vault profile and print the profile list.
---

You will get a config file that names a token variable and does not contain a token. Then `nsvault providers` prints the profile without reading that variable.

## Write the file

Create `.nsvault.toml` in an empty directory:

```toml
version = 1
provider = "work"
prefix = "apps/production"

[providers.work]
kind = "vault"
address = "http://127.0.0.1:8200"
mount = "secret"
token_env = "VAULT_TOKEN"
allow_http_loopback = true
```

`127.0.0.1` is loopback. Plain HTTP to any other host is refused. `VAULT_TOKEN` is a name, not a token. Leave the variable unset for this tour.

## See the profile

From that directory:

```sh
nsvault providers
```

You should see one line for `work`, kind `vault`, with read, write, and ensure marked true. The command does not contact `127.0.0.1` and does not read `VAULT_TOKEN`.

```sh
nsvault dir
```

That prints the directory that holds `.nsvault.toml`.

Nothing here started Vault. A later `get` against this file fails until a server is actually listening and the named variable is set in the environment. That failure must not print a token or a response body.
