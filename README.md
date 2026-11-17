# nsvault

An automation-first secrets proxy: resolve a secret from a directory-scoped
provider without putting the value in `argv`, a log line, or a checked-in file.

The first increment is deliberately small. It implements a CLI, a reusable Rust
client, a conservative C ABI, directory discovery, shell integration, and seven
provider kinds. **No adapter has been verified against a live production
service in this repository.** The verification matrix below states exactly what
was exercised.

## Build

Rust 1.100.0 is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
cargo test
```

The library and C ABI are built by:

```sh
cargo build --release --lib
# target/release/libnsvault.so
# target/release/libnsvault.a
```

## Configuration

Two scopes are discovered, in this order:

1. The nearest `.nsvault.toml`, `.nsvault.yaml`, or `.nsvault.yml` from the
   current directory upwards.
2. Otherwise `$XDG_CONFIG_HOME/nsvault/config.toml` (or `config.yaml`,
   `config.yml`), falling back to `~/.config/nsvault/`.

`NSVAULT_CONFIG` may name a file or a directory and wins over both.
`--config FILE` wins over everything. A directory-scoped file is a complete
configuration: it is not merged with the user configuration, so put shared
provider profiles in the file you want to use.

Credentials are never written in the file. A token, password, or session is
named by an environment variable or an owner-only file:

```toml
version = 1
provider = "work"
prefix = "apps/production"

[providers.work]
kind = "vault"
address = "https://vault.example"
mount = "secret"
token_env = "VAULT_TOKEN"
# token_file = "work.token"   # relative to this config file
```

The same document can be YAML:

```yaml
version: 1
provider: work
prefix: apps/production
providers:
  work:
    kind: vault
    address: https://vault.example
    mount: secret
    token_env: VAULT_TOKEN
```

Unknown fields are rejected. A field named `token`, `password`, or `value` is
not accepted; use `token_env`, `token_file`, `password_env`, or
`password_file`. Plaintext HTTP is refused unless the address is loopback and
`allow_http_loopback = true` is explicit.

## Commands

```sh
nsvault ls [PREFIX]                 # names only, no values
nsvault get KEY [--field FIELD]     # exact bytes to stdout
nsvault set KEY                     # value from stdin or a hidden prompt
nsvault ensure KEY                  # create only if the provider confirms absence
nsvault search QUERY                # names only
nsvault exec -- CMD [ARGS...]       # secrets in the child environment
nsvault x -- CMD [ARGS...]          # alias
nsvault env --shell bash|zsh|fish   # shell exports for this directory
nsvault hook bash|zsh|fish          # directory hook
nsvault completion bash|zsh|fish|powershell|elvish
nsvault providers                   # configured profiles, no credentials read
nsvault dir                         # nearest configuration directory
```

`get` prints the exact value with no trailing newline unless `--newline` is
given. `set` refuses to take a value as an argument and refuses an empty value.
`ensure` uses the same stdin or hidden-prompt input. It creates the key only
when the provider confirms the key is absent, and it leaves an existing key
unchanged. It never deletes. Success writes no secret to stdout. `--json`
prints `{"status":"created"}` or `{"status":"present"}` and nothing else.
Auth, network, and other ambiguous errors are failures, not absence. A
provider without a race-safe create path — Infisical, GitHub, and every
read-only kind in this build — exits with an unsupported error and contacts no
provider. There is no `remove` command.
`search` and `ls` are name operations. Vault, Infisical, KeePass, Proton, and
GitHub listings are metadata-only. The Vaultwarden CLI has no metadata-only list
command, so its adapter fetches full items and keeps only names; see the
limitation below.

`exec` maps each key's basename to an environment variable, upper-cased and
sanitized (`apps/prod/db` becomes `DB`; `db#password` becomes `DB_PASSWORD`).
Use `--env-prefix` to namespace them and `--only` to select keys explicitly.
Collisions and invalid names fail rather than guessing.

### Directory hooks

`nsvault hook bash` (or `zsh`, `fish`) prints a shell function that tracks the
working directory and sets `NSVAULT_DIR`. It does **not** fetch secrets just
because you changed directory. Set `NSVAULT_AUTOLOAD=1` to opt into
`nsvault env` on directory change. On every directory change, names recorded in
`NSVAULT_LOADED_KEYS` are unset first, even if autoload is now disabled; only
fetching new values is gated by `NSVAULT_AUTOLOAD`. A child process or a shell
history still sees exported values, so autoload is a deliberate trade.

## Providers

| Kind | Read | Write | Ensure | Mechanism | Status in this repository |
| --- | --- | --- | --- | --- | --- |
| `vault` | yes | yes | yes | KV v2 HTTP API. Ensure uses metadata and subkeys, then CAS 0 create or a CAS patch. | Fixture plus opt-in testcontainer against `hashicorp/vault:1.21.4`; no production server |
| `openbao` | yes | yes | yes | Vault-compatible KV v2 API | Shares the `vault` adapter; kind not separately exercised |
| `keepass` | yes | no | no | `keepassxc-cli` | Fake-CLI fixture in the suite; a generated local KDBX was also exercised manually with `keepassxc-cli` 2.7.12 |
| `infisical` | yes | yes | no | v4 secrets HTTP API; service token or Universal Auth. `set` is a GET-then-POST/PATCH write. `ensure` is disabled because the Create endpoint's duplicate behavior is unproven. | Fixture-tested for list/get/set and for the `ensure` refusal; ensure is not verified and does not contact the provider |
| `vaultwarden` | yes | no | no | `bw` CLI, existing session | Fake `bw` fixture; `bw` not installed here |
| `proton` | yes | no | no | official `pass-cli`, existing session or PAT | Fake `pass-cli` fixture; not installed here |
| `github` | **no** | yes | **no** | Actions repository secrets REST API | Sealed-box unit test only; no live repository. Ensure is unsupported because PUT creates or updates and would overwrite. |

Key grammar:

- Vault/OpenBao: `path/to/secret` or `path/to/secret#field`. Without a field,
  a `value` field wins, otherwise a single-field secret is accepted.
- KeePass: `Group/Entry` returns the `Password` attribute;
  `Group/Entry#UserName` or another attribute selects one.
- Infisical: `SECRET_NAME`; fields are not part of the API.
- Vaultwarden: item name or UUID, optionally `#password`, `#username`,
  `#notes`, `#name`, `#id`, or a custom field name. Names must be unique;
  use the UUID when they are not.
- Proton: item title, optionally `#password` (default), `#username`, or
  another field name. Titles must be unique.
- GitHub: `SECRET_NAME`; list and set only. The API never returns a value.

The phrase "OpenTofu's version" in the request is treated as **OpenBao**, the
open-source Vault-compatible fork. OpenTofu is a Terraform fork and does not
provide a Vault product. No OpenTofu-specific integration is implemented.

### Deliberate limitations

- Vault KV v2 only. KV v1, dynamic database credentials, transit, and PKI are
  not exposed. Vault/OpenBao tokens are static for the process lifetime.
- Infisical lists one folder (`recursive = false`) and does not paginate; the
  v4 endpoint is unpaginated by design.
- KeePass is read-only. Database passwords and key files are the caller's
  responsibility; the password is written to `keepassxc-cli` stdin.
- Vaultwarden is read-only and never logs in or unlocks. `bw list items`
  returns full items, which this adapter parses and discards except for names.
- Proton writes are unsupported because the documented update command takes
  the value in `argv`.
- GitHub repository secrets only. Organization, environment, Codespaces, and
  Dependabot scopes are future work. `ensure` is unsupported: the secrets API
  has one PUT that creates or updates, and a check-then-PUT race would
  overwrite a value this adapter cannot read back.
- `ensure` without `#field` treats an existing Vault/OpenBao path as present,
  even when the `value` field is missing and even when the latest version is
  soft-deleted. It does not undelete or add fields in that form. `#field`
  reads the metadata version first, checks names through the subkeys API, then
  adds a missing field with `cas` set to that earlier version. A writer that
  creates the field between those two reads also advances the version, so the
  CAS fails and the field is re-checked instead of replaced. A lost CAS race is
  not retried with an unconditional write. A subkeys response without the
  documented `data.subkeys` map is an error, not field absence, and no patch is
  sent.
- Infisical `ensure` is disabled. The adapter returns "does not support
  ensure" and sends no request. The v4 Create (`POST`) has not been proven to
  reject a duplicate rather than upsert it against a live server; until that is
  recorded here, a check-then-create race could replace another writer's value.
  `set` is unaffected: it reads the name and then sends Update (`PATCH`) or
  Create (`POST`) under the same-user write lock.
- There is no remove, delete, or destroy operation.
- There is no backup import or export. See the roadmap. No age identity,
  recipient, or encrypted backup file is read or written.
- There is no request-rewriting proxy, placeholder syntax, or second
  executable. `exec` does not edit outbound HTTP bodies. A proxy remains an
  open question on the roadmap, not a committed design.
- No daemon, cache, keyring, or local encrypted store. Every call resolves from
  the provider.
- Shell completion lists commands and options; it does not dynamically complete
  provider key names.
- A directory-scoped configuration is complete on its own. Provider profiles
  from `~/.config/nsvault` are not merged into it.
- Windows and macOS were not exercised. The code avoids Unix-only calls outside
  the `bw`/`keepassxc-cli`/`pass-cli` process boundary, but that is not a
  portability claim. The same-user write lock uses Linux `flock` and was not
  exercised on those systems.

## Using the Rust crate

```rust
use nsvault::Client;

let client = Client::open(std::path::Path::new(".nsvault.toml"))?;
let keys = client.list(Some("work"), "apps/production")?;
let value = client.get(Some("work"), "apps/production/db#password")?;
// value.expose() is the only accessor; Debug is redacted.
```

`Client` is synchronous and can be shared across threads. Provider adapters are
created per operation from the configuration, so a token read at process start
is not cached by the client. `set` and `ensure` take the same same-user write
lock as the CLI, so two threads or processes that write the same provider scope
serialize; the call can block, and a lock failure is returned as an error
rather than performed unlocked. This requires both writers to resolve the same
lock directory: the same OS user and the same `NSVAULT_LOCK_DIR`, or the same
`XDG_STATE_HOME`/`HOME` when it is unset.

## C ABI

See [`include/nsvault.h`](include/nsvault.h). The ABI is intentionally narrow:

- `nsvault_client_open` / `nsvault_client_close`
- `nsvault_list`, `nsvault_get`, `nsvault_set`, `nsvault_ensure`
- `nsvault_last_error`
- `nsvault_bytes_free`

Every entry point catches panics. Strings are NUL-terminated UTF-8. Output
buffers are caller-owned, freed exactly once, and zeroed before release. A
status of `0` is success and `1` is an error. The last error is redacted and
per-thread. `nsvault_client_close` must not race another call using the same
handle. There is no callback, async, or streaming API. `nsvault_set` and
`nsvault_ensure` take the same same-user write lock as the CLI; they may block
behind another nsvault writer, and a lock failure is returned as status `1`
instead of writing unlocked. Coordination requires the same lock directory:
the same OS user and the same `NSVAULT_LOCK_DIR`, or the same
`XDG_STATE_HOME`/`HOME` when it is unset. Different values are different locks.

Smoke test:

```sh
cargo build --release --lib
cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnsvault \
   -Wl,-rpath,"$PWD/target/release" -o /tmp/nsvault-ffi-smoke
/tmp/nsvault-ffi-smoke
```

## Security model

- The value never goes through `argv`: `set` reads stdin or a hidden prompt.
- Providers read credentials from named environment variables or owner-only
  files; configuration cannot contain a literal token.
- HTTP responses and child-process output are not included in errors. A failed
  provider call names the key and status, not the body or value.
- `search` is a name operation. It does not call a value endpoint.
- Redirects are disabled for provider HTTP requests, so an authorization header
  is not forwarded to a second origin.
- `set` and `ensure` take a same-user advisory file lock on this machine
  before they contact the provider. The CLI, the Rust `Client`, and the C ABI
  share it. The lock identity is a hash of the canonical address plus
  non-secret scope (Vault/OpenBao: mount and namespace, shared across those two
  kind labels; Infisical: project, environment, and folder; GitHub: owner and
  repository). Profile names and config file paths are not part of it.
  `https://Host:443/path/` and `https://host/path` match. `localhost` and
  `127.0.0.1` do not. The lock file lives under
  `$XDG_STATE_HOME/nsvault/locks` or `~/.local/state/nsvault/locks`. A missing
  directory is created `0700`; lock files are created `0600` and must be
  regular, single-link, owner-only files. `NSVAULT_LOCK_DIR` overrides the
  directory. The path is resolved one component at a time and the verified
  directory handle is retained, so the lock file is opened relative to it;
  every parent must not be writable by other users (a sticky directory such as
  `/tmp` is allowed). An existing directory is never chmodded: it must already
  be owned by this user and inaccessible to group and others, and the
  directory itself must not be a symbolic link. Creation respects the process
  umask: a directory that does not end up exactly owner-only is an error, not
  something that is chmodded. Writers coordinate only when they resolve the
  same lock directory: the same OS user and the same `NSVAULT_LOCK_DIR`, or the
  same `XDG_STATE_HOME`/`HOME` when it is unset. Acquisition fails closed, with
  no unlocked fallback and no timeout, and a lock failure is an error instead
  of a write. The kernel releases the lock when the process exits, including a
  crash. This does not stop the Vault CLI, another host, or another OS user.
  Provider CAS is still required for those writers. Linux `flock` is what this
  workspace can exercise; Windows and macOS are not.
- `Secret` has no `Display`; `Debug` prints `Secret([REDACTED])`.
- The C ABI zeroes output buffers on free.

Residual risks are real: a child process, a shell, or a user who asks `get` can
print a value; an exported environment is readable by that process tree; a
provider may log its own request. This project does not claim to prevent those.

## Container integration tests

Vault has an opt-in, isolated testcontainers test pinned to
`hashicorp/vault:1.21.4`:

```sh
cargo test --test container_vault -- --ignored --nocapture
```

It ran successfully here and removed only its own container. Vaultwarden and
Infisical container tests are deferred with concrete prerequisites in
[`docs/testcontainers.md`](docs/testcontainers.md); no test is claimed for them.
Container tests do not run in the default gate.

## Floci / cloud emulation

Floci's AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault emulation
are confirmed by the vendor documentation, but this increment has no AWS, GCP,
or Azure provider to test. The tool is not installed here, no emulator was
started, and no Docker cleanup was performed. See
[`docs/floci.md`](docs/floci.md) for the support evidence and the conditional
test plan. A cloud provider stays "unimplemented" or "fixture-only" until that
plan actually runs.

## Roadmap

The provider boundary is a Rust trait plus one configuration variant and one
metadata row. Future adapters, **none of which are implemented today**:

- Azure Key Vault
- AWS Secrets Manager / SSM Parameter Store
- Google Cloud Secret Manager
- Cloudflare Secrets Store
- 1Password (Service Accounts / Connect)
- Bitwarden Secrets Manager
- Doppler
- Akeyless
- Pulumi ESC
- Vercel Environment Variables
- OCI Vault

Adding one means: a validated non-secret config variant, an adapter implementing
`Provider`, a capability row, fixture tests, and a doc update. There is no plugin
ABI, dynamic loading, or network fallback; an unsupported `kind` is rejected at
configuration parse time.

Backup import and export are also not implemented. A later increment may add
one common encrypted file format, using [age](https://age-encryption.org/), so
a store can be backed up and moved between machines. That work is not started.
This build has no `import` command, no `export` command, no age recipient or
identity field, and no age dependency. An age file created elsewhere is not a
nsvault backup and cannot be loaded.

A local proxy that replaces secret placeholders in agent requests is a future
consideration, not a design this project has accepted. One sketch, still
uncommitted, is a separate executable that shares crates with `nsvault`
instead of growing the `nsvault` binary. Nothing here chooses that split,
a placeholder syntax, a listen address, or a wire format.

If that work is ever started, the trust boundary has to be explicit: the
process would see secret values and the request bodies it rewrites, so it is
not a transparent hop and not a reason to log either. It would also need
injection and egress controls before it could be used: which hosts it may
contact, which placeholders it may expand, and a refusal to send a value to
an unexpected URL. None of that exists today. There is no proxy binary, no
placeholder syntax, and no local listener. `nsvault exec` only exports names
into a child environment; it does not rewrite request bodies.

## Verification in this change

Run and reported:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --lib
cc examples/ffi_smoke.c ... && /tmp/nsvault-ffi-smoke
```

See the final report for the exact counts and any caveats.
