# nsvault

An automation-first secrets proxy: resolve a secret from a directory-scoped
provider without putting the value in `argv`, a log line, or a checked-in file.

The first increment is deliberately small. It implements a CLI, a reusable Rust
client, a conservative C ABI, directory discovery, shell integration, and ten
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
`ensure` uses the same stdin or hidden-prompt input. It writes only through a
provider path that cannot replace an existing key: a successful atomic create
confirms absence, and a provider-confirmed duplicate is reported present. It
never deletes. Success writes no secret to stdout. `--json` prints
`{"status":"created"}` or `{"status":"present"}` and nothing else. Auth,
network, and other ambiguous errors are failures, not absence. A provider
whose adapter has no race-safe create path — GitHub, GCP Secret Manager,
Azure Key Vault, Vaultwarden, and every read-only kind in this build — exits
with an unsupported error and contacts no provider. There is no `remove`
command.
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
| `infisical` | yes | yes | yes | v4 secrets HTTP API; service token or Universal Auth. `set` is a GET-then-POST/PATCH write. `ensure` sends only Create (`POST`); the pinned server's partial unique index rejects a duplicate with `400`, which the adapter reports present. A create that loses a concurrent insert race is an error. | Fixture-tested for list/get/set/ensure, plus an opt-in testcontainer against `infisical/infisical:v0.167.11` with pinned PostgreSQL and Redis, including concurrent duplicate creates; no production server |
| `vaultwarden` | yes | yes | no | `bw` CLI with a supplied unlocked session; writes send encoded item JSON on stdin to `bw create item`/`bw edit item` | Fake `bw` fixture plus an opt-in testcontainer against `vaultwarden/server:1.37.5` with `@bitwarden/cli` 2025.6.1; `bw` not installed here for production use |
| `proton` | yes | no | no | official `pass-cli`, existing session or PAT | Fake `pass-cli` fixture; not installed here |
| `github` | **no** | yes | **no** | Actions repository secrets REST API | Sealed-box unit test only; no live repository. Ensure is unsupported because PUT creates or updates and would overwrite. |
| `aws-secrets-manager` | yes | yes | yes | Secrets Manager JSON 1.1 API with local SigV4 signing | Opt-in Floci test against `floci/floci:2.5.0`; signer unit-tested against AWS's published SigV4 vectors; no AWS account |
| `gcp-secret-manager` | yes | yes | **no** | Secret Manager v1 REST API | Opt-in Floci test against `floci/floci-gcp:0.13.0`; no GCP project. Ensure is refused because create and add-version are separate, non-atomic calls. |
| `azure-key-vault` | yes | yes | no | Key Vault secrets REST API `7.4` | Opt-in Floci test against `floci/floci-az:0.17.0`; no Azure account. Ensure is unsupported because Key Vault has no conditional create. |

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
- AWS Secrets Manager: `SECRET_NAME`; no fields. The adapter reads and writes
  the string value, or reads a base64-encoded binary value.
- GCP Secret Manager: `SECRET_ID`; no fields, latest version only. Every `set`
  adds a version.
- Azure Key Vault: `SECRET_NAME`; no fields, latest version only. Every `set`
  adds a version.

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
- Vaultwarden never logs in or unlocks; the session must already be unlocked when
  the adapter runs. `bw list items` returns full items, which this adapter
  parses and discards except for names. A write reads the whole item, changes
  one field, and sends the item back through `bw edit item`, so the session
  needs write access. Writes require UTF-8 text, refuse an empty value, and are
  capped at 1 MiB. A key without a field writes `login.password` (or `notes` on
  a secure note); `#password`, `#username`, `#notes`, and `#name` are the named
  fields, and any other field name updates or appends a custom field. A missing
  item name is created as a login. There is no `ensure`: a create-then-race
  cannot be made atomic through this CLI, and two items with the same name are
  legal in Bitwarden.
  A write holds one shared lock, runs `bw sync` (failing closed), and only then
  reads and updates the item. Two profiles with separate CLI state directories
  therefore update the same item without losing a field. Reads (`get`, `ls`)
  use the local copy and can be stale until a write or an explicit sync.
  Concurrent external clients are not coordinated. The CLI sends
  `lastKnownRevisionDate` from the synced copy, and the Bitwarden server and
  Vaultwarden reject an update whose revision is more than one second stale
  (Bitwarden `CipherService.ValidateCipherLastKnownRevisionDate`, Vaultwarden
  `update_cipher_from_data`). A change before the sync is incorporated (the
  selected field is replaced) and a change between the sync and the edit is
  rejected where the server enforces the check. That is not coordination: the
  one-second window can let an update through, a server may not enforce the
  check, and a later accepted write wins. This adapter does not claim to
  preserve concurrent external changes. Writes take one conservative same-user
  advisory lock shared by every Vaultwarden profile on this machine, because
  the configuration has no server address and wrapper paths differ.
- Proton writes are unsupported because the documented update command takes
  the value in `argv`.
- GitHub repository secrets only. Organization, environment, Codespaces, and
  Dependabot scopes are future work. `ensure` is unsupported: the secrets API
  has one PUT that creates or updates, and a check-then-PUT race would
  overwrite a value this adapter cannot read back.
- AWS credentials are static for the process lifetime: an access key id, secret
  access key, and optional session token from named environment variables or
  owner-only files. There is no STS AssumeRole, IMDS, credential-provider
  chain, or refresh. SigV4 signing is implemented locally; the emulator does
  not reject an unsigned request, so the emulator test does not prove AWS would
  accept the signature. The signer is unit-tested against AWS's published
  `get-vanilla` and `post-vanilla-query` vectors. No AWS account was used.
- GCP authentication is a static OAuth 2.0 access token from a named
  environment variable or owner-only file. There is no Application Default
  Credentials, service-account JWT exchange, impersonation, or refresh, so a
  long-running process fails when the token expires. `allow_anonymous` exists
  only for a loopback emulator and is refused for any non-loopback endpoint.
  No GCP project was used. `ensure` is refused: Secret Manager has no atomic
  create-with-version call. A create followed by a failed add-version can leave
  an empty secret, and a retry would then report Present.
- Azure authentication is a static bearer token from a named environment
  variable or owner-only file. There is no Microsoft Entra ID
  client-credential flow, managed identity, challenge-based auth, or refresh.
  `ensure` is unsupported because Key Vault has no conditional create and a
  check-then-PUT would race. Only the latest secret version is read. No Azure
  account was used.
- The cloud emulator tests prove that these adapters speak the pinned Floci
  images' wire protocols. They do not prove production authentication, IAM
  policy enforcement, quota behavior, regional endpoints, or service edge
  cases.
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
- Infisical `ensure` sends only the v4 Create (`POST`); it does not check for
  absence first. In v0.167.11 the server enforces the partial unique index
  `uq_secrets_v2_key_folder_id_shared` on (`key`, `folderId`) for shared
  secrets, so a duplicate insert cannot replace the existing row. A sequential
  duplicate is HTTP `400` with the documented "already exists" message and is
  reported `present`. A create that loses a concurrent insert race is an error
  (observed as HTTP `500`), never a silent update or a `present` result. A
  `200` response carrying only an approval request is also an error, not
  `created`. `set` is unchanged: it reads the name and then sends Update
  (`PATCH`) or Create (`POST`) under the same-user write lock.
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
- Provider constructors revalidate the endpoint scheme, the loopback-only HTTP
  rule, cloud project/region/API-version fields, and the GCP anonymous
  restriction. Calling a constructor directly does not bypass the configuration
  checks.
- Vault/OpenBao `set`/`ensure`, GitHub `set`, Infisical `set`, Vaultwarden
  `set`, and cloud `set` (AWS `ensure` too) take a same-user advisory file lock on this machine
  before they contact the provider. The CLI, the Rust `Client`, and the C ABI
  share the mechanism. GCP and Azure `ensure` remain unsupported and send no
  request, so there is no write to lock. The lock identity is a hash of the
  canonical address plus non-secret scope (Vault/OpenBao: mount and namespace,
  shared across those two kind labels; Infisical: project, environment, and
  folder; GitHub: owner and repository; Vaultwarden: one shared identity for
  every profile on this machine, because wrapper paths differ). For the clouds it is deliberately
  conservative:
  - AWS recognizes `secretsmanager.{region}` and
    `secretsmanager-fips.{region}` on `amazonaws.com`, `amazonaws.com.cn`,
    and `api.aws` and maps those spellings to one lock per region, so
    standard, FIPS, and dual-stack endpoints for the same regional vault
    serialize. A custom endpoint keeps its canonical origin plus region.
  - GCP recognizes `secretmanager.*.googleapis.com` and maps those spellings
    to one lock for the service. The project is not part of the identity,
    because a project id and its numeric project number name the same project
    and cannot be mapped locally; this over-serializes every GCP project using
    the service. A custom endpoint keeps its canonical origin.
  - Azure recognizes public, sovereign, and private-link Key Vault suffixes
    and maps them to one lock per vault name. A custom endpoint keeps its
    canonical origin, including the emulator's vault path.
  Profile names, config file paths, and every credential value are excluded.
  Two profiles for one endpoint and scope share a lock even when they use
  different tokens or access keys. The resulting over-serialization of AWS
  accounts in one region, GCP projects on one service, or same-named Azure
  vaults in different clouds is safe; it never under-serializes a recognized
  alias. The canonical origin is normalized for scheme and host case, default
  ports, and a trailing slash, so `https://Host:443/path/` and
  `https://host/path` match. `localhost` and `127.0.0.1` do not.
  **Bound on custom aliases:** an arbitrary URL alias that is not one of the
  recognized provider host patterns — a CNAME, a reverse proxy, custom private
  DNS, or a private endpoint whose name does not match the recognized suffix —
  is treated as a distinct custom endpoint. Two profiles that reach one vault
  through different unrecognized names are not serialized by this lock.
  Cooperating nsvault writers must use the provider's recognized endpoint or
  the same custom endpoint spelling.
  The lock file lives under
  `$XDG_STATE_HOME/nsvault/locks` or `~/.local/state/nsvault/locks`. A missing
  directory is created `0700`; lock files are created `0600` and must be
  regular, single-link, owner-only files. `NSVAULT_LOCK_DIR` overrides the
  directory. The path is resolved one component at a time and the verified
  directory handle is retained, so the lock file is opened relative to it; no
  component of the path may be a symbolic link. The path must be absolute; a
  relative `NSVAULT_LOCK_DIR` or `XDG_STATE_HOME` is rejected. On a system with
  a symlinked home or state directory, set `NSVAULT_LOCK_DIR` to a real,
  non-symlink absolute path. Every parent must be owned by root or this user:
  an owner can rename entries even without write permission. A parent writable
  by group or others must also be sticky. An existing directory is never
  chmodded: it must already be owned by this user and inaccessible to group
  and others. Creation respects the process umask: a directory that does not
  end up exactly owner-only is an error, not something that is chmodded.
  Writers coordinate only when they resolve the same lock directory: the same
  OS user and the same `NSVAULT_LOCK_DIR`, or the same `XDG_STATE_HOME`/`HOME`
  when it is unset.
  Acquisition fails closed, with no unlocked fallback and no timeout, and a
  lock failure is an error instead of a write. The lock is advisory: while a
  write may be in progress, do not remove, rename, or replace the lock
  directory or its `write-*.lock` files. A new inode or directory is a
  different lock, so a hostile same-user process (or root) can break
  cooperation; the lock is not a boundary against it. The kernel releases the
  lock when the process exits, including a crash. This does not stop the Vault
  CLI, another host, or another OS user. Provider CAS is still required for
  those writers. Linux `flock` is what this workspace can exercise; Windows and
  macOS are not.
- `Secret` has no `Display`; `Debug` prints `Secret([REDACTED])`.
- The C ABI zeroes output buffers on free.

Residual risks are real: a child process, a shell, or a user who asks `get` can
print a value; an exported environment is readable by that process tree; a
provider may log its own request. This project does not claim to prevent those.

## Container integration tests

The three cloud adapters have opt-in Floci tests pinned to release images:

```sh
cargo test --test container_cloud -- --ignored --nocapture
```

It starts `floci/floci:2.5.0`, `floci/floci-gcp:0.13.0`, and
`floci/floci-az:0.17.0` on random loopback-mapped ports, writes only obviously
fake fixture values, and lets testcontainers remove only those containers.
Azure Functions is disabled in the Azure container so no Docker socket is
needed. Three more container tests cover Vault, Infisical, and Vaultwarden:

```sh
cargo test --test container_vault -- --ignored --nocapture
cargo test --test container_infisical -- --ignored --nocapture
NSVAULT_TEST_BW=/path/to/pinned/bw \
  cargo test --test container_vaultwarden -- --ignored --nocapture
```

The Infisical test runs `infisical/infisical:v0.167.11` with
`postgres:17-alpine` and `redis:7.4-alpine`, bootstraps the instance, creates a
project, and covers `list`, `get`, `set`, and `ensure`. Eight concurrent Create
requests prove that exactly one succeeds, every loser fails, and the winner's
value is the one that remains. The Vaultwarden test runs
`vaultwarden/server:1.37.5` with a pinned `@bitwarden/cli` 2025.6.1, creates a
throwaway account inside the container, and covers `list`, `get`, and `set`
including sibling fields. Exact evidence and prerequisites are in
[`docs/testcontainers.md`](docs/testcontainers.md). Container tests do not run
in the default gate.

The AWS JSON request contract has a separate loopback fixture test:

```sh
cargo test --test aws_contract
```

It records `CreateSecret` and `PutSecretValue` bodies and asserts every write
carries a valid CSPRNG `ClientRequestToken`; the Put retry after a create
conflict must reuse the same token.

## Floci / cloud emulation

The AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault adapters are
implemented and exercised against pinned Floci release images. The Floci CLI
was not installed; the images were pulled and run directly with Docker:

```sh
docker pull floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
docker pull floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
docker pull floci/floci-az:0.17.0@sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea

docker run -d --rm --name nsvault-floci-aws -p 127.0.0.1:4566:4566 \
  floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
docker run -d --rm --name nsvault-floci-gcp -p 127.0.0.1:4588:4588 \
  floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
docker run -d --rm --name nsvault-floci-az \
  -e FLOCI_AZ_SERVICES_FUNCTIONS_ENABLED=false -p 127.0.0.1:4577:4577 \
  floci/floci-az:0.17.0@sha256:40f1bbf1ef13569c6eacb47e565bf4cd28785ca833208dcc074910e13aec64ea
```

The opt-in test and a manual CLI run covered list, get, set, ensure (AWS),
GCP's and Azure's refused ensure, and search. Exact commands, outputs, and
limitations are in [`docs/floci.md`](docs/floci.md). No global Docker cleanup
was performed. These tests do not make the adapters "production verified": the
emulator does not validate AWS SigV4 signatures, and it does not prove real
cloud authentication, IAM, quotas, or regional behavior.

## Roadmap

The provider boundary is a Rust trait plus one configuration variant and one
metadata row. Future adapters, **none of which are implemented today**:

- AWS SSM Parameter Store (Secrets Manager is implemented)
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

Run in this worktree on 2026-11-17:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --lib
cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnsvault \
   -Wl,-rpath,"$PWD/target/release" -o <tmp>/nsvault-ffi-smoke
<tmp>/nsvault-ffi-smoke
```

Observed:

```text
cargo fmt --check                         clean
cargo clippy --all-targets -- -D warnings clean
cargo test                                71 lib + 1 AWS contract + 26 CLI
                                          + 3 FFI passed;
                                          0 failed; 3 cloud + 1 Vault
                                          container tests ignored
cargo build --release --lib               succeeded
C ABI smoke                               exit 0, "redacted error received
                                          (34 bytes)"
```

The opt-in Vault and cloud emulator tests also passed:

```sh
cargo test --test container_vault -- --ignored --nocapture
# 1 passed; 0 failed

cargo test --test container_cloud -- --ignored --nocapture
# 3 passed; 0 failed
```

The C ABI binary was written under a private cache directory because `/tmp` on
this machine was at a per-process disk quota; the compile and link command was
otherwise the documented one. No claim here covers a live cloud service.
