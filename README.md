# neo-vault (`nvault`)

neo-vault (`nvault`) retrieves secrets from configured vault drivers for
interactive use and automation. Its directory-scoped configuration selects a
provider; `exec` exposes selected values to a child process without putting them
in command-line arguments or checked-in configuration.

This repository includes a CLI, reusable Rust client, conservative C ABI,
directory discovery, and shell integration. Provider support varies: some
adapters are fixture- or emulator-tested, while others have opt-in container
tests. **No adapter has been verified against a live production service in this
repository.** The matrix below describes the evidence for each provider.

## Build

Rust 1.100.0 is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
cargo test
```

The library and C ABI are built by:

```sh
cargo build --release --lib
# target/release/libnvault.so
# target/release/libnvault.a
```

## Configuration

Two scopes are discovered, in this order:

1. The nearest `.nvault.toml`, `.nvault.yaml`, or `.nvault.yml` from the
   current directory upwards.
2. Otherwise `$XDG_CONFIG_HOME/nvault/config.toml` (or `config.yaml`,
   `config.yml`), falling back to `~/.config/nvault/`.

`NVAULT_CONFIG` may name a file or a directory and wins over both.
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
nvault ls [PREFIX]                 # names only, no values
nvault get KEY [--field FIELD]     # exact bytes to stdout
nvault set KEY                     # value from stdin or a hidden prompt
nvault ensure KEY                  # create only if the provider confirms absence
nvault search QUERY                # names only
nvault exec -- CMD [ARGS...]       # secrets in the child environment
nvault x -- CMD [ARGS...]          # alias
nvault env --shell bash|zsh|fish   # shell exports for this directory
nvault hook bash|zsh|fish          # directory hook
nvault completion bash|zsh|fish|powershell|elvish
nvault providers                   # configured profiles, no credentials read
nvault dir                         # nearest configuration directory
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
Azure Key Vault, Vaultwarden, KeePass, and every read-only kind in this build
— exits with an unsupported error and contacts no provider. There is no
`remove` command.
`search` and `ls` are name operations. Vault, Infisical, KeePass, and GitHub
listings are metadata-only. The Vaultwarden CLI has no metadata-only list
command, and the Proton Pass CLI fetches full items even when it prints a
summary; those adapters keep only names. See the limitations below.

`exec` maps each key's basename to an environment variable, upper-cased and
sanitized (`apps/prod/db` becomes `DB`; `db#password` becomes `DB_PASSWORD`).
Use `--env-prefix` to namespace them and `--only` to select keys explicitly.
Collisions and invalid names fail rather than guessing.

### Directory hooks

`nvault hook bash` (or `zsh`, `fish`) prints a shell function that tracks the
working directory and sets `NVAULT_DIR`. It does **not** fetch secrets just
because you changed directory. Set `NVAULT_AUTOLOAD=1` to opt into
`nvault env` on directory change. On every directory change, names recorded in
`NVAULT_LOADED_KEYS` are unset first, even if autoload is now disabled; only
fetching new values is gated by `NVAULT_AUTOLOAD`. A child process or a shell
history still sees exported values, so autoload is a deliberate trade.

## Providers

| Kind | Read | Write | Ensure | Mechanism | Status in this repository |
| --- | --- | --- | --- | --- | --- |
| `vault` | yes | yes | yes | KV v2 HTTP API. Ensure uses metadata and subkeys, then CAS 0 create or a CAS patch. | Fixture plus opt-in testcontainer against `hashicorp/vault:1.21.4`; no production server |
| `openbao` | yes | yes | yes | Vault-compatible KV v2 API | Opt-in testcontainer against `openbao/openbao:2.3.1`; no production server |
| `keepass` | yes | yes | **no** | `keepassxc-cli`; `edit -p`/`add -p` read the database password and the value from stdin, never `argv`. `ensure` is refused: the CLI's check-and-save is not atomic against an external writer. | Fake-CLI fixture in the suite plus opt-in generated local KDBX tests for the round trip, concurrent writers, and duplicate add (`cargo test --test keepass_kdbx -- --ignored`) with `keepassxc-cli` 2.7.12; no production vault |
| `infisical` | yes | yes | yes | v4 secrets HTTP API; service token or Universal Auth. `set` is a GET-then-POST/PATCH write. `ensure` sends only Create (`POST`); the pinned server's partial unique index rejects a duplicate with `400`, which the adapter reports present. A create that loses a concurrent insert race is an error. | Fixture-tested for list/get/set/ensure, plus an opt-in testcontainer against `infisical/infisical:v0.167.11` with pinned PostgreSQL and Redis, including concurrent duplicate creates; no production server |
| `vaultwarden` | yes | yes | no | `bw` CLI with a supplied unlocked session; writes send encoded item JSON on stdin to `bw create item`/`bw edit item` | Fake `bw` fixture plus an opt-in testcontainer against `vaultwarden/server:1.37.5` with `@bitwarden/cli` 2025.6.1; `bw` not installed here for production use |
| `proton` | yes | create only | no | official `pass-cli` 2.7.1; stdin JSON template creates absent login items, existing items cannot be updated | Fake `pass-cli` fixture; no live Proton service verified |
| `github` | **no** | yes | **no** | Actions repository secrets REST API | Sealed-box unit test only; no live repository. Ensure is unsupported because PUT creates or updates and would overwrite. |
| `aws-secrets-manager` | yes | yes | yes | Secrets Manager JSON 1.1 API with local SigV4 signing | Opt-in Floci test against `floci/floci:2.5.0`; signer unit-tested against AWS's published SigV4 vectors; no AWS account |
| `gcp-secret-manager` | yes | yes | **no** | Secret Manager v1 REST API | Opt-in Floci test against `floci/floci-gcp:0.13.0`; no GCP project. Ensure is refused because create and add-version are separate, non-atomic calls. |
| `azure-key-vault` | yes | yes | no | Key Vault secrets REST API `7.4` | Opt-in Floci test against `floci/floci-az:0.17.0`; no Azure account. Ensure is unsupported because Key Vault has no conditional create. |

Key grammar:

- Vault/OpenBao: `path/to/secret` or `path/to/secret#field`. Without a field,
  a `value` field wins, otherwise a single-field secret is accepted.
- KeePass: `Group/Entry` returns the `Password` attribute;
  `Group/Entry#UserName` or another attribute selects one. Writes accept no
  field or `Password` only; every other attribute is read-only and `ensure` is
  unsupported.
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
- KeePass writes one entry's `Password` field. `#UserName`, `#URL`, `#Notes`,
  custom attributes, tags, and attachments are read-only because `edit` takes
  those values in `argv`; this adapter never puts a value there. A write
  requires `password_env`, `password_file`, or a key-file-only database: the
  database password and the value share the child's stdin, so an interactive
  database prompt cannot be combined with them. A value must be UTF-8 without
  a newline or NUL and is capped at 1 MiB; the stdin line ending means a value
  cannot end in a newline.
  An existing entry is updated with `edit -p`, which changes only the password
  and preserves the other fields. A missing entry is created with `add -p` only
  when its parent group already exists; missing groups are not created.
  `set` holds one same-user advisory lock shared by every KeePass write on this
  machine, so cooperating nvault processes (including the Rust `Client` and
  the C ABI) serialize their read-modify-write. The identity is deliberately
  one shared value, not a database path or inode: two hard links to one KDBX
  have different paths, and `keepassxc-cli` may replace the file atomically, so
  either identity could let two writers bypass each other. This over-serializes
  every KeePass database, which is coarser than one vault and never finer.
  `keepassxc-cli` has no conditional write and does not honor that lock: the
  KeePassXC GUI, another tool, another host, or a different OS user can change
  the KDBX between our read and save and lose the other change.
  `ensure` is unsupported and refuses without contacting the database. The
  CLI's check followed by `add` is not atomic against an external writer, and
  its observed refusal of a duplicate path is not a documented conditional
  create. The generated-KDBX test records that duplicate refusal as evidence;
  it does not make `ensure` safe, so the command is disabled.
  Database passwords and key files remain the caller's responsibility; both are
  written to `keepassxc-cli` stdin, never `argv`.
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
- Proton `set` creates a login only when its title is absent. It supports
  `#password` (default), `#username`, `#email`, and `#totp_uri`, with UTF-8
  values sent as a JSON template over stdin. Existing titles and other fields
  are refused; `pass-cli` 2.7.1 updates expose values in argv. Same-user nvault
  writers share a conservative lock, but the list-then-create check is **not
  atomic** against other clients, users, hosts, or differently configured lock
  directories; concurrent creation can produce duplicate titles. `ensure` is
  unsupported. A failed create process has an indeterminate outcome: the item
  may exist, so inspect the vault before retrying. `providers` reports
  `write=false` (no overwrite) and `create=true`; Rust callers can use
  `Client::capabilities` and `Client::can_create`. This uses the separately
  installed CLI, not its GPL library.
- Proton listings are not a metadata-only fetch. In `pass-cli` 2.7.1,
  `item list --output json` downloads and decrypts every `Item` before
  serializing an `ItemSummary` without content. The adapter keeps only titles
  and never returns item content, but the CLI process did fetch it.
- A configured Proton token runs in a private per-process session directory
  under a verified temporary parent with the filesystem key provider, so it
  cannot reuse or overwrite the default `pass-cli` session. The parent walk
  rejects symlinks, foreign owners, and writable non-sticky directories. After
  login the adapter requires `info --output json` to identify a personal access
  token; a user session is rejected. `list` and `get` on one provider instance
  are serialized. Without a token, the existing `pass-cli` session is used
  unchanged. The directory is removed on drop; if removal fails, a warning is
  printed and the directory is left for the system to clean, and a killed
  process cannot run cleanup. Token mode fails closed on platforms without the
  hardened directory walk, or when the temporary path is not a trusted,
  symlink-free location. This is based on the pinned 2.7.1 source, not a live
  service.
- Proton `vault` filters by vault name, not share ID. Duplicate item titles
  must be renamed or narrowed to a vault where the title is unique.
  An explicitly configured `token_env` must be set; it never falls back to
  an existing session. If omitted, `token_file` is used when configured;
  otherwise the existing session is used only if the standard token environment
  variable is absent. If it is present, nvault fails closed: explicitly set
  `token_env = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"` to use it, or unset the
  variable to use the session. This replaces automatic discovery; YAML `null`
  and programmatic `None` follow the same rule.
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
  `200` response must be the documented secret object and identify the
  requested key, project, environment, and shared type; an approval-only,
  malformed, empty, or mismatched body is a redacted error, not `created`.
  `set` is unchanged: it reads the name and then sends Update
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
  from `~/.config/nvault` are not merged into it.
- Windows and macOS were not exercised. The code avoids Unix-only calls outside
  the `bw`/`keepassxc-cli`/`pass-cli` process boundary, but that is not a
  portability claim. The same-user write lock uses Linux `flock` and was not
  exercised on those systems.

## Using the Rust crate

```rust
use nvault::Client;

let client = Client::open(std::path::Path::new(".nvault.toml"))?;
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
lock directory: the same OS user and the same `NVAULT_LOCK_DIR`, or the same
`XDG_STATE_HOME`/`HOME` when it is unset.

## C ABI

See [`include/nvault.h`](include/nvault.h). The ABI is intentionally narrow:

- `nvault_client_open` / `nvault_client_close`
- `nvault_list`, `nvault_get`, `nvault_set`, `nvault_ensure`
- `nvault_last_error`
- `nvault_bytes_free`

Every entry point catches panics. Strings are NUL-terminated UTF-8. Output
buffers are caller-owned, freed exactly once, and zeroed before release. A
status of `0` is success and `1` is an error. The last error is redacted and
per-thread. `nvault_client_close` must not race another call using the same
handle. There is no callback, async, or streaming API. `nvault_set` and
`nvault_ensure` take the same same-user write lock as the CLI; they may block
behind another nvault writer, and a lock failure is returned as status `1`
instead of writing unlocked. Coordination requires the same lock directory:
the same OS user and the same `NVAULT_LOCK_DIR`, or the same
`XDG_STATE_HOME`/`HOME` when it is unset. Different values are different locks.

Smoke test:

```sh
cargo build --release --lib
cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnvault \
   -Wl,-rpath,"$PWD/target/release" -o /tmp/nvault-ffi-smoke
/tmp/nvault-ffi-smoke
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
  `set`, KeePass `set`, and cloud `set` (AWS `ensure` too) take a same-user
  advisory file lock on this machine before they contact the provider. The CLI,
  the Rust `Client`, and the C ABI share the mechanism. KeePass, GCP, and Azure
  `ensure` remain unsupported and send no request, so there is no write to
  lock. The lock identity is a hash of the canonical address plus non-secret
  scope (Vault/OpenBao: mount and namespace, shared across those two kind
  labels; Infisical: project, environment, and folder; GitHub: owner and
  repository; Vaultwarden: one shared identity for every profile on this
  machine, because wrapper paths differ; KeePass: one shared identity for every
  KDBX write on this machine, because hard links and atomic file replacement
  make a path or inode identity unsafe). For the clouds it is deliberately
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
  Cooperating nvault writers must use the provider's recognized endpoint or
  the same custom endpoint spelling.
  The lock file lives under
  `$XDG_STATE_HOME/nvault/locks` or `~/.local/state/nvault/locks`. A missing
  directory is created `0700`; lock files are created `0600` and must be
  regular, single-link, owner-only files. `NVAULT_LOCK_DIR` overrides the
  directory. The path is resolved one component at a time and the verified
  directory handle is retained, so the lock file is opened relative to it; no
  component of the path may be a symbolic link. The path must be absolute; a
  relative `NVAULT_LOCK_DIR` or `XDG_STATE_HOME` is rejected. On a system with
  a symlinked home or state directory, set `NVAULT_LOCK_DIR` to a real,
  non-symlink absolute path. Every parent must be owned by root or this user:
  an owner can rename entries even without write permission. A parent writable
  by group or others must also be sticky. An existing directory is never
  chmodded: it must already be owned by this user and inaccessible to group
  and others. Creation respects the process umask: a directory that does not
  end up exactly owner-only is an error, not something that is chmodded.
  Writers coordinate only when they resolve the same lock directory: the same
  OS user and the same `NVAULT_LOCK_DIR`, or the same `XDG_STATE_HOME`/`HOME`
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
needed. Four more container tests cover Vault, OpenBao, Infisical, and Vaultwarden:

```sh
cargo test --test container_vault -- --ignored --nocapture
cargo test --test container_openbao -- --ignored --nocapture
cargo test --test container_infisical -- --ignored --nocapture
NVAULT_TEST_BW=/path/to/pinned/bw \
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

docker run -d --rm --name nvault-floci-aws -p 127.0.0.1:4566:4566 \
  floci/floci:2.5.0@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
docker run -d --rm --name nvault-floci-gcp -p 127.0.0.1:4588:4588 \
  floci/floci-gcp:0.13.0@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
docker run -d --rm --name nvault-floci-az \
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
nvault backup and cannot be loaded.

A local proxy that replaces secret placeholders in agent requests is a future
consideration, not a design this project has accepted. One sketch, still
uncommitted, is a separate executable that shares crates with `nvault`
instead of growing the `nvault` binary. Nothing here chooses that split,
a placeholder syntax, a listen address, or a wire format.

If that work is ever started, the trust boundary has to be explicit: the
process would see secret values and the request bodies it rewrites, so it is
not a transparent hop and not a reason to log either. It would also need
injection and egress controls before it could be used: which hosts it may
contact, which placeholders it may expand, and a refusal to send a value to
an unexpected URL. None of that exists today. There is no proxy binary, no
placeholder syntax, and no local listener. `nvault exec` only exports names
into a child environment; it does not rewrite request bodies.

## Verification in this change

Run in this worktree on 2026-11-17:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --lib
cc examples/ffi_smoke.c -Iinclude -Ltarget/release -lnvault \
   -Wl,-rpath,"$PWD/target/release" -o <tmp>/nvault-ffi-smoke
<tmp>/nvault-ffi-smoke
```

Observed:

```text
cargo fmt --check                         clean
cargo clippy --all-targets -- -D warnings clean
cargo test                                101 lib + 1 AWS contract + 41 CLI
                                          + 4 FFI passed;
                                          0 failed; 8 ignored (3 cloud
                                          emulator, Vault, Infisical,
                                          Vaultwarden, 2 KeePass)
cargo build --release --lib               succeeded
C ABI smoke                               exit 0, "redacted error received
                                          (34 bytes)"
```

The opt-in tests against real local backends also passed:

```sh
cargo test --test keepass_kdbx -- --ignored --nocapture
# 2 passed; 0 failed (generated KDBX, keepassxc-cli 2.7.12)

cargo test --test container_vault -- --ignored --nocapture
# 1 passed; 0 failed

cargo test --test container_infisical -- --ignored --nocapture
# 1 passed; 0 failed; concurrent Create: one 200, seven 500

cargo test --test container_cloud -- --ignored --nocapture
# 3 passed; 0 failed (AWS, GCP, Azure on Floci)
```

The Vaultwarden container test was not rerun because no pinned `bw` was
configured; its earlier evidence is in
[`docs/testcontainers.md`](docs/testcontainers.md). The container runs used
only their own pinned images, and their containers were gone afterwards. The
C ABI binary was written under a private cache directory and `TMPDIR` was set
there because `/tmp` on this machine was at a per-process disk quota; the
compile and link command was otherwise the documented one. No claim here
covers a live KeePass, Vault, Infisical, cloud, or Vaultwarden service.
