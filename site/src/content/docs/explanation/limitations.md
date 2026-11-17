---
title: Limitations
description: What this build does not do.
---

These are product limits, not temporary bugs.

- Vault KV v2 only. KV v1, dynamic credentials, transit, and PKI are not exposed.
- `ensure` without `#field` treats an existing Vault path as present. It does not add a missing `value` field and it does not undelete a soft-deleted secret.
- A lost Vault CAS race is not retried with an unconditional write.
- Infisical `ensure` is disabled. The adapter refuses the command and sends no request. The v4 Create POST has not been proven to reject a duplicate name instead of upserting it against a live server.
- Infisical list is one folder, `recursive = false`, and is not paginated.
- KeePass and Proton cannot `set` or `ensure`. Proton stays read-only because the documented update takes the value in `argv`. Vaultwarden can `set` through `bw create item`/`bw edit item`; its `ensure` is refused because the CLI cannot create conditionally.
- Vaultwarden list uses `bw list items`, which returns full items. The adapter keeps names and must not return the password from `ls`.
- Vaultwarden writes read and write the whole item through the `bw` CLI's local copy. The CLI sends `lastKnownRevisionDate`, and the Bitwarden server and Vaultwarden reject an item more than one second stale, so a common external edit fails the write instead of being overwritten. This is not coordination: a stale local copy, a server without the check, or an update inside the one-second window can still lose a concurrent change. nsvault does not preserve concurrent external changes.
- GitHub cannot `get` or `ensure`. Repository Actions secrets only.
- Vault/OpenBao `set`/`ensure`, GitHub `set`, Infisical `set`, and Vaultwarden `set` use a Linux `flock` same-user lock in `$XDG_STATE_HOME/nsvault/locks` or `NSVAULT_LOCK_DIR` (Vaultwarden shares one identity across every profile on the machine, because wrapper paths differ); the cloud adapters rely on provider create/version semantics. The path must be absolute and no component may be a symlink. An existing directory is never chmodded; a foreign owner, group/world-accessible directory, or a parent not owned by root or this user is refused, and a writable parent must also be sticky. The lock is advisory: removing, renaming, or replacing the lock file or directory breaks it, so it is not a same-user security boundary. It does not stop the Vault CLI, another host, or another OS user. Windows and macOS were not exercised.
- No `remove`. No daemon, cache, keyring, or local encrypted store.
- No `import` and no `export`. An age file is not a nsvault backup.
- No request-rewriting proxy and no placeholder syntax. `exec` does not edit HTTP bodies. A separate proxy executable is an open question, not a design this project has accepted.
- A directory config is not merged with `~/.config/nsvault`.
- Shell completion does not list provider keys.
- AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault were tested only against pinned local Floci emulators. The emulator does not validate AWS SigV4 signatures and does not prove production authentication, IAM, quotas, or regional behavior.
- Cloud credentials are static for the process lifetime. There is no AWS STS/IMDS chain, GCP ADC or service-account JWT exchange, Azure Entra ID or managed-identity flow, or token refresh.
- Azure Key Vault `ensure` is refused because there is no conditional create. Only the latest version is read.
- GCP Secret Manager `ensure` is refused because create and add-version are separate calls. A partial create could leave an empty secret, and a retry would report Present.
- GCP `allow_anonymous` is a loopback-emulator switch and is refused for any non-loopback endpoint.
- Windows and macOS were not exercised.
