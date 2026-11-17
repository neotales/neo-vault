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
- KeePass, Proton, and Vaultwarden cannot `set` or `ensure`. Proton stays read-only because the documented update takes the value in `argv`.
- Vaultwarden list uses `bw list items`, which returns full items. The adapter keeps names and must not return the password from `ls`.
- GitHub cannot `get` or `ensure`. Repository Actions secrets only.
- The same-user write lock is Linux `flock` in `$XDG_STATE_HOME/nsvault/locks` or `NSVAULT_LOCK_DIR`. An existing directory is never chmodded; a symlink, foreign owner, or group/world-accessible directory is refused. It does not stop the Vault CLI, another host, or another OS user. Windows and macOS were not exercised.
- No `remove`. No daemon, cache, keyring, or local encrypted store.
- No `import` and no `export`. An age file is not a nsvault backup.
- No request-rewriting proxy and no placeholder syntax. `exec` does not edit HTTP bodies. A separate proxy executable is an open question, not a design this project has accepted.
- A directory config is not merged with `~/.config/nsvault`.
- Shell completion does not list provider keys.
- AWS, GCP, and Azure kinds do not exist. Floci was not installed here, and those clouds were not tested.
- Windows and macOS were not exercised.
