---
title: Limitations
description: What this build does not do.
---

These are product limits, not temporary bugs.

- Vault KV v2 only. KV v1, dynamic credentials, transit, and PKI are not exposed.
- `ensure` without `#field` treats an existing Vault path as present. It does not add a missing `value` field and it does not undelete a soft-deleted secret.
- A lost Vault CAS race is not retried with an unconditional write.
- Infisical `ensure` is a GET plus the documented Create POST. It is not a server-side conditional write, and it has not been run against a live Infisical.
- Infisical list is one folder, `recursive = false`, and is not paginated.
- KeePass, Proton, and Vaultwarden cannot `set` or `ensure`. Proton stays read-only because the documented update takes the value in `argv`.
- Vaultwarden list uses `bw list items`, which returns full items. The adapter keeps names and must not return the password from `ls`.
- GitHub cannot `get` or `ensure`. Repository Actions secrets only.
- Vault/OpenBao and GitHub writes use a Linux `flock` same-user lock in `$XDG_STATE_HOME/nsvault/locks` or `NSVAULT_LOCK_DIR`. Infisical and the cloud adapters rely on provider create/version semantics. The lock does not stop the Vault CLI, another host, or another OS user. Windows and macOS were not exercised.
- No `remove`. No daemon, cache, keyring, or local encrypted store.
- No `import` and no `export`. An age file is not a nsvault backup.
- No request-rewriting proxy and no placeholder syntax. `exec` does not edit HTTP bodies. A separate proxy executable is an open question, not a design this project has accepted.
- A directory config is not merged with `~/.config/nsvault`.
- Shell completion does not list provider keys.
- AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault were tested only against pinned local Floci emulators. The emulator does not validate AWS SigV4 signatures and does not prove production authentication, IAM, quotas, or regional behavior.
- Cloud credentials are static for the process lifetime. There is no AWS STS/IMDS chain, GCP ADC or service-account JWT exchange, Azure Entra ID or managed-identity flow, or token refresh.
- Azure Key Vault `ensure` is refused because there is no conditional create. Only the latest version is read.
- GCP `allow_anonymous` is a loopback-emulator switch and is refused for any non-loopback endpoint.
- Windows and macOS were not exercised.
