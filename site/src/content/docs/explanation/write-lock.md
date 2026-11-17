---
title: Write lock
description: What the same-user lock covers, and what it does not.
---

`set` and `ensure` take an exclusive `flock` before they contact the provider. The lock is held for the whole call, including an existence check. Library and C ABI writes use the same path as the CLI.

The identity is a hash of a canonical address plus non-secret scope. Profile names and config paths are not included, so two files that point at the same Vault mount share a lock. `https://Host:443/team/` and `https://host/team` match. `localhost` and `127.0.0.1` do not. Vault and OpenBao share the `kv2` identity when the address, mount, and namespace match.

The file is under `$XDG_STATE_HOME/nsvault/locks`, or `~/.local/state/nsvault/locks`, mode `0700` for the directory and `0600` for the file. `NSVAULT_LOCK_DIR` overrides the directory and must stay owner-only. The kernel releases the lock when the process exits, including a crash. The file can remain. Deleting it is not required to recover.

This lock does not exclude a writer that is not nsvault. Vault CAS is still what stops a concurrent creator outside this process. A different OS user has a different state directory and is not covered.
