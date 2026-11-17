---
title: Write lock
description: What the same-user lock covers, and what it does not.
---

`set` and `ensure` take an exclusive `flock` before they contact the provider. The lock is held for the whole call, including an existence check. Library and C ABI writes use the same path as the CLI, so one OS user's nsvault writers serialize across threads, processes, and entry points.

The identity is a hash of a canonical address plus non-secret scope. Profile names and config paths are not included, so two files that point at the same Vault mount share a lock. `https://Host:443/team/` and `https://host/team` match. `localhost` and `127.0.0.1` do not. Vault and OpenBao share the `kv2` identity when the address, mount, and namespace match.

The file is under `$XDG_STATE_HOME/nsvault/locks`, or `~/.local/state/nsvault/locks`. A missing directory is created `0700`, and lock files are created `0600`. `NSVAULT_LOCK_DIR` overrides the directory. An existing directory is never chmodded: it must already be owned by this user and inaccessible to group and others, and a symbolic link is refused. A pre-existing lock file that is not a regular, single-link, owner-only file is refused. Acquisition fails closed: there is no unlocked fallback and no timeout, so a slow writer makes the next write wait, and a lock failure is an error instead of a write. The kernel releases the lock when the process exits, including a crash. The file can remain. Deleting it is not required to recover.

This lock does not exclude a writer that is not nsvault. Vault CAS is still what stops a concurrent creator outside this process. A different OS user has a different state directory and is not covered.
