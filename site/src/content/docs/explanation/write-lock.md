---
title: Write lock
description: What the same-user lock covers, and what it does not.
---

`set` and `ensure` take an exclusive `flock` before they contact the provider. The lock is held for the whole call, including an existence check. Library and C ABI writes use the same path as the CLI, so one OS user's nsvault writers serialize across threads, processes, and entry points.

The identity is a hash of a canonical address plus non-secret scope. Profile names and config paths are not included, so two files that point at the same Vault mount share a lock. `https://Host:443/team/` and `https://host/team` match. `localhost` and `127.0.0.1` do not. Vault and OpenBao share the `kv2` identity when the address, mount, and namespace match.

The file is under `$XDG_STATE_HOME/nsvault/locks`, or `~/.local/state/nsvault/locks`. A missing directory is created `0700`, and lock files are created `0600`. `NSVAULT_LOCK_DIR` overrides the directory. The path is resolved one component at a time and the verified directory handle is retained, so the lock file is created relative to it. The path must be absolute; a relative `NSVAULT_LOCK_DIR` or `XDG_STATE_HOME` is rejected. No component may be a symbolic link, so on a system with a symlinked home or state directory set `NSVAULT_LOCK_DIR` to a real absolute path. Every parent must be owned by root or this user, because an owner can rename entries even without write permission. A parent writable by group or others must also be sticky. An existing directory is never chmodded: it must already be owned by this user and inaccessible to group and others. Creation respects the umask; a directory that does not end up exactly owner-only is an error, not chmodded. A pre-existing lock file that is not a regular, single-link, owner-only file is refused. Acquisition fails closed: there is no unlocked fallback and no timeout, so a slow writer makes the next write wait, and a lock failure is an error instead of a write. The kernel releases the lock when the process exits, including a crash. The file can remain. Deleting it is not required to recover.

Writers coordinate only when they resolve the same lock directory. The same OS user with the same `NSVAULT_LOCK_DIR` value, or the same `XDG_STATE_HOME`/`HOME` when it is unset, shares a lock. Different values are different locks even for one provider identity.

The lock is advisory. While a write may be in progress, do not remove, rename, or replace the lock directory or its `write-*.lock` files: a new inode or directory is a different lock, and cooperation silently stops. A hostile same-user process, or root, can break the lock this way. Same-user processes can already read this user's secrets, so the lock is not a security boundary against them; it prevents unintentional overlap between cooperating nsvault writers.

This lock does not exclude a writer that is not nsvault. Vault CAS is still what stops a concurrent creator outside this process. A different OS user has a different state directory and is not covered.
