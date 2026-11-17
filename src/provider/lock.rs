//! Same-user advisory lock for nsvault writes on this machine.
//!
//! `set` and `ensure` hold this lock for the whole call, including the
//! existence check. The kernel releases an exclusive `flock` when the process
//! exits, including a crash or `SIGKILL`. The lock file is left in place; it
//! does not have to be deleted to recover.
//!
//! # Scope
//!
//! The lock is per OS user and per provider identity. That identity is a
//! canonical service endpoint or custom origin plus non-secret scope;
//! recognized cloud endpoint aliases are folded onto one conservative service
//! or vault identity, while an arbitrary custom URL alias is not detectable.
//! Every nsvault write on this machine uses it: the CLI, the
//! [`crate::Client`] API, and the C ABI. It serializes those writers only. It
//! does not stop the Vault CLI, a provider UI, another host, or a different OS
//! user; provider CAS remains the control for those writers.
//!
//! Coordination also assumes the writers resolve the *same* lock directory.
//! Two nsvault processes with different `NSVAULT_LOCK_DIR` values, or different
//! `XDG_STATE_HOME`/`HOME` when it is unset, use different lock files even for
//! the same provider identity and are not serialized by this mechanism.
//!
//! # Filesystem safety
//!
//! The lock directory is opened one component at a time with `openat` and
//! `O_NOFOLLOW`, so no component of the path may be a symbolic link. Every
//! ancestor must be owned by root or this user, because a directory's owner can
//! rename its entries even without write permission. A directory writable by
//! group or others must also be sticky. The path must be absolute; a relative
//! `NSVAULT_LOCK_DIR` or `XDG_STATE_HOME` is rejected rather than resolved from
//! an unchecked working directory. The verified directory descriptor is
//! retained.
//! The lock file is then created with `openat` relative to that descriptor, so
//! a path lookup cannot redirect the write after validation. A missing
//! directory is created with `mkdirat` relative to its verified parent. No
//! existing directory is ever chmodded, including one that appears between the
//! `mkdirat` attempt and the open. Creation respects the process umask: if that
//! leaves a directory that is not exactly owner-only, acquisition fails instead
//! of repairing it with a chmod.
//!
//! # Cooperative boundary
//!
//! The lock is advisory and cooperative. It does not defend against a process
//! of this same OS user (or root) that removes, renames, or replaces the lock
//! file or the lock directory while a write is running: a different inode or
//! directory is a different lock. Every writer must leave the lock directory
//! and its `write-*.lock` files in place while any write may be in flight.
//! Same-user processes can already read this user's secrets and memory, so the
//! lock is not a security boundary against them; it prevents unintentional
//! overlap between cooperating nsvault processes.
//!
//! # Failure behavior
//!
//! Acquisition fails closed. A directory that is a symbolic link, is not a
//! directory, is not owned by this user, is accessible by group or others, or
//! sits under a parent that other users can modify is refused. So is a lock
//! file that is not a regular, single-link, owner-only file, or a platform
//! where the advisory lock cannot be taken. There is no unlocked fallback and
//! no timeout: a call can wait until the other nsvault writer exits.

use std::ffi::CString;
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Held for the duration of one write. Dropping it releases the OS lock.
#[derive(Debug)]
pub struct WriteGuard {
    file: File,
}

/// Canonical server identity, with no userinfo, query, or fragment.
///
/// `https://Vault.Example:443/team/` and `https://vault.example/team` match.
/// `localhost` and `127.0.0.1` do not. Profile names are not part of this
/// string; callers add only non-secret scope fields.
///
/// # Errors
///
/// Returns an error when the URL has no host.
pub fn canonical_origin(url: &url::Url) -> Result<String> {
    let Some(host) = url.host_str() else {
        return Err(Error::new("provider address has no host"));
    };
    let scheme = url.scheme().to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let mut origin = format!("{scheme}://{host}");
    if let Some(port) = url.port()
        && !matches!((scheme.as_str(), port), ("https", 443) | ("http", 80))
    {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        origin.push_str(path);
    }
    Ok(origin)
}

/// Stable lock identity. Fields are separated by NUL so they cannot collide.
///
/// The kind is a product family, not a profile name. Vault and OpenBao both
/// use `kv2` so two configs for the same address, mount, and namespace share
/// a lock even when the kind label differs.
#[must_use]
pub fn identity(kind: &str, origin: &str, scope: &[&str]) -> String {
    let mut text = String::from("nsvault-write-lock-v1");
    text.push('\0');
    text.push_str(kind);
    text.push('\0');
    text.push_str(origin);
    for part in scope {
        text.push('\0');
        text.push_str(part.trim());
    }
    text
}

/// Acquires the exclusive write lock for `identity`.
///
/// Blocks until this user's other nsvault process releases it. The identity
/// is hashed into the file name and is not written into the file or the error.
/// Writers are serialized only when they resolve the same lock directory: the
/// same OS user and the same `NSVAULT_LOCK_DIR`, or the same
/// `XDG_STATE_HOME`/`HOME` when it is unset.
///
/// # Errors
///
/// Returns an error when the lock directory cannot be created or opened, is a
/// symbolic link, is not owned by this user, is accessible by group or others,
/// or sits under a parent that other users can modify (a writable sticky parent
/// is accepted only when root or this user owns it); when the lock file is not
/// a regular, single-link, owner-only file; or when the platform cannot take an
/// advisory lock. It never falls back to an unlocked write and never changes
/// the mode of an existing directory.
pub fn acquire(identity: &str) -> Result<WriteGuard> {
    #[cfg(unix)]
    {
        acquire_unix(identity)
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        Err(Error::new(
            "provider write locks are not implemented on this platform",
        ))
    }
}

#[cfg(unix)]
fn acquire_unix(identity: &str) -> Result<WriteGuard> {
    let (dir, allow_create_ancestors) = lock_spec()?;
    let directory = LockDirectory::open(&dir, allow_create_ancestors)?;
    let (file, created) = directory.open_lock(identity)?;
    if created {
        set_file_private(&file)?;
    }
    inspect_lock_file(&file)?;
    lock_exclusive(&file)?;
    Ok(WriteGuard { file })
}

/// Returns the lock directory and whether its missing parents may be created.
///
/// Only the default location may create parents. An explicitly configured
/// `NSVAULT_LOCK_DIR` must be absolute and have an existing parent; its parent
/// chain is not created, so a stale or mistyped path fails instead of creating
/// directories. Relative paths are rejected: a walk from the working directory
/// could not validate the directories above it.
fn lock_spec() -> Result<(PathBuf, bool)> {
    if let Some(dir) = std::env::var_os("NSVAULT_LOCK_DIR") {
        if dir.is_empty() {
            return Err(Error::new("NSVAULT_LOCK_DIR is empty"));
        }
        let path = PathBuf::from(dir);
        if !path.is_absolute() {
            return Err(Error::new("NSVAULT_LOCK_DIR must be an absolute path"));
        }
        return Ok((path, false));
    }
    let state = match std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(Error::new("XDG_STATE_HOME must be an absolute path"));
            }
            path
        }
        None => {
            let home = std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    Error::new(
                        "cannot place the provider write lock: HOME and XDG_STATE_HOME are unset",
                    )
                })?;
            if !home.is_absolute() {
                return Err(Error::new("HOME must be an absolute path"));
            }
            home.join(".local/state")
        }
    };
    Ok((state.join("nsvault/locks"), true))
}

/// A resolved, verified lock directory.
///
/// Every lock file is opened with `openat` relative to this descriptor, so
/// replacing the path after validation cannot redirect a write to a different
/// directory. The descriptor is also the object whose mode and owner were
/// checked.
#[cfg(unix)]
#[derive(Debug)]
struct LockDirectory {
    fd: OwnedFd,
}

#[cfg(unix)]
impl LockDirectory {
    /// Resolves `dir` one component at a time and retains the verified
    /// descriptor. Missing components are created only when
    /// `allow_create_ancestors` is set (the default state location); otherwise
    /// only the final component may be created. The path must be absolute so
    /// the walk starts at `/` and every ancestor is validated.
    fn open(dir: &Path, allow_create_ancestors: bool) -> Result<Self> {
        if !dir.is_absolute() {
            return Err(Error::new("provider write lock path must be absolute"));
        }
        let names = directory_components(dir)?;
        Ok(Self {
            fd: resolve(&names, allow_create_ancestors)?,
        })
    }

    fn open_lock(&self, identity: &str) -> Result<(File, bool)> {
        open_lock_file(&self.fd, identity)
    }
}

/// Splits a lock directory path into plain component names. `..` is refused
/// rather than resolved, so the walk never leaves the anchor.
#[cfg(unix)]
fn directory_components(path: &Path) -> Result<Vec<CString>> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(CString::new(name.as_bytes()).map_err(|_| {
                Error::new("provider write lock path contains an invalid component")
            })?),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::new(
                    "provider write lock path must not contain '..' or a prefix",
                ));
            }
        }
    }
    if names.is_empty() {
        return Err(Error::new(
            "provider write lock path is not a usable directory",
        ));
    }
    Ok(names)
}

/// Walks `names` from `/`, opening one descriptor per component and retaining
/// it for the next lookup. Every ancestor must be owned by root or this user
/// (its owner can rename entries otherwise), and a directory writable by group
/// or others must also be sticky. A missing component is created with
/// `mkdirat` only when allowed; its mode is then validated, never repaired with
/// a chmod.
#[cfg(unix)]
fn resolve(names: &[CString], allow_create_ancestors: bool) -> Result<OwnedFd> {
    let mut fd = open_anchor()?;
    let total = names.len();
    for (index, name) in names.iter().enumerate() {
        let last = index + 1 == total;
        let next = match open_at(&fd, name, last) {
            Ok(next) => next,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && (last || allow_create_ancestors) =>
            {
                create_at(&fd, name)?;
                open_at(&fd, name, last).map_err(|error| map_open_error(&error, last))?
            }
            Err(error) => return Err(map_open_error(&error, last)),
        };
        fd = next;
        if !last {
            inspect_ancestor(&fd)?;
        }
    }
    inspect_lock_dir(&fd)?;
    Ok(fd)
}

/// Opens `/` as the anchor. The lock path must be absolute, so every ancestor
/// is validated from the root rather than from an unchecked working directory.
#[cfg(unix)]
fn open_anchor() -> Result<OwnedFd> {
    // SAFETY: `c"/"` is a valid NUL-terminated string and no memory owned by
    // the caller is retained.
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::new("could not open the provider write lock path"));
    }
    // SAFETY: open returned a new descriptor that this function owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Opens one path component relative to `parent`, refusing symbolic links.
///
/// Every component uses `O_NOFOLLOW`, so neither the lock directory nor any
/// ancestor may be a symbolic link. Intermediate components also use
/// `O_DIRECTORY`; the final component is type-checked on its descriptor so a
/// regular file or FIFO reports a directory error instead of being used.
#[cfg(unix)]
fn open_at(parent: &OwnedFd, name: &CString, final_component: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW;
    if !final_component {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: `parent` is a live descriptor and `name` is NUL-terminated.
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that this function owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Creates one component with `mkdirat` relative to the verified parent. It
/// never chmods: if a different entry appeared first (`EEXIST`), the caller
/// opens and validates that object instead of changing it.
#[cfg(unix)]
fn create_at(parent: &OwnedFd, name: &CString) -> Result<()> {
    // SAFETY: `parent` is live, `name` is NUL-terminated, and 0700 is a valid
    // mode. mkdirat does not return a descriptor, so nothing is chmodded here.
    let raw = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if raw == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(Error::new(
        "could not create the provider write lock directory",
    ))
}

#[cfg(unix)]
fn map_open_error(error: &io::Error, final_component: bool) -> Error {
    match (error.raw_os_error(), final_component) {
        (Some(libc::ELOOP), true) => Error::new("provider write lock directory is a symbolic link"),
        (Some(libc::ELOOP), false) => Error::new(
            "provider write lock path must not contain a symbolic link or a non-directory",
        ),
        (Some(libc::ENOTDIR), false) => Error::new(
            "provider write lock path must not contain a symbolic link or a non-directory",
        ),
        (Some(libc::ENOTDIR), true) => Error::new("provider write lock path is not a directory"),
        (Some(libc::ENOENT), _) => Error::new("provider write lock directory does not exist"),
        _ => Error::new("could not open the provider write lock directory"),
    }
}

#[cfg(unix)]
fn fd_stat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the struct on success; the descriptor is live.
    let raw = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if raw != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded and initialized the struct.
    Ok(unsafe { stat.assume_init() })
}

/// Whether a directory is safe to traverse as an ancestor.
///
/// The owner of a directory can rename or remove its entries even when the
/// directory is not writable by anyone else, so every ancestor must be owned by
/// root or this user. Root is trusted because it can already replace or read
/// anything on the machine. A directory writable by group or others must also
/// be sticky, so those users cannot rename entries they do not own.
#[cfg(unix)]
fn ancestor_is_trusted(mode: libc::mode_t, uid: libc::uid_t, effective: libc::uid_t) -> bool {
    if uid != 0 && uid != effective {
        return false;
    }
    mode & 0o022 == 0 || mode & 0o1000 != 0
}

/// A parent owned by a third user, or one that other users can modify without
/// the sticky bit, could have its entries renamed or replaced during
/// resolution.
#[cfg(unix)]
fn inspect_ancestor(fd: &OwnedFd) -> Result<()> {
    let stat =
        fd_stat(fd).map_err(|_| Error::new("could not inspect the provider write lock path"))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(Error::new("provider write lock path is not a directory"));
    }
    let mode = stat.st_mode & 0o7777;
    if ancestor_is_trusted(mode, stat.st_uid, effective_uid()) {
        return Ok(());
    }
    if stat.st_uid != 0 && stat.st_uid != effective_uid() {
        return Err(Error::new(
            "provider write lock path has a parent owned by another user",
        ));
    }
    Err(Error::new(
        "provider write lock path has a parent that other users can modify",
    ))
}

#[cfg(unix)]
fn inspect_lock_dir(fd: &OwnedFd) -> Result<()> {
    let stat = fd_stat(fd)
        .map_err(|_| Error::new("could not inspect the provider write lock directory"))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(Error::new("provider write lock path is not a directory"));
    }
    if stat.st_uid != effective_uid() {
        return Err(Error::new(
            "provider write lock directory is not owned by this user",
        ));
    }
    let mode = stat.st_mode & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::new("provider write lock directory is not private"));
    }
    if mode & 0o700 != 0o700 {
        return Err(Error::new(
            "provider write lock directory is not accessible only to this user",
        ));
    }
    Ok(())
}

/// Opens the lock file with `openat` in the verified directory. The `created`
/// flag tells the caller whether it may restrict the mode; an existing file is
/// inspected, not changed.
#[cfg(unix)]
fn open_lock_file(dir: &OwnedFd, identity: &str) -> Result<(File, bool)> {
    let name = CString::new(file_name(identity)).expect("lock file name has no NUL");
    // SAFETY: `dir` is live, `name` is NUL-terminated, and 0600 is a valid
    // mode. O_EXCL returns the descriptor of the file this call created, so a
    // later chmod acts on that inode and not on a substituted path.
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw >= 0 {
        // SAFETY: openat returned a new descriptor that this function owns.
        return Ok((unsafe { File::from_raw_fd(raw) }, true));
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(Error::new("could not open the provider write lock"));
    }
    // SAFETY: `dir` is live and `name` is NUL-terminated. No create flag is
    // set, so this opens only an existing entry and O_NOFOLLOW rejects a link.
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::new("could not open the provider write lock"));
    }
    // SAFETY: openat returned a new descriptor that this function owns.
    Ok((unsafe { File::from_raw_fd(raw) }, false))
}

/// Removes mode bits a restrictive umask may have added. Only called for a
/// file this process just created with `O_EXCL`.
fn set_file_private(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::new("could not restrict the provider write lock"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(Error::new(
            "provider write locks are not implemented on this platform",
        ))
    }
}

/// Requires a regular, single-link, owner-only lock file. A pre-created
/// symbolic link, hard link, foreign file, or world/group-accessible file is
/// refused instead of repaired.
#[cfg(unix)]
fn inspect_lock_file(file: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file
        .metadata()
        .map_err(|_| Error::new("could not inspect the provider write lock"))?;
    if !metadata.is_file() {
        return Err(Error::new("provider write lock is not a regular file"));
    }
    if metadata.uid() != effective_uid() {
        return Err(Error::new("provider write lock is not owned by this user"));
    }
    if metadata.nlink() != 1 {
        return Err(Error::new(
            "provider write lock has an unexpected hard link",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::new("provider write lock file is not private"));
    }
    Ok(())
}

fn file_name(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    format!("write-{digest:x}.lock")
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    loop {
        // SAFETY: `fd` belongs to `file`, which outlives this call. `LOCK_EX`
        // waits until the kernel grants the lock or the call fails. No other
        // memory is accessed.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        let errno = error.raw_os_error().unwrap_or(0);
        return Err(Error::new(format!(
            "could not acquire the provider write lock (errno {errno})"
        )));
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid reads a process credential and has no pointer arguments.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
impl Drop for WriteGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the fd is still owned by this guard. Unlocking before close
        // makes the release independent of drop order. A crash skips this and
        // the kernel releases the lock with the process.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_origin, identity};

    #[cfg(unix)]
    use super::{
        LockDirectory, ancestor_is_trusted, directory_components, file_name, inspect_ancestor,
        inspect_lock_file,
    };

    #[cfg(unix)]
    fn try_lock(file: &std::fs::File) -> bool {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the descriptor is live for the duration of the call.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
    }

    #[test]
    fn origin_folds_case_default_port_and_trailing_slash() {
        let left = url::Url::parse("HTTPS://Vault.Example:443/team/").expect("url");
        let right = url::Url::parse("https://vault.example/team").expect("url");
        assert_eq!(
            canonical_origin(&left).expect("left"),
            canonical_origin(&right).expect("right")
        );
        assert_eq!(
            canonical_origin(&left).expect("left"),
            "https://vault.example/team"
        );
    }

    #[test]
    fn origin_keeps_loopback_names_distinct() {
        let local = url::Url::parse("http://localhost:8200").expect("url");
        let numeric = url::Url::parse("http://127.0.0.1:8200").expect("url");
        assert_ne!(
            canonical_origin(&local).expect("local"),
            canonical_origin(&numeric).expect("numeric")
        );
    }

    #[test]
    fn identity_ignores_profile_names_and_keeps_mounts_apart() {
        let origin = "http://127.0.0.1:8200";
        let shared = identity("kv2", origin, &["secret", ""]);
        assert_eq!(shared, identity("kv2", origin, &["secret", ""]));
        assert_ne!(shared, identity("kv2", origin, &["other", ""]));
        assert_ne!(shared, identity("kv2", origin, &["secret", "ns"]));
    }

    #[cfg(unix)]
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nsvault-lock-unit-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_with_group_or_other_access_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("mode");
        let path = dir.join("write.lock");
        std::fs::write(&path, b"").expect("write lock fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let file = std::fs::File::open(&path).expect("open lock fixture");
        let error = inspect_lock_file(&file).expect_err("must reject a readable lock file");
        assert!(
            error.message().contains("not private"),
            "{}",
            error.message()
        );
        drop(file);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_with_an_extra_hard_link_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("hardlink");
        let path = dir.join("write.lock");
        std::fs::write(&path, b"").expect("write lock fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::hard_link(&path, dir.join("alias")).expect("hard link");
        let file = std::fs::File::open(&path).expect("open lock fixture");
        let error = inspect_lock_file(&file).expect_err("must reject a hard-linked lock file");
        assert!(error.message().contains("hard link"), "{}", error.message());
        drop(file);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_symlink_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("file-symlink");
        let locks = dir.join("locks");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))
            .expect("chmod dir");
        let target = dir.join("target");
        std::fs::write(&target, b"").expect("target fixture");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = locks.join(file_name("symlink-test"));
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let directory = LockDirectory::open(&locks, false).expect("open lock directory");
        assert!(directory.open_lock("symlink-test").is_err());
        let mode = std::fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the symlink target must not be used");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn lock_directory_symlink_is_rejected() {
        let dir = scratch_dir("dir-symlink");
        let target = dir.join("target");
        std::fs::create_dir(&target).expect("target dir");
        let link = dir.join("locks");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error =
            LockDirectory::open(&link, false).expect_err("must reject a symlinked lock directory");
        assert!(
            error.message().contains("symbolic link"),
            "{}",
            error.message()
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn an_intermediate_symlink_is_rejected() {
        let base = scratch_dir("ancestor-symlink");
        let real = base.join("real");
        std::fs::create_dir(&real).expect("real dir");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let error = LockDirectory::open(&link.join("locks"), false)
            .expect_err("must reject a symlinked ancestor");
        assert!(
            error.message().contains("symbolic link"),
            "{}",
            error.message()
        );
        assert!(
            !real.join("locks").exists(),
            "nothing may be created through the symlink"
        );
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_directory_is_never_chmodded_when_it_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("preserve-mode");
        let locks = base.join("locks");
        std::fs::create_dir(&locks).expect("existing lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let error = LockDirectory::open(&locks, false).expect_err("must reject a non-private dir");
        assert!(
            error.message().contains("not private"),
            "{}",
            error.message()
        );
        let mode = std::fs::metadata(&locks)
            .expect("lock dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "an existing directory must keep its mode");
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_owners_are_trusted_only_for_root_or_this_user() {
        // Not writable by group/others, but the owner can still replace
        // entries, so a foreign owner is not trusted.
        assert!(!ancestor_is_trusted(0o0755, 1234, 1000));
        assert!(ancestor_is_trusted(0o0755, 0, 1000));
        assert!(ancestor_is_trusted(0o0755, 1000, 1000));
        // Sticky writable and owned by root or this user.
        assert!(ancestor_is_trusted(0o1777, 0, 1000));
        assert!(ancestor_is_trusted(0o1777, 1000, 1000));
        // Sticky writable but owned by a third user: that owner can rename any
        // entry, so it is not trusted. Only the decision function is tested
        // here; this workspace cannot chown to a foreign UID.
        assert!(!ancestor_is_trusted(0o1777, 1234, 1000));
        // Writable without the sticky bit is never trusted.
        assert!(!ancestor_is_trusted(0o0777, 0, 1000));
        assert!(!ancestor_is_trusted(0o0770, 1000, 1000));
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_lock_path_is_rejected() {
        let error = LockDirectory::open(std::path::Path::new("locks"), false)
            .expect_err("must reject a relative path");
        assert!(error.message().contains("absolute"), "{}", error.message());
    }

    #[cfg(unix)]
    #[test]
    fn root_owned_sticky_tmp_is_allowed() {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/tmp").expect("stat /tmp");
        assert_eq!(metadata.uid(), 0, "test expects a root-owned /tmp");
        assert_ne!(metadata.mode() & 0o1000, 0, "test expects a sticky /tmp");
        let file = std::fs::File::open("/tmp").expect("open /tmp");
        let fd: std::os::fd::OwnedFd = file.into();
        inspect_ancestor(&fd).expect("a root-owned sticky directory is allowed");
    }

    #[cfg(unix)]
    #[test]
    fn a_sticky_writable_parent_is_allowed() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("sticky-parent");
        let sticky = base.join("sticky");
        std::fs::create_dir(&sticky).expect("sticky dir");
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).expect("chmod");
        let locks = sticky.join("locks");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        LockDirectory::open(&locks, false).expect("a sticky parent is allowed");
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_other_users_can_modify_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("writable-parent");
        let shared = base.join("shared");
        std::fs::create_dir(&shared).expect("shared dir");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let locks = shared.join("locks");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let error = LockDirectory::open(&locks, false).expect_err("must reject a writable parent");
        assert!(error.message().contains("parent"), "{}", error.message());
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn parent_components_are_rejected() {
        let error = directory_components(std::path::Path::new("a/../b"))
            .expect_err("must reject a parent component");
        assert!(error.message().contains("'..'"), "{}", error.message());
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_parent_is_not_created_for_an_explicit_directory() {
        let base = scratch_dir("missing-parent");
        let target = base.join("missing/locks");
        let error =
            LockDirectory::open(&target, false).expect_err("must not create a missing parent");
        assert!(
            error.message().contains("does not exist"),
            "{}",
            error.message()
        );
        assert!(!base.join("missing").exists());
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn default_creation_makes_missing_parents_private() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("create-parents");
        let target = base.join("state/nsvault/locks");
        let directory = LockDirectory::open(&target, true).expect("create lock path");
        for path in [
            base.join("state"),
            base.join("state/nsvault"),
            target.clone(),
        ] {
            let mode = std::fs::metadata(&path)
                .expect("created directory")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} is not 0700", path.display());
        }
        drop(directory);
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn replacing_the_lock_directory_or_file_breaks_mutual_exclusion() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("advisory-boundary");
        let locks = base.join("locks");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let directory = LockDirectory::open(&locks, false).expect("open lock directory");

        let (held, first_created) = directory.open_lock("boundary").expect("first lock file");
        assert!(first_created);
        assert!(try_lock(&held), "the first writer takes the lock");
        let (second, second_created) = directory.open_lock("boundary").expect("second handle");
        assert!(!second_created);
        assert!(
            !try_lock(&second),
            "a second handle for the same inode must conflict"
        );

        // Documented boundary, directory form: a same-user process moves the
        // verified directory away and a new writer resolves a fresh tree. The
        // two writers now hold different inodes.
        let moved = base.join("moved-locks");
        std::fs::rename(&locks, &moved).expect("move lock directory");
        std::fs::create_dir(&locks).expect("replacement lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let replacement_directory =
            LockDirectory::open(&locks, false).expect("open replacement directory");
        let (fresh, fresh_created) = replacement_directory
            .open_lock("boundary")
            .expect("fresh lock file");
        assert!(fresh_created);
        assert!(try_lock(&fresh), "a replaced directory is a different lock");

        // Documented boundary, file form: a same-user process removes the lock
        // file from the original directory and recreates it.
        std::fs::remove_file(moved.join(file_name("boundary"))).expect("remove lock file");
        let (replacement, replacement_created) = directory
            .open_lock("boundary")
            .expect("replacement lock file");
        assert!(replacement_created);
        assert!(
            try_lock(&replacement),
            "removal breaks mutual exclusion; this lock is not a same-user boundary"
        );

        drop(replacement);
        drop(fresh);
        drop(second);
        drop(held);
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn retained_handle_ignores_a_replaced_directory_entry() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("entry-swap");
        let locks = base.join("locks");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let directory = LockDirectory::open(&locks, false).expect("open lock directory");
        // Move the verified directory away and put another directory at the
        // same path. A path-based open after validation would land in the
        // replacement.
        let moved = base.join("moved");
        std::fs::rename(&locks, &moved).expect("move verified directory");
        std::fs::create_dir(&locks).expect("replacement directory");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o755))
            .expect("replacement mode");

        let (file, created) = directory
            .open_lock("entry-swap")
            .expect("lock via retained handle");
        assert!(created);
        drop(file);
        assert!(
            moved.join(file_name("entry-swap")).exists(),
            "the lock must land in the verified directory"
        );
        assert!(
            !locks.join(file_name("entry-swap")).exists(),
            "the replacement directory must stay unused"
        );
        let mode = std::fs::metadata(&locks)
            .expect("replacement metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the replacement must not be chmodded");
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn retained_handle_ignores_a_replaced_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("ancestor-swap");
        let parent = base.join("parent");
        let locks = parent.join("locks");
        std::fs::create_dir(&parent).expect("parent dir");
        std::fs::create_dir(&locks).expect("lock dir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let directory = LockDirectory::open(&locks, false).expect("open lock directory");
        let moved = base.join("moved-parent");
        std::fs::rename(&parent, &moved).expect("move parent");
        std::fs::create_dir(&parent).expect("replacement parent");
        std::fs::create_dir(&locks).expect("replacement lock dir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).expect("chmod");

        let (file, created) = directory
            .open_lock("ancestor-swap")
            .expect("lock via retained handle");
        assert!(created);
        drop(file);
        assert!(
            moved
                .join("locks")
                .join(file_name("ancestor-swap"))
                .exists(),
            "the lock must land under the verified ancestor"
        );
        assert!(
            !locks.join(file_name("ancestor-swap")).exists(),
            "the replacement tree must stay unused"
        );
        std::fs::remove_dir_all(base).expect("cleanup");
    }
}
