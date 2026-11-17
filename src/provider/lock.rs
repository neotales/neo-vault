//! Same-user advisory lock for nsvault writes on this machine.
//!
//! `set` and `ensure` hold this lock for the whole call, including the
//! existence check. The kernel releases an exclusive `flock` when the process
//! exits, including a crash or `SIGKILL`. The lock file is left in place; it
//! does not have to be deleted to recover.
//!
//! # Scope
//!
//! The lock is per OS user and per provider identity (canonical origin plus
//! non-secret scope). Every nsvault write on this machine uses it: the CLI, the
//! [`crate::Client`] API, and the C ABI. It serializes those writers only. It
//! does not stop the Vault CLI, a provider UI, another host, or a different OS
//! user; provider CAS remains the control for those writers.
//!
//! # Failure behavior
//!
//! Acquisition fails closed. A missing directory is created private; an
//! existing directory is never chmodded. A directory that is a symbolic link,
//! is not a directory, is not owned by this user, or is accessible by group or
//! others is refused. So is a lock file that is not a regular, single-link,
//! owner-only file, or a platform where the advisory lock cannot be taken.
//! There is no unlocked fallback and no timeout: a call can wait until the
//! other nsvault writer exits.

use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
///
/// # Errors
///
/// Returns an error when the lock directory cannot be created, is a symbolic
/// link, is not owned by this user, or is accessible by group or others; when
/// the lock file is not a regular, single-link, owner-only file; or when the
/// platform cannot take an advisory lock. It never falls back to an unlocked
/// write and never changes the mode of an existing directory.
pub fn acquire(identity: &str) -> Result<WriteGuard> {
    let (dir, create_parents) = lock_dir()?;
    prepare_dir(&dir, create_parents)?;
    let path = dir.join(file_name(identity));
    let (file, created) = open_lock_file(&path)?;
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
/// `NSVAULT_LOCK_DIR` must have an existing parent; its parent chain is not
/// created, so a stale or mistyped path fails instead of creating directories.
fn lock_dir() -> Result<(PathBuf, bool)> {
    if let Some(dir) = std::env::var_os("NSVAULT_LOCK_DIR") {
        if dir.is_empty() {
            return Err(Error::new("NSVAULT_LOCK_DIR is empty"));
        }
        return Ok((PathBuf::from(dir), false));
    }
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        });
    let Some(state) = state else {
        return Err(Error::new(
            "cannot place the provider write lock: HOME and XDG_STATE_HOME are unset",
        ));
    };
    Ok((state.join("nsvault/locks"), true))
}

/// Creates the directory with `0700` if it is missing. It never chmods an
/// existing directory: that directory belongs to the caller.
fn prepare_dir(dir: &Path, create_parents: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let created = match create_private_dir(dir, create_parents) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(_) => {
                return Err(Error::new(
                    "could not create the provider write lock directory",
                ));
            }
        };
        let handle = open_dir(dir)?;
        if created {
            handle
                .set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|_| Error::new("could not restrict the provider write lock directory"))?;
        }
        // Check the opened handle, not the path: that is the object the
        // directory was resolved to and no later lookup can swap it.
        let metadata = handle
            .metadata()
            .map_err(|_| Error::new("could not inspect the provider write lock directory"))?;
        if !metadata.is_dir() {
            return Err(Error::new("provider write lock path is not a directory"));
        }
        if metadata.uid() != effective_uid() {
            return Err(Error::new(
                "provider write lock directory is not owned by this user",
            ));
        }
        let mode = metadata.permissions().mode();
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
    #[cfg(not(unix))]
    {
        let _ = (dir, create_parents);
        Err(Error::new(
            "provider write locks are not implemented on this platform",
        ))
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path, create_parents: bool) -> io::Result<()> {
    if create_parents
        && let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::DirBuilder::new().mode(0o700).create(dir)
}

/// Opens the directory without following a final symbolic link.
///
/// `O_DIRECTORY` is deliberately not set: on Linux a symbolic link combined
/// with it can report `ENOTDIR` instead of `ELOOP`, which hides the real
/// reason. The caller checks `is_dir` on the opened handle instead.
/// `O_NONBLOCK` only prevents a FIFO or device node at that path from blocking
/// the open; it has no effect on a directory.
#[cfg(unix)]
fn open_dir(dir: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(dir)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => Error::new("provider write lock directory is a symbolic link"),
            Some(libc::ENOTDIR) => Error::new("provider write lock path is not a directory"),
            _ => Error::new("could not open the provider write lock directory"),
        })
}

/// Opens the lock file without following a symbolic link. The `created` flag
/// tells the caller whether it may restrict the mode; an existing file is
/// inspected, not changed.
#[cfg(unix)]
fn open_lock_file(path: &Path) -> Result<(File, bool)> {
    fn options(create_new: bool) -> OpenOptions {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .create_new(create_new);
        options
    }
    match options(true).open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => options(false)
            .open(path)
            .map(|file| (file, false))
            .map_err(|_| Error::new("could not open the provider write lock")),
        Err(_) => Err(Error::new("could not open the provider write lock")),
    }
}

/// Removes mode bits a restrictive umask may have added. Only called for a
/// file this process just created.
fn set_file_private(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(0o600))
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
    use super::{inspect_lock_file, open_dir, open_lock_file};

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
        let target = dir.join("target");
        std::fs::write(&target, b"").expect("target fixture");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.join("write.lock");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(open_lock_file(&link).is_err());
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
        let error = open_dir(&link).expect_err("must reject a symlinked lock directory");
        assert!(
            error.message().contains("symbolic link"),
            "{}",
            error.message()
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
