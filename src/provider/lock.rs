//! Same-user advisory lock for nsvault writes on this machine.
//!
//! `set` and `ensure` hold this lock for the whole call, including the
//! existence check. The kernel releases an exclusive `flock` when the process
//! exits, including a crash or `SIGKILL`. The lock file is left in place; it
//! does not have to be deleted to recover.
//!
//! This does not stop the Vault CLI, a provider UI, another host, or a
//! different OS user. Provider CAS remains the control for writers that do
//! not take this lock.

use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
/// Returns an error when the lock directory is missing, not private, or the
/// platform cannot take an advisory lock. It does not fall back to an unlocked
/// write.
pub fn acquire(identity: &str) -> Result<WriteGuard> {
    let dir = lock_dir()?;
    prepare_dir(&dir)?;
    let path = dir.join(file_name(identity));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| Error::new("could not open the provider write lock"))?;
    restrict_file(&path)?;
    lock_exclusive(&file)?;
    Ok(WriteGuard { file })
}

fn lock_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("NSVAULT_LOCK_DIR") {
        if dir.is_empty() {
            return Err(Error::new("NSVAULT_LOCK_DIR is empty"));
        }
        return Ok(PathBuf::from(dir));
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
    Ok(state.join("nsvault/locks"))
}

fn prepare_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .map_err(|_| Error::new("could not create the provider write lock directory"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::new("could not restrict the provider write lock directory"))?;
        let meta = fs::metadata(dir)
            .map_err(|_| Error::new("could not inspect the provider write lock directory"))?;
        if meta.uid() != unsafe_euid() {
            return Err(Error::new(
                "provider write lock directory is not owned by this user",
            ));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::new("provider write lock directory is not private"));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        return Err(Error::new(
            "provider write locks are not implemented on this platform",
        ));
    }
    Ok(())
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::new("could not restrict the provider write lock"))?;
        let mode = fs::metadata(path)
            .map_err(|_| Error::new("could not inspect the provider write lock"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::new("provider write lock file is not private"));
        }
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
fn unsafe_euid() -> u32 {
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
}
