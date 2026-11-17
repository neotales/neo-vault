//! Shareable Rust client for embedding `nsvault`.
//!
//! The client loads the same configuration as the CLI and exposes listing,
//! reading, and writing without going through the command line. It is a thin
//! wrapper over the provider boundary; it does not implement a daemon, cache,
//! or credential store of its own.
//!
//! `set` and `ensure` take the same per-machine, same-user write lock the CLI
//! uses, keyed by a provider identity built from the canonical service
//! endpoint or custom origin plus non-secret scope. Recognized cloud endpoint
//! aliases are folded onto one conservative service or vault identity; an
//! arbitrary custom URL alias is not detectable. A `Client` shared across
//! threads serializes writes for the same identity, and it
//! serializes with other nsvault processes of the same OS user. A call can
//! block until the other writer exits. Lock failures are returned as errors;
//! there is no unlocked write. The lock does not cover other clients, other
//! hosts, or other OS users.
//!
//! Serialization assumes every writer resolves the same lock directory: the
//! same OS user and the same `NSVAULT_LOCK_DIR` value, or the same
//! `XDG_STATE_HOME`/`HOME` when it is unset. Two processes with different
//! values use different lock files even for one provider identity and are not
//! serialized by this mechanism. The lock path must be absolute; a relative
//! `NSVAULT_LOCK_DIR` or `XDG_STATE_HOME` is rejected. No component of the path
//! may be a symbolic link. The directory is created `0700` if missing and must
//! be owned by this user and inaccessible to group and others. Every ancestor
//! must be owned by root or this user, because an owner can rename entries even
//! without write permission; an ancestor writable by group or others must also
//! be sticky.
//!
//! The lock is advisory and cooperative. While a write may be in progress,
//! callers must not remove, rename, or replace the lock directory or its
//! `write-*.lock` files: a new inode or directory is a different lock. A
//! hostile same-user process (or root) can break cooperation this way. The
//! lock is not a security boundary against that process; it prevents
//! unintentional overlap between cooperating nsvault writers.

use std::path::Path;

use crate::config::Config;
use crate::error::Result;
use crate::provider::{self, EnsureStatus, ListedKey};
use crate::secret::Secret;

/// A configured, reusable secrets client.
#[derive(Debug)]
pub struct Client {
    config: Config,
}

impl Client {
    /// Opens a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is missing, invalid, or insecure.
    pub fn open(path: &Path) -> Result<Self> {
        Config::load(path).map(|config| Self { config })
    }

    /// Returns the default key prefix configured for this client.
    #[must_use]
    pub fn default_prefix(&self, requested: Option<&str>) -> String {
        provider::default_prefix(&self.config, requested)
    }

    /// Lists key names. Values are not read.
    ///
    /// # Errors
    ///
    /// Returns a configuration or provider error.
    pub fn list(&self, selected: Option<&str>, prefix: &str) -> Result<Vec<ListedKey>> {
        let provider = provider::select(&self.config, selected)?;
        provider.provider.list(prefix)
    }

    /// Reads one secret.
    ///
    /// # Errors
    ///
    /// Returns a configuration or provider error.
    pub fn get(&self, selected: Option<&str>, key: &str) -> Result<Secret> {
        let provider = provider::select(&self.config, selected)?;
        provider.provider.get(key)
    }

    /// Writes one secret.
    ///
    /// Takes the same-user write lock for this provider scope and may block
    /// behind another nsvault writer on this machine. A lock failure is an
    /// error, not an unlocked write.
    ///
    /// # Errors
    ///
    /// Returns a configuration, provider, or lock error.
    pub fn set(&self, selected: Option<&str>, key: &str, value: &Secret) -> Result<()> {
        let provider = provider::select(&self.config, selected)?;
        provider.provider.set(key, value)
    }

    /// Creates a secret when it is absent and leaves an existing secret unchanged.
    ///
    /// Takes the same-user write lock for this provider scope and may block
    /// behind another nsvault writer on this machine. The lock excludes only
    /// nsvault writers of the same OS user; the provider's own conditional
    /// write is what protects against a concurrent external writer.
    ///
    /// # Errors
    ///
    /// Returns a configuration, provider, or lock error, or an unsupported
    /// error for a provider without a race-safe create path. An error is not
    /// absence.
    pub fn ensure(
        &self,
        selected: Option<&str>,
        key: &str,
        value: &Secret,
    ) -> Result<EnsureStatus> {
        let provider = provider::select(&self.config, selected)?;
        provider.provider.ensure(key, value)
    }
}
