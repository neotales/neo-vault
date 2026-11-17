//! Shareable Rust client for embedding `nsvault`.
//!
//! The client loads the same configuration as the CLI and exposes listing,
//! reading, and writing without going through the command line. It is a thin
//! wrapper over the provider boundary; it does not implement a daemon, cache,
//! or credential store of its own.

use std::path::Path;

use crate::config::Config;
use crate::error::Result;
use crate::provider::{self, ListedKey};
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
    /// # Errors
    ///
    /// Returns a configuration or provider error.
    pub fn set(&self, selected: Option<&str>, key: &str, value: &Secret) -> Result<()> {
        let provider = provider::select(&self.config, selected)?;
        provider.provider.set(key, value)
    }
}
