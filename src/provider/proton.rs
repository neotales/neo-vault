//! Proton Pass provider backed by the official `pass-cli` 2.7.1.
//!
//! Reads use `pass-cli item view --field`, which prints only the field value.
//!
//! Listing uses `pass-cli item list --output json`. This is not a metadata-only
//! fetch: upstream `list_items` downloads and decrypts each `Item`, then
//! serializes an `ItemSummary` without content. This adapter keeps only the
//! title and share id and never returns item content.
//!
//! Writes are deliberately unsupported: the documented update command takes the
//! value as an argument, and this project will not put a secret in `argv`.
//!
//! Authentication can use an existing `pass-cli` session or a personal access
//! token supplied through the environment/file named in configuration. The
//! token is passed to the child through its environment only.
//!
//! When a token is configured, each provider instance uses a private
//! per-process `PROTON_PASS_SESSION_DIR` and the filesystem key provider. It
//! therefore cannot reuse or modify the user's default session, and a login is
//! guaranteed to use the configured token. After login, `info --output json`
//! must report a personal access token; a user session is rejected. Without a
//! token, the existing `pass-cli` session is used unchanged.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::config::ProtonConfig;
use crate::error::{Error, Result, unsupported};
use crate::key::Key;
use crate::provider::{Capabilities, ListedKey, Provider, command_available};
use crate::secret::Secret;

/// Read-only Proton Pass provider.
#[derive(Debug)]
pub struct ProtonProvider {
    name: String,
    command: String,
    vault: Option<String>,
    token: Option<Secret>,
    reason: Option<String>,
    session_dir: OnceLock<SessionDir>,
}

/// A private per-process directory for one isolated `pass-cli` session.
#[derive(Debug)]
struct SessionDir {
    path: PathBuf,
}

/// Redacted failure message for session-directory setup.
const SESSION_DIR_ERROR: &str = "could not create an isolated pass-cli session directory";

impl SessionDir {
    fn create() -> Result<Self> {
        let base = std::env::temp_dir();
        // `pass-cli` reads this override with `std::env::var`, which rejects
        // non-Unicode values and would silently fall back to the default
        // session. Fail closed instead.
        if base.to_str().is_none() {
            return Err(Error::new(SESSION_DIR_ERROR));
        }
        let process = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        for attempt in 0..32 {
            let path = base.join(format!("nsvault-proton-{process}-{nanos}-{attempt}"));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => break,
            }
        }
        Err(Error::new(SESSION_DIR_ERROR))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl ProtonProvider {
    /// Builds a Proton Pass provider.
    ///
    /// # Errors
    ///
    /// Returns an error when `pass-cli` is unavailable or the token file cannot
    /// be read.
    pub fn new(name: &str, config: &ProtonConfig, root: &Path) -> Result<Self> {
        if !command_available(&config.command) && !Path::new(&config.command).is_file() {
            return Err(Error::new(format!(
                "Proton Pass command {:?} is not available; install pass-cli",
                config.command
            )));
        }
        let token = match (&config.token_env, &config.token_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                Some(crate::provider::credential_from_env(variable)?)
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            _ => None,
        };
        Ok(Self {
            name: name.to_owned(),
            command: config.command.clone(),
            vault: config.vault.clone(),
            token,
            reason: config.reason.clone(),
            session_dir: OnceLock::new(),
        })
    }

    fn command(&self, arguments: &[&str]) -> Result<Command> {
        let mut command = Command::new(&self.command);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(reason) = &self.reason {
            command.env("PROTON_PASS_AGENT_REASON", reason);
        }
        if let Some(token) = &self.token {
            let token = std::str::from_utf8(token.expose())
                .map_err(|_| Error::new("credential is not valid UTF-8"))?;
            command.env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", token);
            let session_dir = self.session_dir()?;
            command.env("PROTON_PASS_SESSION_DIR", session_dir.path());
            command.env("PROTON_PASS_KEY_PROVIDER", "fs");
        }
        Ok(command)
    }

    fn session_dir(&self) -> Result<&SessionDir> {
        if let Some(directory) = self.session_dir.get() {
            return Ok(directory);
        }
        let directory = SessionDir::create()?;
        let _ = self.session_dir.set(directory);
        self.session_dir
            .get()
            .ok_or_else(|| Error::new(SESSION_DIR_ERROR))
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let output = self
            .command(arguments)?
            .spawn()
            .map_err(|_| Error::new("could not start pass-cli"))?
            .wait_with_output()
            .map_err(|_| Error::new("pass-cli did not finish"))?;
        if !output.status.success() {
            return Err(Error::new(
                "pass-cli failed; check the session, vault, item, and field",
            ));
        }
        if output.stdout.len() > 8 * 1024 * 1024 {
            return Err(Error::new("pass-cli output exceeded the size limit"));
        }
        Ok(output.stdout)
    }

    fn session_is_pat(&self) -> Result<bool> {
        // Require the session file to be inside the private directory first.
        // This detects a `pass-cli` that ignored `PROTON_PASS_SESSION_DIR` and
        // would otherwise let `info` report the user's session.
        if !self.session_dir.get().is_some_and(|directory| {
            directory
                .path()
                .join(".session")
                .join("session.json")
                .is_file()
        }) {
            return Ok(false);
        }
        let output = match self.run(&["info", "--output", "json"]) {
            Ok(output) => output,
            Err(_) => return Ok(false),
        };
        #[derive(Deserialize)]
        struct SessionInfo {
            #[serde(default)]
            personal_access_token_name: Option<String>,
        }
        let info: SessionInfo = serde_json::from_slice(&output)
            .map_err(|_| Error::new("pass-cli returned unexpected session information"))?;
        Ok(info
            .personal_access_token_name
            .as_deref()
            .is_some_and(|name| !name.is_empty()))
    }

    fn ensure_session(&self) -> Result<()> {
        if self.token.is_none() {
            return Ok(());
        }
        if self.session_is_pat()? {
            return Ok(());
        }
        self.run(&["login"])?;
        if self.session_is_pat()? {
            Ok(())
        } else {
            Err(Error::new(
                "pass-cli did not create a personal access token session",
            ))
        }
    }

    fn items(&self) -> Result<Vec<ItemSummary>> {
        self.ensure_session()?;
        let mut arguments = vec!["item", "list", "--output", "json"];
        if let Some(vault) = &self.vault {
            arguments.extend(["--vault-name", vault]);
        }
        let output = self.run(&arguments)?;
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            items: Vec<ItemSummary>,
        }
        let envelope: Envelope = serde_json::from_slice(&output)
            .map_err(|_| Error::new("pass-cli returned an unexpected item list"))?;
        Ok(envelope.items)
    }

    fn resolve_title(&self, title: &str) -> Result<ItemSummary> {
        let matches: Vec<ItemSummary> = self
            .items()?
            .into_iter()
            .filter(|item| item.title == title)
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("one item")),
            0 => Err(Error::new(format!(
                "Proton Pass item {title:?} was not found"
            ))),
            _ => Err(Error::new(format!(
                "Proton Pass item title {title:?} is ambiguous; use a unique title or share id"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ItemSummary {
    #[serde(default)]
    title: String,
    #[serde(default)]
    share_id: String,
}

impl Provider for ProtonProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "proton"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_ONLY
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        for item in self.items()? {
            if !item.title.is_empty() && (prefix.is_empty() || item.title.starts_with(prefix)) {
                keys.push(ListedKey::new(item.title));
            }
        }
        Ok(keys)
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        let title = key.path();
        let field = key.field().unwrap_or("password");
        let item = self.resolve_title(title)?;
        self.ensure_session()?;
        let mut arguments = vec!["item", "view", "--item-title", title, "--field", field];
        if let Some(vault) = &self.vault {
            arguments.extend(["--vault-name", vault]);
        } else if !item.share_id.is_empty() {
            arguments.extend(["--share-id", item.share_id.as_str()]);
        }
        let output = self.run(&arguments)?;
        Ok(Secret::new(trim_one_newline(output)))
    }

    fn set(&self, _key: &str, _value: &Secret) -> Result<()> {
        Err(unsupported("set", &self.name))
    }
}

fn trim_one_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{SessionDir, trim_one_newline};

    #[test]
    fn session_directory_is_removed_on_drop() {
        let directory = SessionDir::create().expect("session directory");
        let path = directory.path().to_path_buf();
        assert!(path.is_dir());
        drop(directory);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn session_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = SessionDir::create().expect("session directory");
        let mode = std::fs::metadata(directory.path())
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn removes_only_one_line_ending() {
        assert_eq!(trim_one_newline(b"value\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\r\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\n\n".to_vec()), b"value\n");
    }
}
