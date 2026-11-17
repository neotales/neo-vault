//! Proton Pass provider backed by the official `pass-cli`.
//!
//! Reads use `pass-cli item view --field`, which prints only the field value.
//! Writes are deliberately unsupported: the documented update command takes the
//! value as an argument, and this project will not put a secret in `argv`.
//!
//! Authentication can use an existing `pass-cli` session or a personal access
//! token supplied through the environment/file named in configuration. The
//! token is passed to the child through its environment only.

use std::path::Path;
use std::process::{Command, Stdio};

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
        })
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.command);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(reason) = &self.reason {
            command.env("PROTON_PASS_AGENT_REASON", reason);
        }
        if let Some(token) = &self.token
            && let Ok(token) = std::str::from_utf8(token.expose())
        {
            command.env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", token);
        }
        command
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let output = self
            .command(arguments)
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

    fn ensure_session(&self) -> Result<()> {
        if self.token.is_none() {
            return Ok(());
        }
        if self
            .command(&["info"])
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Ok(());
        }
        let arguments = ["login"];
        self.run(&arguments).map(|_| ())
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
    use super::trim_one_newline;

    #[test]
    fn removes_only_one_line_ending() {
        assert_eq!(trim_one_newline(b"value\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\r\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\n\n".to_vec()), b"value\n");
    }
}
