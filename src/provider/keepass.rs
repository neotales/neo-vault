//! KeePass provider backed by `keepassxc-cli`.
//!
//! This adapter is read-only in the first increment. The database password is
//! written to the child's standard input, never passed as an argument. When no
//! password source is configured and the process has a terminal, the child
//! inherits the terminal so `keepassxc-cli` can prompt itself.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::KeepassConfig;
use crate::error::{Error, Result, unsupported};
use crate::key::Key;
use crate::provider::{Capabilities, ListedKey, Provider, command_available};
use crate::secret::Secret;

/// Read-only KeePass provider.
#[derive(Debug)]
pub struct KeepassProvider {
    name: String,
    database: PathBuf,
    key_file: Option<PathBuf>,
    password: Option<Secret>,
    command: String,
    interactive: bool,
}

impl KeepassProvider {
    /// Builds a KeePass provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the database path or command is invalid or the
    /// configured password source cannot be read.
    pub fn new(name: &str, config: &KeepassConfig, root: &Path) -> Result<Self> {
        if !command_available(&config.command) && !Path::new(&config.command).is_file() {
            return Err(Error::new(format!(
                "KeePass command {:?} is not available; install keepassxc-cli or set command",
                config.command
            )));
        }
        let database = resolve(root, &config.database);
        let key_file = config.key_file.as_ref().map(|path| resolve(root, path));
        let password = match (&config.password_env, &config.password_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                let value = std::env::var_os(variable).expect("checked");
                let bytes = value.as_encoded_bytes().to_vec();
                if bytes.is_empty() || bytes.iter().any(|byte| *byte == 0 || *byte == b'\n') {
                    return Err(Error::new(
                        "KeePass password is empty or contains a newline",
                    ));
                }
                Some(Secret::new(bytes))
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&resolve(root, path))?),
            (Some(variable), None) => {
                return Err(Error::new(format!(
                    "KeePass password environment variable {variable} is not set"
                )));
            }
            (None, None) => None,
        };
        let interactive = std::io::stdin().is_terminal();
        if password.is_none() && key_file.is_none() && !interactive {
            return Err(Error::new(
                "KeePass password is not configured: set password_env or password_file",
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            database,
            key_file,
            password,
            command: config.command.clone(),
            interactive,
        })
    }

    fn command(&self, subcommand: &str, extra: &[&str], positional: &[&str]) -> Command {
        let mut command = Command::new(&self.command);
        command
            .arg(subcommand)
            .arg("-q")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(key_file) = &self.key_file {
            command.arg("-k").arg(key_file);
        }
        if self.password.is_none() && self.key_file.is_some() {
            command.arg("--no-password");
        }
        for argument in extra {
            command.arg(argument);
        }
        command.arg(&self.database);
        for argument in positional {
            command.arg(argument);
        }
        command
    }

    fn run(
        &self,
        subcommand: &str,
        extra: &[&str],
        positional: &[&str],
    ) -> Result<std::process::Output> {
        self.run_command(self.command(subcommand, extra, positional))
    }

    fn run_command(&self, mut command: Command) -> Result<std::process::Output> {
        if self.password.is_some() {
            command.stdin(Stdio::piped());
        } else if self.interactive {
            command.stdin(Stdio::inherit());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command
            .spawn()
            .map_err(|_| Error::new("could not start keepassxc-cli"))?;
        if let Some(password) = &self.password {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::new("could not open keepassxc-cli stdin"))?;
            stdin
                .write_all(password.expose())
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|_| Error::new("could not pass the KeePass password"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| Error::new("keepassxc-cli did not finish"))?;
        if !output.status.success() {
            return Err(Error::new(
                "keepassxc-cli failed; check the database path, password, and key file",
            ));
        }
        if output.stdout.len() > 8 * 1024 * 1024 {
            return Err(Error::new("keepassxc-cli output exceeded the size limit"));
        }
        Ok(output)
    }

    fn read_password(&self, key: &str) -> Result<Secret> {
        let parsed = Key::parse(key)?;
        let field = parsed.field().unwrap_or("Password");
        let output = self.run("show", &["-s", "-a", field], &[parsed.path()])?;
        Ok(Secret::new(trim_one_newline(output.stdout)))
    }
}

impl Provider for KeepassProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "keepass"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_ONLY
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let output = self.run("ls", &["-R", "-f"], &[])?;
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| Error::new("keepassxc-cli produced non-UTF-8 names"))?;
        let mut keys = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.ends_with('/') {
                continue;
            }
            if prefix.is_empty() || line.starts_with(prefix) {
                keys.push(ListedKey::new(line.to_owned()));
            }
        }
        Ok(keys)
    }

    fn get(&self, key: &str) -> Result<Secret> {
        self.read_password(key)
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

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}
