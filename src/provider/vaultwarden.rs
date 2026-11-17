//! Vaultwarden/Bitwarden provider backed by the `bw` CLI.
//!
//! The adapter is read-only. It never logs in, unlocks, or changes CLI state;
//! the caller supplies a session through `BW_SESSION` (or a file). Values are
//! parsed from the CLI's JSON response in memory and never echo to an error.

use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;
use serde_json::Value;

use crate::config::VaultwardenConfig;
use crate::error::{Error, Result, unsupported};
use crate::key::Key;
use crate::provider::{Capabilities, ListedKey, Provider, command_available};
use crate::secret::Secret;

/// Read-only Vaultwarden provider.
#[derive(Debug)]
pub struct VaultwardenProvider {
    name: String,
    command: String,
    session: Option<Secret>,
}

impl VaultwardenProvider {
    /// Builds a Vaultwarden provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the `bw` executable is unavailable or the session
    /// file cannot be read.
    pub fn new(name: &str, config: &VaultwardenConfig, root: &Path) -> Result<Self> {
        if !command_available(&config.command) && !Path::new(&config.command).is_file() {
            return Err(Error::new(format!(
                "Vaultwarden command {:?} is not available; install the Bitwarden CLI",
                config.command
            )));
        }
        let session = match (&config.session_env, &config.session_file) {
            (Some(variable), _) if std::env::var_os(variable).is_some() => {
                Some(crate::provider::credential_from_env(variable)?)
            }
            (_, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            _ => None,
        };
        Ok(Self {
            name: name.to_owned(),
            command: config.command.clone(),
            session,
        })
    }

    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let mut command = Command::new(&self.command);
        command
            .arg("--nointeraction")
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        if let Some(session) = &self.session {
            command.env(
                "BW_SESSION",
                std::str::from_utf8(session.expose())
                    .map_err(|_| Error::new("Bitwarden session is not valid UTF-8"))?,
            );
        }
        let output = command
            .spawn()
            .map_err(|_| Error::new("could not start the Bitwarden CLI"))?
            .wait_with_output()
            .map_err(|_| Error::new("Bitwarden CLI did not finish"))?;
        if !output.status.success() {
            return Err(Error::new(
                "Bitwarden CLI failed; is the vault unlocked and BW_SESSION current?",
            ));
        }
        if output.stdout.len() > 16 * 1024 * 1024 {
            return Err(Error::new("Bitwarden CLI output exceeded the size limit"));
        }
        Ok(output.stdout)
    }

    fn items(&self) -> Result<Vec<Value>> {
        let output = self.run(&["list", "items"])?;
        parse_items(&output)
    }

    fn item(&self, id: &str) -> Result<Value> {
        let output = self.run(&["get", "item", id])?;
        parse_item(&output)
    }

    fn resolve_item(&self, selector: &str) -> Result<Value> {
        if is_uuid(selector) {
            return self.item(selector);
        }
        let matches: Vec<String> = self
            .items()?
            .into_iter()
            .filter(|item| item.get("name").and_then(Value::as_str) == Some(selector))
            .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        match matches.len() {
            1 => self.item(&matches[0]),
            0 => Err(Error::new(format!(
                "Vaultwarden item {selector:?} was not found"
            ))),
            _ => Err(Error::new(format!(
                "Vaultwarden item name {selector:?} is ambiguous; use the item UUID"
            ))),
        }
    }
}

impl Provider for VaultwardenProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vaultwarden"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_ONLY
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        for item in self.items()? {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && (prefix.is_empty() || name.starts_with(prefix))
            {
                keys.push(ListedKey::new(name.to_owned()));
            }
        }
        Ok(keys)
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        let selector = key.path();
        let item = self.resolve_item(selector)?;
        let field = key.field();
        let value = match field {
            Some("password") => item
                .pointer("/login/password")
                .and_then(Value::as_str)
                .map(str::to_owned),
            Some("username") => item
                .pointer("/login/username")
                .and_then(Value::as_str)
                .map(str::to_owned),
            Some("notes") => item.get("notes").and_then(Value::as_str).map(str::to_owned),
            Some("name") => item.get("name").and_then(Value::as_str).map(str::to_owned),
            Some("id") => item.get("id").and_then(Value::as_str).map(str::to_owned),
            Some(custom) => custom_field(&item, custom),
            None => default_field(&item),
        };
        value
            .map(|value| Secret::new(value.into_bytes()))
            .ok_or_else(|| {
                Error::new(format!(
                    "Vaultwarden item {selector:?} has no value for field {:?}",
                    field.unwrap_or("password")
                ))
            })
    }

    fn set(&self, _key: &str, _value: &Secret) -> Result<()> {
        Err(unsupported("set", &self.name))
    }
}

fn parse_items(bytes: &[u8]) -> Result<Vec<Value>> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if let Some(data) = value.get("data")
            && let Some(items) = data.as_array()
        {
            return Ok(items.clone());
        }
        if let Some(items) = value.as_array() {
            return Ok(items.clone());
        }
    }
    Err(Error::new(
        "Bitwarden CLI returned an unexpected item list; is the session valid?",
    ))
}

fn parse_item(bytes: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Envelope {
        data: Value,
    }
    if let Ok(envelope) = serde_json::from_slice::<Envelope>(bytes) {
        return Ok(envelope.data);
    }
    serde_json::from_slice(bytes)
        .map_err(|_| Error::new("Bitwarden CLI returned an unexpected item"))
}

fn default_field(item: &Value) -> Option<String> {
    if let Some(password) = item
        .pointer("/login/password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Some(password.to_owned());
    }
    if item.get("type").and_then(Value::as_u64) == Some(2) {
        return item.get("notes").and_then(Value::as_str).map(str::to_owned);
    }
    None
}

fn custom_field(item: &Value, name: &str) -> Option<String> {
    item.get("fields")
        .and_then(Value::as_array)?
        .iter()
        .find(|field| {
            field
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .and_then(|field| field.get("value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::{default_field, is_uuid, parse_item};
    use serde_json::json;

    #[test]
    fn accepts_uuid_and_rejects_a_name() {
        assert!(is_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid("my item"));
    }

    #[test]
    fn default_login_field_is_the_password() {
        let item = json!({"login":{"password":"value"},"notes":"note"});
        assert_eq!(default_field(&item).as_deref(), Some("value"));
    }

    #[test]
    fn parses_a_response_envelope_without_printing_it() {
        let item = parse_item(br#"{"success":true,"data":{"name":"x"}}"#).expect("item");
        assert_eq!(item["name"], "x");
    }
}
