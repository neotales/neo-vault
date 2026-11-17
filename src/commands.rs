//! Command dispatch.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

use crate::cli::{Cli, Command};
use crate::config::{Config, ProviderConfig};
use crate::error::{Error, Result};
use crate::key::{Key, env_name};
use crate::provider::{self, ListedKey, SelectedProvider, command_available};
use crate::secret::Secret;
use crate::shell::{self, Export};

/// Runs the CLI and returns a process exit code.
pub fn run(cli: Cli) -> u8 {
    match dispatch(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("nsvault: {error}");
            1
        }
    }
}

fn dispatch(cli: Cli) -> Result<u8> {
    let config = load_optional(&cli.config)?;
    match cli.command {
        Command::Completion { shell } => {
            let mut command = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(shell, &mut command, "nsvault", &mut io::stdout());
            Ok(0)
        }
        Command::Hook { shell } => {
            print!("{}", shell::hook(shell));
            Ok(0)
        }
        Command::Dir => {
            if let Some(path) = &config {
                println!("{}", path.root.display());
            }
            Ok(0)
        }
        Command::Providers => {
            let config = require_config(config)?;
            list_providers(&config);
            Ok(0)
        }
        Command::Ls { prefix, json } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let prefix =
                prefix.unwrap_or_else(|| provider::default_prefix(&config, cli.prefix.as_deref()));
            let keys = selected.provider.list(&prefix)?;
            if json {
                let keys: Vec<serde_json::Value> = keys
                    .into_iter()
                    .map(|key| serde_json::json!({ "key": key.key }))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&keys)
                        .map_err(|_| Error::new("cannot encode key list"))?
                );
            } else {
                for key in keys {
                    println!("{}", key.key);
                }
            }
            Ok(0)
        }
        Command::Get {
            key,
            field,
            newline,
        } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let key = apply_field(&key, field.as_deref())?;
            let secret = selected.provider.get(&key)?;
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(secret.expose())
                .map_err(|_| Error::new("cannot write secret to stdout"))?;
            if newline {
                stdout
                    .write_all(b"\n")
                    .map_err(|_| Error::new("cannot write secret to stdout"))?;
            }
            stdout
                .flush()
                .map_err(|_| Error::new("cannot write secret to stdout"))?;
            Ok(0)
        }
        Command::Set { key, field, stdin } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let key = apply_field(&key, field.as_deref())?;
            if !selected.provider.capabilities().write {
                return Err(crate::error::unsupported("set", &selected.name));
            }
            let secret = read_secret(stdin)?;
            selected.provider.set(&key, &secret)?;
            eprintln!("nsvault: stored {key}");
            Ok(0)
        }
        Command::Ensure {
            key,
            field,
            stdin,
            json,
        } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let key = apply_field(&key, field.as_deref())?;
            if !selected.provider.capabilities().ensure {
                return Err(crate::error::unsupported("ensure", &selected.name));
            }
            let secret = read_secret(stdin)?;
            let status = selected.provider.ensure(&key, &secret)?;
            let label = match status {
                provider::EnsureStatus::Created => "created",
                provider::EnsureStatus::Present => "present",
            };
            if json {
                println!(r#"{{"status":"{label}"}}"#);
            }
            eprintln!("nsvault: {label} {key}");
            Ok(0)
        }
        Command::Search { query, limit, json } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let needle = query.to_lowercase();
            let mut matches = Vec::new();
            for key in selected.provider.list("")? {
                if key.key.to_lowercase().contains(&needle) {
                    matches.push(key);
                    if matches.len() >= limit {
                        break;
                    }
                }
            }
            if json {
                let matches: Vec<serde_json::Value> = matches
                    .into_iter()
                    .map(|key| serde_json::json!({ "key": key.key }))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&matches)
                        .map_err(|_| Error::new("cannot encode search results"))?
                );
            } else {
                for key in matches {
                    println!("{}", key.key);
                }
            }
            Ok(0)
        }
        Command::Exec {
            env_prefix,
            only,
            command,
        } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let exports = load_exports(
                &config,
                &selected,
                cli.prefix.as_deref(),
                env_prefix.as_deref(),
                only.as_deref(),
            )?;
            run_child(&command, &exports)
        }
        Command::Env {
            shell,
            env_prefix,
            only,
        } => {
            let config = require_config(config)?;
            let selected = provider::select(&config, cli.provider.as_deref())?;
            let exports = load_exports(
                &config,
                &selected,
                cli.prefix.as_deref(),
                env_prefix.as_deref(),
                only.as_deref(),
            )?;
            print!("{}", shell::render_env(&exports, shell)?);
            Ok(0)
        }
    }
}

fn load_optional(explicit: &Option<PathBuf>) -> Result<Option<Config>> {
    if let Some(path) = explicit {
        return Config::load(path).map(Some);
    }
    let current = std::env::current_dir()
        .map_err(|_| Error::new("cannot determine the current directory"))?;
    let Some(path) = Config::discover(&current) else {
        return Ok(None);
    };
    Config::load(&path).map(Some)
}

fn require_config(config: Option<Config>) -> Result<Config> {
    config.ok_or_else(|| {
        Error::new(
            "no .nsvault.toml found; create one or pass --config (completion, hook, and dir work without one)",
        )
    })
}

fn apply_field(key: &str, field: Option<&str>) -> Result<String> {
    let parsed = Key::parse(key)?;
    match field {
        Some(field) => {
            if parsed.field().is_some() {
                return Err(Error::new(
                    "specify a field either as key#field or with --field, not both",
                ));
            }
            if field.is_empty() || field.contains('#') {
                return Err(Error::new("--field must be a non-empty name without '#'"));
            }
            Ok(format!("{}#{field}", parsed.path()))
        }
        None => Ok(key.to_owned()),
    }
}

/// Maximum secret bytes accepted from stdin.
///
/// The read takes one extra byte so an oversized stream is refused rather than
/// silently truncated.
const MAX_SECRET_INPUT_BYTES: usize = 8 * 1024 * 1024;

fn read_secret(force_stdin: bool) -> Result<Secret> {
    let stdin_is_terminal = io::stdin().is_terminal();
    if !force_stdin && stdin_is_terminal {
        let value = rpassword::prompt_password("Secret value: ")
            .map_err(|_| Error::new("cannot read a secret from the terminal"))?;
        if value.is_empty() {
            return Err(Error::new("refusing to store an empty secret"));
        }
        return Ok(Secret::new(value.into_bytes()));
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_SECRET_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("cannot read a secret from stdin"))?;
    if bytes.len() > MAX_SECRET_INPUT_BYTES {
        return Err(Error::new(format!(
            "secret from stdin exceeds the {MAX_SECRET_INPUT_BYTES} byte limit"
        )));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(Error::new("refusing to store an empty secret"));
    }
    Ok(Secret::new(bytes))
}

fn load_exports(
    config: &Config,
    selected: &SelectedProvider,
    prefix: Option<&str>,
    env_prefix: Option<&str>,
    only: Option<&str>,
) -> Result<Vec<Export>> {
    let prefix = provider::default_prefix(config, prefix);
    let keys = selected.provider.list(&prefix)?;
    let keys = shell::select_keys(&keys, only)?;
    let env_prefix = validate_env_prefix(env_prefix.unwrap_or(""))?;
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut exports = Vec::with_capacity(keys.len());
    for ListedKey { key } in keys {
        if key.ends_with('/') {
            continue;
        }
        let name = env_name(&key, &env_prefix)?;
        if let Some(previous) = seen.insert(name.clone(), key.clone()) {
            return Err(Error::new(format!(
                "keys {previous:?} and {key:?} both map to environment variable {name}; use --only or --env-prefix"
            )));
        }
        let value = selected.provider.get(&key)?;
        exports.push(Export { name, value });
    }
    Ok(exports)
}

fn validate_env_prefix(prefix: &str) -> Result<String> {
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if !prefix
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::new(
            "--env-prefix must start with a letter or '_' and contain only letters, digits, and '_'",
        ));
    }
    Ok(prefix.to_owned())
}

fn run_child(command: &[String], exports: &[Export]) -> Result<u8> {
    let mut arguments = command;
    if arguments.first().is_some_and(|argument| argument == "--") {
        arguments = &arguments[1..];
    }
    let Some(program) = arguments.first() else {
        return Err(Error::new("exec requires a command"));
    };
    let mut child = ProcessCommand::new(program);
    child.args(&arguments[1..]);
    for export in exports {
        let value = std::str::from_utf8(export.value.expose())
            .map_err(|_| Error::new(format!("value for {} is not UTF-8", export.name)))?;
        if value.contains('\0') {
            return Err(Error::new(format!(
                "value for {} contains NUL",
                export.name
            )));
        }
        child.env(&export.name, value);
    }
    child
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = child
        .status()
        .map_err(|_| Error::new(format!("could not start {program:?}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Ok(u8::try_from(128 + signal).unwrap_or(1));
        }
    }
    Ok(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1))
}

fn list_providers(config: &Config) {
    for (name, profile) in &config.document.providers {
        let (kind, read, write, ensure, available) = describe(profile);
        let marker = if available {
            ""
        } else {
            " (command unavailable)"
        };
        println!("{name}\t{kind}\tread={read}\twrite={write}\tensure={ensure}{marker}");
    }
}

fn describe(profile: &ProviderConfig) -> (&'static str, bool, bool, bool, bool) {
    match profile {
        ProviderConfig::Vault(_) => ("vault", true, true, true, true),
        ProviderConfig::Openbao(_) => ("openbao", true, true, true, true),
        ProviderConfig::Keepass(config) => (
            "keepass",
            true,
            false,
            false,
            command_available(&config.command),
        ),
        ProviderConfig::Infisical(_) => ("infisical", true, true, true, true),
        ProviderConfig::Vaultwarden(config) => (
            "vaultwarden",
            true,
            true,
            false,
            command_available(&config.command),
        ),
        ProviderConfig::Proton(config) => (
            "proton",
            true,
            false,
            false,
            command_available(&config.command),
        ),
        ProviderConfig::Github(_) => ("github", false, true, false, true),
        ProviderConfig::AwsSecretsManager(_) => ("aws-secrets-manager", true, true, true, true),
        ProviderConfig::GcpSecretManager(_) => ("gcp-secret-manager", true, true, false, true),
        ProviderConfig::AzureKeyVault(_) => ("azure-key-vault", true, true, false, true),
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_field, validate_env_prefix};

    #[test]
    fn field_option_is_not_allowed_with_key_field() {
        assert!(apply_field("path#field", Some("other")).is_err());
        assert_eq!(
            apply_field("path", Some("field")).expect("key"),
            "path#field"
        );
    }

    #[test]
    fn env_prefix_must_be_an_identifier() {
        assert!(validate_env_prefix("APP_").is_ok());
        assert!(validate_env_prefix("").is_ok());
        assert!(validate_env_prefix("1APP").is_err());
        assert!(validate_env_prefix("A-B").is_err());
    }
}
