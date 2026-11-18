//! Proton Pass provider backed by the official `pass-cli` 2.7.1.
//!
//! Reads use `pass-cli item view --field`, which prints only the field value.
//!
//! Listing uses `pass-cli item list --output json`. This is not a metadata-only
//! fetch: upstream `list_items` downloads and decrypts each `Item`, then
//! serializes an `ItemSummary` without content. This adapter keeps only the
//! title and share id and never returns item content.
//!
//! Creating a missing login uses the stdin template. Existing items cannot be
//! updated safely by pass-cli 2.7.1 and are refused. The check and create are
//! not atomic against external writers.
//!
//! Authentication can use an existing `pass-cli` session or a personal access
//! token supplied through the environment/file named in configuration. The
//! token is passed to the child through its environment only.
//!
//! When a token is configured, each provider instance uses a private
//! per-process `PROTON_PASS_SESSION_DIR` under a verified temporary parent and
//! the filesystem key provider. It therefore cannot reuse or modify the user's
//! default session, and a login is guaranteed to use the configured token.
//! After login, `info --output json` must report a personal access token; a
//! user session is rejected. Without a token, the existing `pass-cli` session
//! is used unchanged.
//!
//! All `list` and `get` calls on one provider instance hold a mutex for the
//! whole check, login, and item operation, so two threads cannot share one
//! CLI session. The private directory is removed on drop; a removal failure
//! prints a redacted warning and leaves it for the system to clean. Token
//! mode fails closed on platforms without the hardened directory walk, or when
//! the temporary path is not a trusted, symlink-free location.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::Deserialize;

use crate::config::ProtonConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{Capabilities, ListedKey, Provider, command_available};
use crate::secret::Secret;

/// Redacted error when the operation mutex is poisoned.
const OPERATION_POISONED: &str = "Proton Pass provider is unavailable after an internal panic";

/// Redacted failure message for session-directory setup.
const SESSION_DIR_ERROR: &str = "could not create an isolated pass-cli session directory";

/// Proton Pass provider; writes create missing login items only.
#[derive(Debug)]
pub struct ProtonProvider {
    name: String,
    command: String,
    vault: Option<String>,
    token: Option<Secret>,
    reason: Option<String>,
    session_dir: OnceLock<SessionDir>,
    operation: Mutex<()>,
}

/// A private per-process directory for one isolated `pass-cli` session.
#[cfg(unix)]
#[derive(Debug)]
struct SessionDir {
    directory: super::lock::PrivateDirectory,
}

#[cfg(unix)]
impl SessionDir {
    fn create() -> Result<Self> {
        let parent = std::env::temp_dir();
        // `pass-cli` reads this override with `std::env::var`, which rejects
        // non-Unicode values and would silently fall back to the default
        // session. Fail closed instead.
        if parent.to_str().is_none() {
            return Err(Error::new(SESSION_DIR_ERROR));
        }
        Ok(Self {
            directory: super::lock::create_private_directory(&parent, "nvault-proton")?,
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
struct SessionDir;

#[cfg(not(unix))]
impl SessionDir {
    fn create() -> Result<Self> {
        Err(Error::new(
            "isolated pass-cli sessions are not implemented on this platform",
        ))
    }

    fn path(&self) -> &Path {
        Path::new("")
    }
}

impl ProtonProvider {
    /// Builds a Proton Pass provider.
    ///
    /// # Errors
    ///
    /// Returns an error when `pass-cli` is unavailable or a configured token
    /// source cannot be read.
    pub fn new(name: &str, config: &ProtonConfig, root: &Path) -> Result<Self> {
        if !command_available(&config.command) && !Path::new(&config.command).is_file() {
            return Err(Error::new(format!(
                "Proton Pass command {:?} is not available; install pass-cli",
                config.command
            )));
        }
        let token = match (&config.token_env, &config.token_file) {
            (Some(variable), _) => Some(crate::provider::credential_from_env(variable)?),
            (None, Some(path)) => Some(crate::provider::credential_from_file(&root.join(path))?),
            (None, None) => None,
        };
        Ok(Self {
            name: name.to_owned(),
            command: config.command.clone(),
            vault: config.vault.clone(),
            token,
            reason: config.reason.clone(),
            session_dir: OnceLock::new(),
            operation: Mutex::new(()),
        })
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, ()>> {
        self.operation
            .lock()
            .map_err(|_| Error::new(OPERATION_POISONED))
    }

    fn command(&self, arguments: &[&str]) -> Result<Command> {
        let mut command = Command::new(&self.command);
        command
            .args(arguments)
            .env_remove("PROTON_PASS_PERSONAL_ACCESS_TOKEN")
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
                "Proton Pass item title {title:?} is ambiguous; use a unique title or configure a vault name that makes it unique"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ItemSummary {
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

    fn can_create(&self) -> bool {
        true
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let _operation = self.lock_operation()?;
        let mut keys = Vec::new();
        for item in self.items()? {
            if !item.title.is_empty() && (prefix.is_empty() || item.title.starts_with(prefix)) {
                keys.push(ListedKey::new(item.title));
            }
        }
        Ok(keys)
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let _operation = self.lock_operation()?;
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

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        let field = key.field().unwrap_or("password");
        if !matches!(field, "password" | "username" | "email" | "totp_uri") {
            return Err(Error::new(
                "Proton create supports only password, username, email, or totp_uri",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("Proton login values must be UTF-8"))?;
        let _operation = self.lock_operation()?;
        // Serialize all nvault Proton writers, including profiles and wrappers.
        let identity = super::lock::identity("proton", "shared", &[]);
        let _write_lock = super::lock::acquire(&identity)?;
        if self.items()?.iter().any(|item| item.title == key.path()) {
            return Err(Error::new(
                "Proton item already exists; safe updates are unavailable",
            ));
        }
        // Serialize directly to a zeroized buffer, without making a secret String.
        #[derive(serde::Serialize)]
        struct Template<'a> {
            title: &'a str,
            #[serde(flatten)]
            field: std::collections::BTreeMap<&'a str, &'a str>,
        }
        let template = Template {
            title: key.path(),
            field: [(field, text)].into_iter().collect(),
        };
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *bytes, &template)
            .map_err(|_| Error::new("could not encode Proton login template"))?;
        let mut args = vec!["item", "create", "login", "--from-template", "-"];
        if let Some(vault) = &self.vault {
            args.extend(["--vault-name", vault]);
        }
        let mut command = self.command(&args)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| Error::new("could not start pass-cli"))?;
        let result = child.stdin.take().map(|mut stdin| stdin.write_all(&bytes));
        let status = child
            .wait()
            .map_err(|_| Error::new("Proton create outcome indeterminate; item may exist; inspect the vault before retrying"))?;
        if !matches!(result, Some(Ok(()))) || !status.success() {
            return Err(Error::new(
                "Proton create outcome indeterminate; item may exist; inspect the vault before retrying",
            ));
        }
        Ok(())
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
    use super::{ProtonProvider, SessionDir, trim_one_newline};

    #[cfg(unix)]
    #[test]
    fn programmatic_none_disables_ambient_token() {
        use crate::config::ProtonConfig;
        use crate::provider::Provider;
        use std::os::unix::fs::PermissionsExt;
        if let Some(script) = std::env::var_os("NVAULT_TEST_PROTON_SCRIPT") {
            let config = ProtonConfig {
                command: script.to_string_lossy().into_owned(),
                vault: None,
                token_env: None,
                token_file: None,
                reason: None,
            };
            let provider =
                ProtonProvider::new("p", &config, std::path::Path::new(".")).expect("provider");
            assert!(provider.list("").expect("session listing").is_empty());
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("nvault-proton-none-{}", std::process::id()));
        std::fs::create_dir(&directory).expect("directory");
        let script = directory.join("pass-cli");
        std::fs::write(&script, "#!/bin/sh\n[ -z \"${PROTON_PASS_PERSONAL_ACCESS_TOKEN+x}\" ] || exit 3\ncase \"$*\" in *'item list'*) printf '%s' '{\"items\":[]}';; *) exit 1;; esac\n").expect("fixture");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let result = std::process::Command::new(std::env::current_exe().expect("executable"))
            .args([
                "--exact",
                "provider::proton::tests::programmatic_none_disables_ambient_token",
            ])
            .env("NVAULT_TEST_PROTON_SCRIPT", &script)
            .env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fake-token")
            .output()
            .expect("child test");
        assert!(result.status.success(), "child test failed");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn concurrent_gets_share_one_serialized_session() {
        use crate::config::ProtonConfig;
        use crate::provider::Provider;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Barrier;

        let directory = std::env::temp_dir().join(format!(
            "nvault-proton-threads-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("test directory");
        let script = directory.join("pass-cli");
        let trace = directory.join("trace");
        let invocation_lock = directory.join("invocation-lock");
        std::fs::write(
            &script,
            format!(
                r#"#!/bin/sh
lock='{lock}'
trace='{trace}'
if ! mkdir "$lock" 2>/dev/null; then
  printf 'overlap\n' >> "$trace"
  exit 90
fi
trap 'rmdir "$lock"' EXIT
sleep 0.1
case "$*" in
  "info --output json")
    if [ -f "${{PROTON_PASS_SESSION_DIR:-/nonexistent}}/.session/session.json" ]; then
      printf '%s\n' '{{"personal_access_token_name":"fixture-pat"}}'
      exit 0
    fi
    exit 1
    ;;
  "login")
    mkdir -p "${{PROTON_PASS_SESSION_DIR}}/.session" || exit 4
    : > "${{PROTON_PASS_SESSION_DIR}}/.session/session.json" || exit 4
    exit 0
    ;;
  *"item list"*)
    printf '%s' '{{"items":[{{"id":"i","title":"DB","share_id":"s"}}]}}'
    ;;
  *"item view"*) printf '%s\n' 'pw' ;;
  *) exit 2 ;;
esac
"#,
                lock = invocation_lock.display(),
                trace = trace.display()
            ),
        )
        .expect("write fixture");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("chmod script");
        let token = directory.join("token");
        std::fs::write(&token, b"not-a-real-token").expect("write token");
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
            .expect("chmod token");
        let config = ProtonConfig {
            command: script.display().to_string(),
            vault: Some("Work".to_owned()),
            token_env: None,
            token_file: Some(std::path::PathBuf::from("token")),
            reason: None,
        };
        let provider = ProtonProvider::new("p", &config, &directory).expect("provider");
        let barrier = Barrier::new(2);
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                provider.get("DB#password")
            });
            let second = scope.spawn(|| {
                barrier.wait();
                provider.get("DB#password")
            });
            (
                first.join().expect("first thread"),
                second.join().expect("second thread"),
            )
        });
        assert_eq!(first.expect("first get").expose(), b"pw".as_slice());
        assert_eq!(second.expect("second get").expose(), b"pw".as_slice());
        let trace = std::fs::read_to_string(&trace).unwrap_or_default();
        assert!(
            !trace.contains("overlap"),
            "concurrent pass-cli invocations overlapped"
        );
        drop(provider);
        std::fs::remove_dir_all(directory).expect("cleanup test directory");
    }

    #[test]
    fn removes_only_one_line_ending() {
        assert_eq!(trim_one_newline(b"value\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\r\n".to_vec()), b"value");
        assert_eq!(trim_one_newline(b"value\n\n".to_vec()), b"value\n");
    }
}
