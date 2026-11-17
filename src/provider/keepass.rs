//! KeePass provider backed by `keepassxc-cli`.
//!
//! The database password is written to the child's standard input, never
//! passed as an argument. When no password source is configured and the
//! process has a terminal, reads inherit the terminal so `keepassxc-cli` can
//! prompt itself. A write never inherits the terminal: the entry value and the
//! database password share stdin, so the prompt order would be ambiguous.
//!
//! A write can replace or create an entry's `Password` field. Other fields are
//! read-only because `keepassxc-cli edit` takes `-u`, `--url`, and `--notes`
//! values in `argv`; this adapter never puts a secret there. `edit` changes
//! only the password and leaves every other field of the entry intact.
//!
//! `set` and `ensure` hold one same-user advisory lock keyed by the canonical
//! database path, so cooperating nsvault processes do not overlap a
//! read-modify-write of the KDBX file. The lock does not cover KeePassXC's GUI,
//! `keepassxc-cli` invoked by another tool, or another host: `keepassxc-cli`
//! has no conditional write, so an external change that lands between our read
//! and save can be lost. See the provider matrix in `README.md`.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use crate::config::KeepassConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{Capabilities, EnsureStatus, ListedKey, Provider, command_available, lock};
use crate::secret::Secret;

/// Maximum bytes accepted for one written value.
const MAX_WRITE_BYTES: usize = 1024 * 1024;

/// What a key path names in the database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    /// No entry and no group has this path.
    Absent,
    /// The path names an entry.
    Entry,
    /// The path names a group.
    Group,
}

/// KeePass provider.
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
        // End option parsing before the database path: a path or entry name
        // that starts with `-` is still a positional value, not a flag.
        command.arg("--").arg(&self.database);
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

    /// Returns the lock identity for this database.
    ///
    /// The canonical path, hashed so an unusual non-UTF-8 path stays distinct,
    /// makes two profiles that name the same KDBX file share one lock even when
    /// they use different relative paths or symbolic links. Profile names and
    /// every credential are excluded.
    fn write_identity(&self) -> Result<String> {
        let canonical = std::fs::canonicalize(&self.database).map_err(|_| {
            Error::new(
                "KeePass database path could not be resolved; the database must exist before a write",
            )
        })?;
        let digest = Sha256::digest(canonical.as_os_str().as_encoded_bytes());
        Ok(lock::identity("keepass", &format!("{digest:x}"), &[]))
    }

    /// Rejects a write whose value cannot travel through the CLI's stdin.
    fn check_value(value: &Secret) -> Result<()> {
        if value.expose().len() > MAX_WRITE_BYTES {
            return Err(Error::new(format!(
                "KeePass values are limited to {MAX_WRITE_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("KeePass values must be UTF-8 text"))?;
        if text.is_empty() {
            return Err(Error::new("refusing to store an empty secret"));
        }
        if text.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(Error::new(
                "KeePass values must not contain a newline or NUL: keepassxc-cli reads one line from stdin",
            ));
        }
        Ok(())
    }

    /// A write needs both lines on stdin.
    fn require_writable(&self) -> Result<()> {
        if self.password.is_none() && self.key_file.is_none() {
            return Err(Error::new(
                "KeePass writes need password_env, password_file, or a key file: the value and an interactive database password cannot share stdin",
            ));
        }
        Ok(())
    }

    /// Builds an `add` or `edit` invocation.
    ///
    /// `-p` asks the CLI for the entry password from the same stdin stream the
    /// database password comes from. The value is then written by
    /// [`Self::write_entry`], never placed in `argv`.
    fn write_command(&self, subcommand: &str, entry: &str) -> Command {
        let mut command = Command::new(&self.command);
        command
            .arg(subcommand)
            .arg("-q")
            .arg("-p")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(key_file) = &self.key_file {
            command.arg("-k").arg(key_file);
        }
        if self.password.is_none() && self.key_file.is_some() {
            command.arg("--no-password");
        }
        command.arg("--").arg(&self.database).arg(entry);
        command
    }

    /// Adds or edits one entry password.
    ///
    /// The CLI reads the database password first (when configured) and then the
    /// entry password, one line each, from stdin. stdout and stderr are
    /// discarded on success and reduced to a fixed message on failure, so a
    /// value or response body never reaches the caller's terminal.
    fn write_entry(&self, subcommand: &str, entry: &str, value: &Secret) -> Result<()> {
        let mut command = self.write_command(subcommand, entry);
        command.stdin(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| Error::new("could not start keepassxc-cli"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::new("could not open keepassxc-cli stdin"))?;
        let input = write_lines(&mut stdin, self.password.as_ref(), value);
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|_| Error::new("keepassxc-cli did not finish"))?;
        if !output.status.success() {
            return Err(Error::new(
                "keepassxc-cli refused the write; check the database path, password, key file, entry, and parent group",
            ));
        }
        if input.is_err() {
            return Err(Error::new(
                "keepassxc-cli did not accept the value on stdin",
            ));
        }
        if output.stdout.len() > 8 * 1024 * 1024 {
            return Err(Error::new("keepassxc-cli output exceeded the size limit"));
        }
        Ok(())
    }

    /// Lists every entry and group path in the database.
    fn listing(&self) -> Result<Vec<String>> {
        let output = self.run("ls", &["-R", "-f"], &[])?;
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| Error::new("keepassxc-cli produced non-UTF-8 names"))?;
        Ok(text
            .lines()
            .map(|line| line.trim_end_matches('\r').to_owned())
            .filter(|line| !line.is_empty())
            .collect())
    }

    /// Requires the parent path, when there is one, to be an existing group.
    fn require_parent_group(lines: &[String], path: &str) -> Result<()> {
        let Some((parent, _)) = path.rsplit_once('/') else {
            return Ok(());
        };
        if parent.is_empty() {
            return Ok(());
        }
        match classify(lines, parent)? {
            EntryState::Group => Ok(()),
            EntryState::Entry => Err(Error::new(format!(
                "KeePass parent {parent:?} is an entry, not a group"
            ))),
            EntryState::Absent => Err(Error::new(format!(
                "KeePass group {parent:?} does not exist; create it before this write"
            ))),
        }
    }

    /// Rejects a group-shaped key before it can be mistaken for an entry.
    fn require_entry_path(path: &str) -> Result<()> {
        if path.ends_with('/') {
            return Err(Error::new(
                "KeePass key must name an entry, not a group path ending in '/'",
            ));
        }
        Ok(())
    }

    /// Rejects a field other than `Password` before contacting the database.
    fn require_password_field(key: &Key<'_>) -> Result<()> {
        match key.field() {
            None => Ok(()),
            Some(field) if field.eq_ignore_ascii_case("Password") => Ok(()),
            Some(field) => Err(Error::new(format!(
                "KeePass writes support only the Password field; {field:?} is read-only because keepassxc-cli takes that value in argv"
            ))),
        }
    }
}

/// Writes the database password, when configured, and the entry password.
fn write_lines(
    stdin: &mut impl Write,
    password: Option<&Secret>,
    value: &Secret,
) -> std::io::Result<()> {
    if let Some(password) = password {
        stdin.write_all(password.expose())?;
        stdin.write_all(b"\n")?;
    }
    stdin.write_all(value.expose())?;
    stdin.write_all(b"\n")
}

/// Classifies one path against a flattened `ls -R -f` listing.
fn classify(lines: &[String], path: &str) -> Result<EntryState> {
    let entry = lines.iter().any(|line| line == path);
    let group = lines
        .iter()
        .any(|line| line.strip_suffix('/') == Some(path));
    match (entry, group) {
        (true, true) => Err(Error::new(format!(
            "KeePass path {path:?} is both a group and an entry"
        ))),
        (true, false) => Ok(EntryState::Entry),
        (false, true) => Ok(EntryState::Group),
        (false, false) => Ok(EntryState::Absent),
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
        Capabilities::READ_WRITE_ENSURE
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        for line in self.listing()? {
            if line.ends_with('/') {
                continue;
            }
            if prefix.is_empty() || line.starts_with(prefix) {
                keys.push(ListedKey::new(line));
            }
        }
        Ok(keys)
    }

    fn get(&self, key: &str) -> Result<Secret> {
        self.read_password(key)
    }

    /// Replaces or creates an entry's `Password` field.
    ///
    /// An existing entry is edited, which leaves its username, URL, notes,
    /// custom attributes, tags, and UUID untouched. A new entry is added only
    /// when its parent group already exists. The same-user lock is held across
    /// the listing and the write, so cooperating nsvault processes cannot
    /// interleave. `keepassxc-cli` has no conditional write, so an external
    /// process (the KeePassXC GUI, another tool, another host) is not
    /// coordinated.
    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        Self::require_entry_path(key.path())?;
        Self::require_password_field(&key)?;
        Self::check_value(value)?;
        self.require_writable()?;
        let _lock = lock::acquire(&self.write_identity()?)?;
        let lines = self.listing()?;
        match classify(&lines, key.path())? {
            EntryState::Entry => self.write_entry("edit", key.path(), value),
            EntryState::Group => Err(Error::new(format!(
                "KeePass path {:?} is a group; name an entry",
                key.path()
            ))),
            EntryState::Absent => {
                Self::require_parent_group(&lines, key.path())?;
                self.write_entry("add", key.path(), value)
            }
        }
    }

    /// Creates an entry only when the database confirms it is absent.
    ///
    /// The check and the add run under the same lock, so a second cooperating
    /// nsvault writer sees the created entry instead of adding a duplicate.
    /// The tested `keepassxc-cli` 2.7.12 refuses a duplicate path, so an
    /// uncoordinated writer cannot be overwritten; if the add fails, the
    /// listing is repeated and a now-present entry is reported as `Present`.
    /// The duplicate refusal is observed behavior, not a documented contract:
    /// a CLI version that upserts would defeat this check. A group, an unreadable
    /// database, or a failed listing is an error, not absence.
    fn ensure(&self, raw_key: &str, value: &Secret) -> Result<EnsureStatus> {
        let key = Key::parse(raw_key)?;
        Self::require_entry_path(key.path())?;
        Self::require_password_field(&key)?;
        Self::check_value(value)?;
        self.require_writable()?;
        let _lock = lock::acquire(&self.write_identity()?)?;
        let lines = self.listing()?;
        match classify(&lines, key.path())? {
            EntryState::Entry => Ok(EnsureStatus::Present),
            EntryState::Group => Err(Error::new(format!(
                "KeePass path {:?} is a group; name an entry",
                key.path()
            ))),
            EntryState::Absent => {
                Self::require_parent_group(&lines, key.path())?;
                match self.write_entry("add", key.path(), value) {
                    Ok(()) => Ok(EnsureStatus::Created),
                    Err(write_error) => {
                        // An uncoordinated writer may have added the entry
                        // between the listing and the add. The CLI refuses the
                        // duplicate, so re-list rather than retrying a write.
                        if let Ok(lines) = self.listing()
                            && matches!(classify(&lines, key.path()), Ok(EntryState::Entry))
                        {
                            return Ok(EnsureStatus::Present);
                        }
                        Err(write_error)
                    }
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::{EntryState, KeepassProvider, MAX_WRITE_BYTES, classify, write_lines};
    use crate::config::KeepassConfig;
    use crate::key::Key;
    use crate::provider::Provider;
    use crate::secret::Secret;
    use std::path::{Path, PathBuf};

    #[test]
    fn classify_distinguishes_entries_groups_and_absence() {
        let lines = [
            "Entry".to_owned(),
            "Group/".to_owned(),
            "Group/Child".to_owned(),
        ];
        assert_eq!(classify(&lines, "Entry").expect("entry"), EntryState::Entry);
        assert_eq!(classify(&lines, "Group").expect("group"), EntryState::Group);
        assert_eq!(
            classify(&lines, "Group/Child").expect("nested entry"),
            EntryState::Entry
        );
        assert_eq!(
            classify(&lines, "Missing").expect("absent"),
            EntryState::Absent
        );
        assert!(classify(&["Both".to_owned(), "Both/".to_owned()], "Both").is_err());
    }

    #[test]
    fn values_that_cannot_travel_on_one_line_are_refused() {
        assert!(KeepassProvider::check_value(&Secret::new(b"a normal value".to_vec())).is_ok());
        assert!(KeepassProvider::check_value(&Secret::new(Vec::new())).is_err());
        assert!(KeepassProvider::check_value(&Secret::new(b"line\nbreak".to_vec())).is_err());
        assert!(KeepassProvider::check_value(&Secret::new(b"line\rbreak".to_vec())).is_err());
        assert!(KeepassProvider::check_value(&Secret::new(b"nul\0byte".to_vec())).is_err());
        assert!(KeepassProvider::check_value(&Secret::new(vec![0xff])).is_err());
        assert!(
            KeepassProvider::check_value(&Secret::new(vec![b'x'; MAX_WRITE_BYTES + 1])).is_err()
        );
    }

    #[test]
    fn stdin_order_is_database_password_then_value() {
        let mut bytes = Vec::new();
        write_lines(
            &mut bytes,
            Some(&Secret::new(b"database".to_vec())),
            &Secret::new(b"value".to_vec()),
        )
        .expect("write lines");
        assert_eq!(bytes, b"database\nvalue\n");

        let mut key_file_only = Vec::new();
        write_lines(&mut key_file_only, None, &Secret::new(b"value".to_vec()))
            .expect("write lines");
        assert_eq!(key_file_only, b"value\n");
    }

    #[cfg(unix)]
    fn scratch_dir(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "nsvault-keepass-unit-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("scratch dir");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("scratch mode");
        directory
    }

    #[cfg(unix)]
    fn provider(root: &Path, database: &str) -> KeepassProvider {
        use std::os::unix::fs::PermissionsExt;

        let password = root.join("database-password");
        std::fs::write(&password, b"not-a-real-password").expect("password fixture");
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600))
            .expect("password mode");
        let config = KeepassConfig {
            database: PathBuf::from(database),
            key_file: None,
            password_env: None,
            password_file: Some(PathBuf::from("database-password")),
            command: "/bin/true".to_owned(),
        };
        KeepassProvider::new("k", &config, root).expect("provider")
    }

    #[cfg(unix)]
    #[test]
    fn non_password_fields_are_refused_before_the_database_is_opened() {
        let directory = scratch_dir("field");
        let provider = provider(&directory, "missing.kdbx");
        let error = provider
            .set(
                "Entry#UserName",
                &Secret::new(b"must-not-be-written".to_vec()),
            )
            .expect_err("a non-password field must be refused");
        assert!(
            error.message().contains("only the Password field"),
            "{}",
            error.message()
        );
        assert!(
            !error.message().contains("must-not-be-written"),
            "the value must not be echoed"
        );
        assert!(Key::parse("Entry#password").is_ok());
        let group = provider
            .set("Group/", &Secret::new(b"must-not-be-written".to_vec()))
            .expect_err("a group path must be refused");
        assert!(
            group.message().contains("group path"),
            "{}",
            group.message()
        );
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_is_stable_and_separates_databases() {
        let directory = scratch_dir("identity");
        std::fs::write(directory.join("one.kdbx"), b"fixture").expect("one");
        std::fs::write(directory.join("two.kdbx"), b"fixture").expect("two");

        let one = provider(&directory, "one.kdbx");
        let one_dotted = provider(&directory, "./one.kdbx");
        let two = provider(&directory, "two.kdbx");
        assert_eq!(
            one.write_identity().expect("one"),
            one_dotted.write_identity().expect("one dotted")
        );
        assert_ne!(
            one.write_identity().expect("one"),
            two.write_identity().expect("two")
        );
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_write_requires_an_existing_database() {
        let directory = scratch_dir("missing-database");
        let provider = provider(&directory, "missing.kdbx");
        let error = provider
            .set("Entry", &Secret::new(b"not-a-real-secret".to_vec()))
            .expect_err("a missing database must fail");
        assert!(
            error.message().contains("must exist"),
            "{}",
            error.message()
        );
        std::fs::remove_dir_all(directory).expect("cleanup");
    }
}
