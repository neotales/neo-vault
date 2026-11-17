#![cfg(unix)]

//! Opt-in test against a real `keepassxc-cli` and a generated temporary KDBX.
//!
//! Run explicitly:
//!
//! ```sh
//! cargo test --test keepass_kdbx -- --ignored --nocapture
//! ```
//!
//! It requires `keepassxc-cli` on `PATH` or `NSVAULT_TEST_KEEPASSXC` set to an
//! absolute path. The database, its password, and every entry value are
//! throwaway fixtures created in a private temporary directory. No existing
//! vault is opened.
//!
//! The configured command is a wrapper that records every argument the adapter
//! passes and then execs the real CLI with the same stdin. That proves the
//! value and the database password do not appear in `argv`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DATABASE_PASSWORD: &str = "not-a-real-database-password";
const INITIAL_VALUE: &str = "initial-secret-value";
const REPLACEMENT_VALUE: &str = "replacement-secret-value";

fn scratch_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "nsvault-keepass-kdbx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("scratch dir");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("scratch mode");
    path
}

fn keepass_cli() -> PathBuf {
    if let Some(value) = std::env::var_os("NSVAULT_TEST_KEEPASSXC") {
        return PathBuf::from(value);
    }
    let path = std::env::var_os("PATH").expect("PATH is set");
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("keepassxc-cli");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("keepassxc-cli was not found; set NSVAULT_TEST_KEEPASSXC to its absolute path");
}

fn run_cli(real: &Path, arguments: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(real);
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn keepassxc-cli");
    if let Some(stdin) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write keepassxc-cli stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for keepassxc-cli")
}

fn run_nsvault(directory: &Path, arguments: &[&str], stdin: Option<&[u8]>, real: &Path) -> Output {
    let lock_dir = directory.join("locks");
    std::fs::create_dir_all(&lock_dir).expect("lock dir");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700)).expect("lock mode");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nsvault"));
    command
        .args(arguments)
        .current_dir(directory)
        .env("KP_TEST_PASSWORD", DATABASE_PASSWORD)
        .env("NSVAULT_LOCK_DIR", &lock_dir)
        .env("NSVAULT_TEST_KEEPASS_REAL", real)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn nsvault");
    if let Some(stdin) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin)
            .expect("write nsvault stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for nsvault")
}

fn show(real: &Path, database: &Path, field: &str, entry: &str) -> String {
    let database = database.to_str().expect("database path is UTF-8");
    let output = run_cli(
        real,
        &["show", "-q", "-s", "-a", field, "--", database, entry],
        Some(&format!("{DATABASE_PASSWORD}\n")),
    );
    assert!(
        output.status.success(),
        "keepassxc-cli show {entry} {field} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("show output is UTF-8")
        .trim_end_matches(['\n', '\r'])
        .to_owned()
}

fn wrapper(directory: &Path) -> PathBuf {
    let path = directory.join("keepassxc-cli-wrapper");
    std::fs::write(
        &path,
        r#"#!/bin/sh
printf '<%s>\n' "$@" >> "$(dirname "$0")/argv.log"
exec "$NSVAULT_TEST_KEEPASS_REAL" "$@"
"#,
    )
    .expect("write wrapper");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("wrapper mode");
    path
}

#[test]
#[ignore = "requires keepassxc-cli and generates a temporary KDBX"]
fn generated_kdbx_round_trip_preserves_fields_and_ensures_are_create_only() {
    let real = keepass_cli();
    let directory = scratch_dir();
    let database = directory.join("vault.kdbx");
    let database_text = database.to_str().expect("database path is UTF-8");

    let created = run_cli(
        &real,
        &["db-create", "-t", "100", "-p", database_text],
        Some(&format!("{DATABASE_PASSWORD}\n{DATABASE_PASSWORD}\n")),
    );
    assert!(
        created.status.success(),
        "db-create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let group = run_cli(
        &real,
        &["mkdir", "-q", database_text, "Group"],
        Some(&format!("{DATABASE_PASSWORD}\n")),
    );
    assert!(
        group.status.success(),
        "mkdir failed: {}",
        String::from_utf8_lossy(&group.stderr)
    );

    let seeded = run_cli(
        &real,
        &[
            "add",
            "-q",
            "-u",
            "alice",
            "--url",
            "https://example.invalid/",
            "--notes",
            "keep-me",
            "-p",
            database_text,
            "Group/DB",
        ],
        Some(&format!("{DATABASE_PASSWORD}\n{INITIAL_VALUE}\n")),
    );
    assert!(
        seeded.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&seeded.stderr)
    );

    let command = wrapper(&directory);
    std::fs::write(
        directory.join(".nsvault.toml"),
        format!(
            r#"version = 1
provider = "k"
[providers.k]
kind = "keepass"
database = "vault.kdbx"
command = {:?}
password_env = "KP_TEST_PASSWORD"
"#,
            command.display().to_string()
        ),
    )
    .expect("write config");

    let read = run_nsvault(&directory, &["get", "Group/DB"], None, &real);
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&read.stdout), INITIAL_VALUE);

    let updated = run_nsvault(
        &directory,
        &["set", "Group/DB"],
        Some(b"replacement-secret-value\n"),
        &real,
    );
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    assert!(!String::from_utf8_lossy(&updated.stderr).contains(REPLACEMENT_VALUE));
    assert_eq!(
        show(&real, &database, "Password", "Group/DB"),
        REPLACEMENT_VALUE
    );
    assert_eq!(show(&real, &database, "UserName", "Group/DB"), "alice");
    assert_eq!(
        show(&real, &database, "URL", "Group/DB"),
        "https://example.invalid/"
    );
    assert_eq!(show(&real, &database, "Notes", "Group/DB"), "keep-me");

    let present = run_nsvault(
        &directory,
        &["ensure", "Group/DB"],
        Some(b"must-not-replace\n"),
        &real,
    );
    assert!(
        present.status.success(),
        "{}",
        String::from_utf8_lossy(&present.stderr)
    );
    assert!(String::from_utf8_lossy(&present.stderr).contains("present"));
    assert_eq!(
        show(&real, &database, "Password", "Group/DB"),
        REPLACEMENT_VALUE
    );

    let ensured = run_nsvault(
        &directory,
        &["ensure", "Group/New"],
        Some(b"created-secret-value\n"),
        &real,
    );
    assert!(
        ensured.status.success(),
        "{}",
        String::from_utf8_lossy(&ensured.stderr)
    );
    assert!(String::from_utf8_lossy(&ensured.stderr).contains("created"));
    assert_eq!(
        show(&real, &database, "Password", "Group/New"),
        "created-secret-value"
    );

    let added = run_nsvault(
        &directory,
        &["set", "Group/Second"],
        Some(b"second-secret-value\n"),
        &real,
    );
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert_eq!(
        show(&real, &database, "Password", "Group/Second"),
        "second-secret-value"
    );

    let refused = run_nsvault(
        &directory,
        &["set", "Group/DB#UserName"],
        Some(b"must-not-be-written\n"),
        &real,
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("only the Password field"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(show(&real, &database, "UserName", "Group/DB"), "alice");

    let missing_group = run_nsvault(
        &directory,
        &["set", "Missing/Entry"],
        Some(b"must-not-be-written\n"),
        &real,
    );
    assert!(!missing_group.status.success());
    assert!(
        String::from_utf8_lossy(&missing_group.stderr).contains("does not exist"),
        "{}",
        String::from_utf8_lossy(&missing_group.stderr)
    );

    let multiline = run_nsvault(
        &directory,
        &["set", "Group/DB"],
        Some(b"has\nnewline"),
        &real,
    );
    assert!(!multiline.status.success());
    assert!(
        String::from_utf8_lossy(&multiline.stderr).contains("newline"),
        "{}",
        String::from_utf8_lossy(&multiline.stderr)
    );
    assert_eq!(
        show(&real, &database, "Password", "Group/DB"),
        REPLACEMENT_VALUE
    );

    let mut children = Vec::new();
    for index in 0..4 {
        let lock_dir = directory.join("locks");
        let mut child = Command::new(env!("CARGO_BIN_EXE_nsvault"))
            .args(["set", &format!("Group/Concurrent{index}")])
            .current_dir(&directory)
            .env("KP_TEST_PASSWORD", DATABASE_PASSWORD)
            .env("NSVAULT_LOCK_DIR", &lock_dir)
            .env("NSVAULT_TEST_KEEPASS_REAL", &real)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn concurrent nsvault");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(format!("concurrent-{index}-value\n").as_bytes())
            .expect("write concurrent stdin");
        drop(child.stdin.take());
        children.push((index, child));
    }
    for (index, child) in children {
        let output = child.wait_with_output().expect("wait for concurrent write");
        assert!(
            output.status.success(),
            "concurrent write {index} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for index in 0..4 {
        assert_eq!(
            show(
                &real,
                &database,
                "Password",
                &format!("Group/Concurrent{index}")
            ),
            format!("concurrent-{index}-value")
        );
    }

    let argv = std::fs::read_to_string(directory.join("argv.log")).expect("argv log");
    for secret in [
        DATABASE_PASSWORD,
        INITIAL_VALUE,
        REPLACEMENT_VALUE,
        "created-secret-value",
        "second-secret-value",
        "concurrent-0-value",
        "must-not-replace",
        "must-not-be-written",
    ] {
        assert!(!argv.contains(secret), "argv contained a secret: {secret}");
    }

    std::fs::remove_dir_all(&directory).expect("cleanup");
}
