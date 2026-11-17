//! End-to-end CLI tests against local fixtures.
//!
//! No real provider credential or remote service is used. The HTTP fixture is
//! loopback-only, and the CLI fixtures are temporary scripts.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Map, Value, json};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nsvault")
}

fn run(
    directory: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    stdin: Option<&[u8]>,
) -> Output {
    let mut command = Command::new(binary());
    command
        .args(arguments)
        .current_dir(directory)
        .envs(environment.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn nsvault");
    if let Some(bytes) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for nsvault")
}

fn run_with_stdin_file(
    directory: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    stdin_path: &Path,
) -> Output {
    let stdin = std::fs::File::open(stdin_path).expect("open stdin fixture");
    Command::new(binary())
        .args(arguments)
        .current_dir(directory)
        .envs(environment.iter().copied())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run nsvault with stdin file")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct Fixture {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let request = read_request(&mut stream);
                        if let Some(request) = request {
                            thread_requests.lock().expect("requests").push(request);
                            let response = vault_response(
                                thread_requests
                                    .lock()
                                    .expect("requests")
                                    .last()
                                    .expect("request"),
                            );
                            let _ = stream.write_all(response.as_bytes());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            requests,
            stop,
        }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("requests").clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut chunk).ok()?;
        if count == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..count]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let headers = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let mut lines = headers.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut chunk).ok()?;
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
    }
    body.truncate(content_length);
    Some(Request { method, path, body })
}

fn vault_response(request: &Request) -> String {
    let status_and_body = if request.path.starts_with("/v1/secret/metadata/apps/prod") {
        ("200 OK", r#"{"data":{"keys":["db"]}}"#.to_owned())
    } else if request
        .path
        .starts_with("/v1/secret/metadata/apps?list=true")
    {
        ("200 OK", r#"{"data":{"keys":["prod/"]}}"#.to_owned())
    } else if request.path.starts_with("/v1/secret/metadata?list=true") {
        ("200 OK", r#"{"data":{"keys":["apps/"]}}"#.to_owned())
    } else if request.path.starts_with("/v1/secret/data/apps/prod/db") {
        if request.method == "GET" {
            (
                "200 OK",
                r#"{"data":{"data":{"value":"s3cr3t","user":"alice"}}}"#.to_owned(),
            )
        } else {
            ("204 No Content", String::new())
        }
    } else {
        ("404 Not Found", String::new())
    };
    let (status, body) = status_and_body;
    simple_response(status, &body)
}

fn simple_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn vault_config(directory: &Path, port: u16) {
    std::fs::write(
        directory.join(".nsvault.toml"),
        format!(
            r#"version = 1
provider = "v"
prefix = "apps/prod"

[providers.v]
kind = "vault"
address = "http://127.0.0.1:{port}"
mount = "secret"
token_env = "TEST_VAULT_TOKEN"
allow_http_loopback = true
"#
        ),
    )
    .expect("write config");
}

#[test]
fn lists_reads_writes_and_injects_through_the_cli() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let listing = run(&directory, &["ls"], &environment, None);
    assert!(listing.status.success(), "{}", stderr(&listing));
    assert_eq!(stdout(&listing), "apps/prod/db\n");

    let get = run(
        &directory,
        &["get", "apps/prod/db#user"],
        &environment,
        None,
    );
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "alice");

    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &environment,
        Some(b"new-value\n"),
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert!(stdout(&set).is_empty());
    let body = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PATCH")
        .expect("write request");
    let body = String::from_utf8(body.body).expect("utf8 request body");
    assert!(body.contains(r#""value":"new-value""#));
    assert!(!stderr(&set).contains("new-value"));

    let exec = run(
        &directory,
        &["exec", "--", "sh", "-c", "test \"$DB\" = s3cr3t"],
        &environment,
        None,
    );
    assert!(exec.status.success(), "{}", stderr(&exec));

    let exports = run(&directory, &["env", "--shell", "bash"], &environment, None);
    assert!(exports.status.success(), "{}", stderr(&exports));
    assert!(stdout(&exports).contains("export DB='s3cr3t'"));
    assert!(stdout(&exports).contains("NSVAULT_LOADED_KEYS='DB'"));
}

struct VaultMergeFixture {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    state: Arc<Mutex<BTreeMap<String, Map<String, Value>>>>,
    patch_404: Arc<Mutex<BTreeSet<String>>>,
    stop: Arc<AtomicBool>,
}

impl VaultMergeFixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(BTreeMap::new()));
        let patch_404 = Arc::new(Mutex::new(BTreeSet::new()));
        state.lock().expect("state").insert(
            "apps/prod/db".to_owned(),
            serde_json::from_value(json!({"user": "alice", "value": "old"}))
                .expect("initial state"),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_state = Arc::clone(&state);
        let thread_patch_404 = Arc::clone(&patch_404);
        let thread_stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        if let Some(request) = read_request(&mut stream) {
                            thread_requests
                                .lock()
                                .expect("requests")
                                .push(request.clone());
                            let response =
                                vault_merge_response(&request, &thread_state, &thread_patch_404);
                            let _ = stream.write_all(response.as_bytes());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            requests,
            state,
            patch_404,
            stop,
        }
    }

    fn force_patch_404(&self, path: &str) {
        self.patch_404
            .lock()
            .expect("patch 404 state")
            .insert(path.to_owned());
    }
}

impl Drop for VaultMergeFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn request_data(body: &[u8]) -> Option<Map<String, Value>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value.get("data")?.as_object().cloned()
}

fn vault_merge_response(
    request: &Request,
    state: &Arc<Mutex<BTreeMap<String, Map<String, Value>>>>,
    patch_404: &Arc<Mutex<BTreeSet<String>>>,
) -> String {
    let (status, body) = if let Some(path) = request.path.strip_prefix("/v1/secret/data/") {
        let path = path.split('?').next().unwrap_or(path);
        let mut state = state.lock().expect("state");
        match request.method.as_str() {
            "GET" => match state.get(path) {
                Some(data) => ("200 OK", json!({"data": {"data": data}}).to_string()),
                None => ("404 Not Found", String::new()),
            },
            "PATCH" => {
                if patch_404.lock().expect("patch 404 state").remove(path) {
                    ("404 Not Found", String::new())
                } else {
                    match (state.get_mut(path), request_data(&request.body)) {
                        (Some(existing), Some(changes)) => {
                            existing.extend(changes);
                            ("204 No Content", String::new())
                        }
                        _ => ("404 Not Found", String::new()),
                    }
                }
            }
            "POST" => {
                let parsed: Value = match serde_json::from_slice(&request.body) {
                    Ok(parsed) => parsed,
                    Err(_) => return simple_response("400 Bad Request", ""),
                };
                let Some(data) = request_data(&request.body) else {
                    return simple_response("400 Bad Request", "");
                };
                let cas = parsed.pointer("/options/cas").and_then(Value::as_u64);
                if cas == Some(0) && state.contains_key(path) {
                    // Simulate a concurrent creator winning between PATCH 404
                    // and the CAS 0 create attempt.
                    return simple_response("400 Bad Request", "");
                }
                state.insert(path.to_owned(), data);
                ("204 No Content", String::new())
            }
            _ => ("405 Method Not Allowed", String::new()),
        }
    } else {
        ("404 Not Found", String::new())
    };
    simple_response(status, &body)
}

#[test]
fn vault_create_cas_conflict_does_not_destroy_existing_fields() {
    let fixture = VaultMergeFixture::start();
    fixture.force_patch_404("apps/prod/db");
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &environment,
        Some(b"must-not-win\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("concurrently"));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    drop(state);

    let requests = fixture.requests.lock().expect("requests");
    let create = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("CAS create request");
    let body: Value = serde_json::from_slice(&create.body).expect("create body");
    assert_eq!(
        body.pointer("/options/cas").and_then(Value::as_u64),
        Some(0)
    );
    assert!(requests.iter().any(|request| request.method == "PATCH"));
}

#[test]
fn vault_set_patches_existing_secret_and_preserves_sibling_fields() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &environment,
        Some(b"new-value\n"),
    );
    assert!(set.status.success(), "{}", stderr(&set));

    {
        let state = fixture.state.lock().expect("state");
        let data = state.get("apps/prod/db").expect("db state");
        assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
        assert_eq!(data.get("value").and_then(Value::as_str), Some("new-value"));
    }
    let requests = fixture.requests.lock().expect("requests");
    assert!(requests.iter().any(|request| request.method == "PATCH"));
    assert!(
        !requests
            .iter()
            .any(|request| request.method == "POST" && request.path.contains("apps/prod/db"))
    );
    drop(requests);

    let get = run(
        &directory,
        &["get", "apps/prod/db#user"],
        &environment,
        None,
    );
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "alice");

    let create = run(
        &directory,
        &["set", "apps/prod/new"],
        &environment,
        Some(b"created-value\n"),
    );
    assert!(create.status.success(), "{}", stderr(&create));
    let state = fixture.state.lock().expect("state");
    assert_eq!(
        state
            .get("apps/prod/new")
            .and_then(|data| data.get("value"))
            .and_then(Value::as_str),
        Some("created-value")
    );
    drop(state);
    assert!(
        fixture
            .requests
            .lock()
            .expect("requests")
            .iter()
            .any(|request| request.method == "POST" && request.path.contains("apps/prod/new"))
    );
}

#[test]
fn search_only_requests_metadata() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let search = run(&directory, &["search", "db"], &environment, None);
    assert!(search.status.success(), "{}", stderr(&search));
    assert_eq!(stdout(&search), "apps/prod/db\n");
    assert!(
        fixture
            .requests()
            .iter()
            .all(|request| request.path.contains("/metadata")),
        "search fetched a value path"
    );
}

#[test]
fn set_refuses_oversized_stdin_instead_of_truncating() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let input = directory.join("oversized-secret");
    std::fs::write(&input, vec![b'x'; 8 * 1024 * 1024 + 1]).expect("write oversized input");
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let set = run_with_stdin_file(&directory, &["set", "apps/prod/db"], &environment, &input);
    assert!(!set.status.success());
    assert!(stderr(&set).contains("exceeds the 8388608 byte limit"));
    assert!(
        fixture.requests().is_empty(),
        "oversized input must be refused before a provider request"
    );
}

#[test]
fn missing_key_never_echoes_a_value_or_body() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let get = run(
        &directory,
        &["get", "apps/prod/missing"],
        &environment,
        None,
    );
    assert!(!get.status.success());
    assert!(stdout(&get).is_empty());
    assert!(!stderr(&get).contains("s3cr3t"));
    assert!(stderr(&get).contains("no key"));
}

#[test]
fn completion_and_hooks_work_without_a_configuration() {
    let directory = tempfile_dir();
    let completion = run(&directory, &["completion", "bash"], &[], None);
    assert!(completion.status.success(), "{}", stderr(&completion));
    assert!(stdout(&completion).contains("nsvault"));

    let hook = run(&directory, &["hook", "zsh"], &[], None);
    assert!(hook.status.success(), "{}", stderr(&hook));
    assert!(stdout(&hook).contains("NSVAULT_AUTOLOAD"));

    let dir = run(&directory, &["dir"], &[], None);
    assert!(dir.status.success());
    assert!(stdout(&dir).is_empty());
}

#[test]
fn vaultwarden_fixture_reads_a_name_and_field() {
    let directory = tempfile_dir();
    let script = directory.join("bw");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$*" in
  *"list items"*) printf '%s' '[{"id":"123e4567-e89b-12d3-a456-426614174000","name":"DB","login":{"password":"pw"}}]' ;;
  *"get item"*) printf '%s' '{"name":"DB","login":{"password":"pw"},"fields":[{"name":"api","value":"key"}]}' ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nsvault.toml"),
        format!(
            r#"version = 1
provider = "v"
[providers.v]
kind = "vaultwarden"
command = "{}"
session_env = "BW_SESSION"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let environment = [("BW_SESSION", "test-session")];
    let get = run(&directory, &["get", "DB#password"], &environment, None);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "pw");
    let custom = run(&directory, &["get", "DB#api"], &environment, None);
    assert!(custom.status.success(), "{}", stderr(&custom));
    assert_eq!(stdout(&custom), "key");
}

#[test]
fn proton_fixture_reads_a_field() {
    let directory = tempfile_dir();
    let script = directory.join("pass-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$*" in
  "info") exit 0 ;;
  *"item list"*) printf '%s' '{"items":[{"id":"i","title":"DB","share_id":"s"}]}' ;;
  *"item view"*) printf '%s\n' 'pw' ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nsvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let get = run(&directory, &["get", "DB#password"], &[], None);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "pw");
}

#[test]
fn keepass_fixture_uses_the_documented_command_shape() {
    let directory = tempfile_dir();
    let script = directory.join("keepassxc-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$1" in
  ls) printf '%s\n' 'Entry' 'Group/' ;;
  show) printf '%s\n' 'entry-value' ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nsvault.toml"),
        format!(
            r#"version = 1
provider = "k"
[providers.k]
kind = "keepass"
database = "test.kdbx"
command = "{}"
password_env = "KP_PW"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let environment = [("KP_PW", "not-a-real-password")];
    let get = run(&directory, &["get", "Entry"], &environment, None);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "entry-value");
    let list = run(&directory, &["ls"], &environment, None);
    assert!(list.status.success(), "{}", stderr(&list));
    assert_eq!(stdout(&list), "Entry\n");
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).expect("chmod");
    }
}

fn tempfile_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nsvault-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("temp dir");
    path
}
