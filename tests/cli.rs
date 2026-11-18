//! End-to-end CLI tests against local fixtures.
//!
//! No real provider credential or remote service is used. The HTTP fixture is
//! loopback-only, and the CLI fixtures are temporary scripts.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use serde_json::{Map, Value, json};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nvault")
}

fn run(
    directory: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    stdin: Option<&[u8]>,
) -> Output {
    let mut command = Command::new(binary());
    let lock_dir = std::env::temp_dir().join(format!("nvault-locks-{}", std::process::id()));
    std::fs::create_dir_all(&lock_dir).expect("lock dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700))
            .expect("lock dir mode");
    }
    command
        .args(arguments)
        .current_dir(directory)
        .env("NVAULT_LOCK_DIR", &lock_dir)
        .envs(environment.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn nvault");
    if let Some(bytes) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for nvault")
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
        .expect("run nvault with stdin file")
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
    headers: Vec<(String, String)>,
    target: Option<String>,
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let target = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-amz-target"))
        .map(|(_, value)| value.clone());
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut chunk).ok()?;
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
    }
    body.truncate(content_length);
    Some(Request {
        method,
        path,
        headers,
        target,
        body,
    })
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
        directory.join(".nvault.toml"),
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
    assert!(stdout(&exports).contains("NVAULT_LOADED_KEYS='DB'"));
}

#[derive(Default)]
struct VaultMergeHooks {
    race_fields: Mutex<BTreeMap<String, String>>,
    stale_cas: Mutex<BTreeSet<String>>,
    malformed_subkeys: Mutex<BTreeSet<String>>,
    patch_404: Mutex<BTreeSet<String>>,
    lie_absent: Mutex<BTreeSet<String>>,
}

struct VaultMergeFixture {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    state: Arc<Mutex<BTreeMap<String, Map<String, Value>>>>,
    hooks: Arc<VaultMergeHooks>,
    stop: Arc<AtomicBool>,
}

impl VaultMergeFixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(BTreeMap::new()));
        let versions = Arc::new(Mutex::new(BTreeMap::new()));
        let hooks = Arc::new(VaultMergeHooks::default());
        state.lock().expect("state").insert(
            "apps/prod/db".to_owned(),
            serde_json::from_value(json!({"user": "alice", "value": "old"}))
                .expect("initial state"),
        );
        versions
            .lock()
            .expect("versions")
            .insert("apps/prod/db".to_owned(), 1);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_state = Arc::clone(&state);
        let thread_versions = Arc::clone(&versions);
        let thread_hooks = Arc::clone(&hooks);
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
                            let response = vault_merge_response(
                                &request,
                                &thread_state,
                                &thread_versions,
                                &thread_hooks,
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
            state,
            hooks,
            stop,
        }
    }

    fn lie_absent_once(&self, path: &str) {
        self.hooks
            .lie_absent
            .lock()
            .expect("lie absent")
            .insert(path.to_owned());
    }

    fn force_patch_404(&self, path: &str) {
        self.hooks
            .patch_404
            .lock()
            .expect("patch 404 state")
            .insert(path.to_owned());
    }

    /// Makes the next subkeys read report the field as absent and then apply a
    /// concurrent writer's creation. The response was computed first, so the
    /// client sees absence while the fixture's version has already advanced.
    fn race_field_creation(&self, path: &str, field: &str) {
        self.hooks
            .race_fields
            .lock()
            .expect("race fields")
            .insert(path.to_owned(), field.to_owned());
    }

    /// Makes the next conditional patch lose: another writer's update lands
    /// just before it, so the version read by the client is stale.
    fn stale_cas_once(&self, path: &str) {
        self.hooks
            .stale_cas
            .lock()
            .expect("stale cas")
            .insert(path.to_owned());
    }

    /// Returns a 200 subkeys body without the documented `data.subkeys` map.
    fn malformed_subkeys_once(&self, path: &str) {
        self.hooks
            .malformed_subkeys
            .lock()
            .expect("malformed subkeys")
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
    versions: &Arc<Mutex<BTreeMap<String, u64>>>,
    hooks: &VaultMergeHooks,
) -> String {
    let current_version = |path: &str| {
        versions
            .lock()
            .expect("versions")
            .get(path)
            .copied()
            .unwrap_or(1)
    };
    let (status, body) = if let Some(path) = request
        .path
        .strip_prefix("/v1/secret/metadata/")
        .filter(|_| !request.path.contains("list=true"))
    {
        let path = path.split('?').next().unwrap_or(path);
        if hooks.lie_absent.lock().expect("lie absent").remove(path) {
            ("404 Not Found", String::new())
        } else if state.lock().expect("state").contains_key(path) {
            let version = current_version(path);
            (
                "200 OK",
                json!({"data": {"current_version": version}}).to_string(),
            )
        } else {
            ("404 Not Found", String::new())
        }
    } else if let Some(path) = request.path.strip_prefix("/v1/secret/subkeys/") {
        let path = path.split('?').next().unwrap_or(path);
        if hooks
            .malformed_subkeys
            .lock()
            .expect("malformed subkeys")
            .remove(path)
        {
            return simple_response("200 OK", r#"{"data":{}}"#);
        }
        // Compute the response before the simulated concurrent write, so the
        // client is told the field is absent while the version already moved.
        let response = {
            let state = state.lock().expect("state");
            match state.get(path) {
                Some(data) => {
                    let mut subkeys = serde_json::Map::new();
                    for key in data.keys() {
                        subkeys.insert(key.clone(), Value::Null);
                    }
                    ("200 OK", json!({"data": {"subkeys": subkeys}}).to_string())
                }
                None => ("404 Not Found", String::new()),
            }
        };
        if let Some(field) = hooks.race_fields.lock().expect("race fields").remove(path) {
            {
                let mut state = state.lock().expect("state");
                if let Some(data) = state.get_mut(path) {
                    data.insert(field, json!("concurrent-writer"));
                }
            }
            *versions
                .lock()
                .expect("versions")
                .entry(path.to_owned())
                .or_insert(1) += 1;
        }
        response
    } else if let Some(path) = request.path.strip_prefix("/v1/secret/data/") {
        let path = path.split('?').next().unwrap_or(path);
        match request.method.as_str() {
            "GET" => {
                let state = state.lock().expect("state");
                match state.get(path) {
                    Some(data) => ("200 OK", json!({"data": {"data": data}}).to_string()),
                    None => ("404 Not Found", String::new()),
                }
            }
            "PATCH" => {
                if hooks
                    .patch_404
                    .lock()
                    .expect("patch 404 state")
                    .remove(path)
                {
                    ("404 Not Found", String::new())
                } else {
                    if hooks.stale_cas.lock().expect("stale cas").remove(path) {
                        // Another writer's update lands after the client read
                        // the version and before this patch is evaluated.
                        {
                            let mut state = state.lock().expect("state");
                            if let Some(data) = state.get_mut(path) {
                                data.insert("stale-writer".to_owned(), json!("won"));
                            }
                        }
                        *versions
                            .lock()
                            .expect("versions")
                            .entry(path.to_owned())
                            .or_insert(1) += 1;
                    }
                    let parsed: Value =
                        serde_json::from_slice(&request.body).unwrap_or(Value::Null);
                    let cas = parsed.pointer("/options/cas").and_then(Value::as_u64);
                    let version = current_version(path);
                    let merged = {
                        let mut state = state.lock().expect("state");
                        if cas.is_some_and(|cas| cas != version) && state.contains_key(path) {
                            return simple_response("400 Bad Request", "");
                        }
                        match (state.get_mut(path), request_data(&request.body)) {
                            (Some(existing), Some(changes)) => {
                                existing.extend(changes);
                                true
                            }
                            _ => false,
                        }
                    };
                    if merged {
                        // Vault advances current_version for every successful
                        // data write.
                        *versions
                            .lock()
                            .expect("versions")
                            .entry(path.to_owned())
                            .or_insert(1) += 1;
                        ("204 No Content", String::new())
                    } else {
                        ("404 Not Found", String::new())
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
                {
                    let mut state = state.lock().expect("state");
                    if cas == Some(0) && state.contains_key(path) {
                        // Simulate a concurrent creator winning between PATCH
                        // 404 and the CAS 0 create attempt.
                        return simple_response("400 Bad Request", "");
                    }
                    state.insert(path.to_owned(), data);
                }
                versions
                    .lock()
                    .expect("versions")
                    .insert(path.to_owned(), 1);
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
fn ensure_leaves_an_existing_vault_secret_unchanged() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db"],
        &environment,
        Some(b"must-not-land\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"present\"}\n");
    assert!(!stdout(&ensured).contains("must-not-land"));
    assert!(!stderr(&ensured).contains("must-not-land"));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    drop(state);
    let requests = fixture.requests.lock().expect("requests");
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests
            .iter()
            .all(|request| request.path.contains("/metadata/"))
    );
}

#[test]
fn ensure_creates_a_missing_vault_secret_with_cas_0() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/new"],
        &environment,
        Some(b"created-once\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"created\"}\n");

    let state = fixture.state.lock().expect("state");
    assert_eq!(
        state
            .get("apps/prod/new")
            .and_then(|data| data.get("value"))
            .and_then(Value::as_str),
        Some("created-once")
    );
    drop(state);
    let requests = fixture.requests.lock().expect("requests");
    let create = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("CAS create");
    let body: Value = serde_json::from_slice(&create.body).expect("body");
    assert_eq!(
        body.pointer("/options/cas").and_then(Value::as_u64),
        Some(0)
    );
    assert!(!requests.iter().any(|request| request.method == "PATCH"));
}

#[test]
fn ensure_cas_conflict_does_not_overwrite() {
    let fixture = VaultMergeFixture::start();
    fixture.lie_absent_once("apps/prod/db");
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db"],
        &environment,
        Some(b"lost-the-race\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"present\"}\n");
    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db");
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    drop(state);
    let requests = fixture.requests.lock().expect("requests");
    assert!(requests.iter().any(|request| request.method == "POST"));
    assert!(!requests.iter().any(|request| request.method == "PATCH"));
}

#[test]
fn vault_field_ensure_does_not_overwrite_a_concurrently_created_field() {
    let fixture = VaultMergeFixture::start();
    fixture.race_field_creation("apps/prod/db", "token");
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#token"],
        &environment,
        Some(b"must-not-overwrite\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"present\"}\n");
    assert!(!stderr(&ensured).contains("must-not-overwrite"));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert_eq!(
        data.get("token").and_then(Value::as_str),
        Some("concurrent-writer"),
        "the concurrent writer's field was replaced"
    );
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    drop(state);

    let requests = fixture.requests.lock().expect("requests");
    let version_read = requests
        .iter()
        .rposition(|request| {
            request.method == "GET" && request.path.starts_with("/v1/secret/metadata/")
        })
        .expect("metadata read");
    let subkeys = requests
        .iter()
        .position(|request| {
            request.method == "GET" && request.path.starts_with("/v1/secret/subkeys/")
        })
        .expect("subkeys read");
    assert!(
        version_read < subkeys,
        "the CAS version must be read before the field-absence check"
    );
    let patch = requests
        .iter()
        .find(|request| request.method == "PATCH")
        .expect("conditional field patch");
    let body: Value = serde_json::from_slice(&patch.body).expect("patch body");
    assert_eq!(
        body.pointer("/options/cas").and_then(Value::as_u64),
        Some(1),
        "the patch must use the version read before the absence check"
    );
}

#[test]
fn vault_field_ensure_refuses_a_malformed_subkeys_response() {
    let fixture = VaultMergeFixture::start();
    fixture.malformed_subkeys_once("apps/prod/db");
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#token"],
        &environment,
        Some(b"must-not-land\n"),
    );
    assert!(!ensured.status.success());
    assert!(
        stderr(&ensured).contains("no subkeys map"),
        "{}",
        stderr(&ensured)
    );
    assert!(!stderr(&ensured).contains("must-not-land"));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert!(data.get("token").is_none());
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    drop(state);

    let requests = fixture.requests.lock().expect("requests");
    assert!(
        !requests
            .iter()
            .any(|request| request.method == "PATCH" || request.method == "POST"),
        "a malformed subkeys body must not lead to a write"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.path.contains("/subkeys/"))
    );
}

#[test]
fn vault_field_ensure_fails_closed_on_a_stale_cas_version() {
    let fixture = VaultMergeFixture::start();
    fixture.stale_cas_once("apps/prod/db");
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#token"],
        &environment,
        Some(b"must-not-land\n"),
    );
    assert!(!ensured.status.success());
    assert!(
        stderr(&ensured).contains("still absent"),
        "{}",
        stderr(&ensured)
    );
    assert!(!stderr(&ensured).contains("must-not-land"));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert!(
        data.get("token").is_none(),
        "the stale patch must not write"
    );
    assert_eq!(
        data.get("stale-writer").and_then(Value::as_str),
        Some("won"),
        "the concurrent write must survive"
    );
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    drop(state);

    let requests = fixture.requests.lock().expect("requests");
    let patches: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "PATCH")
        .collect();
    assert_eq!(patches.len(), 1, "a lost CAS race is not retried");
    let body: Value = serde_json::from_slice(&patches[0].body).expect("patch body");
    assert_eq!(
        body.pointer("/options/cas").and_then(Value::as_u64),
        Some(1),
        "the patch used the version read before the concurrent write"
    );
    assert!(!requests.iter().any(|request| request.method == "POST"));
}

#[test]
fn vault_field_ensure_reads_the_version_after_a_previous_write() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let first = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#token"],
        &environment,
        Some(b"first-field\n"),
    );
    assert!(first.status.success(), "{}", stderr(&first));
    let second = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#note"],
        &environment,
        Some(b"second-field\n"),
    );
    assert!(second.status.success(), "{}", stderr(&second));

    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db state");
    assert_eq!(
        data.get("token").and_then(Value::as_str),
        Some("first-field")
    );
    assert_eq!(
        data.get("note").and_then(Value::as_str),
        Some("second-field")
    );
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    drop(state);

    let requests = fixture.requests.lock().expect("requests");
    let cas: Vec<u64> = requests
        .iter()
        .filter(|request| request.method == "PATCH")
        .map(|request| {
            let body: Value = serde_json::from_slice(&request.body).expect("patch body");
            body.pointer("/options/cas")
                .and_then(Value::as_u64)
                .expect("cas")
        })
        .collect();
    assert_eq!(
        cas,
        vec![1, 2],
        "the fixture increments the version after every successful patch"
    );
}

#[test]
fn ensure_adds_a_missing_field_without_replacing_siblings() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "--json", "apps/prod/db#token"],
        &environment,
        Some(b"field-once\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"created\"}\n");
    let state = fixture.state.lock().expect("state");
    let data = state.get("apps/prod/db").expect("db");
    assert_eq!(data.get("user").and_then(Value::as_str), Some("alice"));
    assert_eq!(data.get("value").and_then(Value::as_str), Some("old"));
    assert_eq!(
        data.get("token").and_then(Value::as_str),
        Some("field-once")
    );
    drop(state);
    let requests = fixture.requests.lock().expect("requests");
    let patch = requests
        .iter()
        .find(|request| request.method == "PATCH")
        .expect("field patch");
    let body: Value = serde_json::from_slice(&patch.body).expect("body");
    assert_eq!(
        body.pointer("/options/cas").and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        requests
            .iter()
            .any(|request| request.path.contains("/subkeys/"))
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.method == "GET" && request.path.contains("/data/"))
    );
}

#[test]
fn ensure_does_not_replace_an_existing_field() {
    let fixture = VaultMergeFixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let environment = [("TEST_VAULT_TOKEN", "test-token")];

    let ensured = run(
        &directory,
        &["ensure", "apps/prod/db#user"],
        &environment,
        Some(b"not-alice\n"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert!(stdout(&ensured).is_empty());
    let state = fixture.state.lock().expect("state");
    assert_eq!(
        state
            .get("apps/prod/db")
            .and_then(|data| data.get("user"))
            .and_then(Value::as_str),
        Some("alice")
    );
    drop(state);
    let requests = fixture.requests.lock().expect("requests");
    assert!(!requests.iter().any(|request| request.method == "PATCH"));
    assert!(!requests.iter().any(|request| request.method == "POST"));
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
    assert!(stdout(&completion).contains("nvault"));

    let hook = run(&directory, &["hook", "zsh"], &[], None);
    assert!(hook.status.success(), "{}", stderr(&hook));
    assert!(stdout(&hook).contains("NVAULT_AUTOLOAD"));

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
if [ -n "$BW_TRACE" ]; then printf '%s\n' "$*" >> "$BW_TRACE"; fi
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
        directory.join(".nvault.toml"),
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
    let trace = directory.join("calls");
    let trace_path = trace.to_string_lossy().to_string();
    let environment = [
        ("BW_SESSION", "test-session"),
        ("BW_TRACE", trace_path.as_str()),
    ];
    let get = run(&directory, &["get", "DB#password"], &environment, None);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "pw");
    let custom = run(&directory, &["get", "DB#api"], &environment, None);
    assert!(custom.status.success(), "{}", stderr(&custom));
    assert_eq!(stdout(&custom), "key");

    let listing = run(&directory, &["ls"], &environment, None);
    assert!(listing.status.success(), "{}", stderr(&listing));
    assert_eq!(stdout(&listing), "DB\n");
    assert!(!stdout(&listing).contains("pw"));
    assert!(!stderr(&listing).contains("pw"));
    assert!(!stdout(&listing).contains("key"));
    let calls = std::fs::read_to_string(&trace).expect("bw call trace");
    assert!(
        calls.lines().any(|line| line.ends_with("list items")),
        "ls did not fetch items through the CLI: {calls}"
    );

    let ensured = run(
        &directory,
        &["ensure", "DB"],
        &environment,
        Some(b"must-not-run\n"),
    );
    assert!(!ensured.status.success());
    assert!(stderr(&ensured).contains("does not support ensure"));
    assert!(!stderr(&ensured).contains("must-not-run"));
    assert!(!stderr(&ensured).contains("pw"));
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
        directory.join(".nvault.toml"),
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
fn proton_token_mode_isolates_the_session_and_uses_the_token_from_env() {
    let directory = tempfile_dir();
    let trace = directory.join("trace");
    let ambient = directory.join("ambient-session");
    let script = directory.join("pass-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$PROTON_TRACE"
printf 'session=%s\n' "${PROTON_PASS_SESSION_DIR:-}" >> "$PROTON_TRACE"
printf 'key=%s\n' "${PROTON_PASS_KEY_PROVIDER:-}" >> "$PROTON_TRACE"
printf 'token=%s\n' "${PROTON_PASS_PERSONAL_ACCESS_TOKEN:+set}" >> "$PROTON_TRACE"
case "$*" in
  "info --output json")
    if [ -f "${PROTON_PASS_SESSION_DIR:-/nonexistent}/.session/session.json" ]; then
      printf '%s\n' '{"personal_access_token_name":"fixture-pat"}'
      exit 0
    fi
    exit 1
    ;;
  "login")
    [ -n "${PROTON_PASS_PERSONAL_ACCESS_TOKEN:-}" ] || exit 3
    mkdir -p "${PROTON_PASS_SESSION_DIR}/.session" || exit 4
    : > "${PROTON_PASS_SESSION_DIR}/.session/session.json" || exit 4
    exit 0
    ;;
  *"item list"*)
    printf '%s' '{"items":[{"id":"i","title":"DB","share_id":"s","content":{"password":"pw"}}]}'
    ;;
  *"item view"*)
    printf '%s\n' 'pw'
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
token_env = "PROTON_TEST_PAT"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let get = run(
        &directory,
        &["get", "DB#password"],
        &[
            ("PROTON_TEST_PAT", "not-a-real-token"),
            ("PROTON_TRACE", trace.to_str().expect("trace path")),
            (
                "PROTON_PASS_SESSION_DIR",
                ambient.to_str().expect("ambient path"),
            ),
        ],
        None,
    );
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "pw");
    assert!(!stderr(&get).contains("not-a-real-token"));

    let trace = std::fs::read_to_string(&trace).expect("trace");
    assert!(!trace.contains("not-a-real-token"));
    let sessions: Vec<&str> = trace
        .lines()
        .filter_map(|line| line.strip_prefix("session="))
        .collect();
    assert!(!sessions.is_empty(), "no session directory recorded");
    let session = sessions[0];
    assert!(!session.is_empty());
    assert!(sessions.iter().all(|recorded| *recorded == session));
    assert_ne!(session, ambient.to_str().expect("ambient path"));
    assert!(session.contains("nvault-proton-"));
    assert!(
        !Path::new(session).exists(),
        "isolated session directory was not removed"
    );
    assert!(
        trace
            .lines()
            .filter_map(|line| line.strip_prefix("key="))
            .all(|key| key == "fs")
    );
    assert!(trace.lines().any(|line| line == "token=set"));
    assert_eq!(trace.lines().filter(|line| *line == "login").count(), 1);
    assert!(trace.contains("info --output json"));
    assert!(trace.contains("item list"));
    assert!(trace.contains("item view"));
}

#[test]
fn proton_token_mode_rejects_a_session_that_is_not_a_pat() {
    let directory = tempfile_dir();
    let trace = directory.join("trace");
    let script = directory.join("pass-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$*" in
  "info --output json") printf '%s\n' '{"id":"user","username":"fixture"}' ;;
  "login")
    mkdir -p "${PROTON_PASS_SESSION_DIR}/.session" || exit 4
    : > "${PROTON_PASS_SESSION_DIR}/.session/session.json" || exit 4
    exit 0
    ;;
  *) printf 'item\n' >> "$PROTON_TRACE"; printf 'leaked\n' ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
token_env = "PROTON_TEST_PAT"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let get = run(
        &directory,
        &["get", "DB#password"],
        &[
            ("PROTON_TEST_PAT", "not-a-real-token"),
            ("PROTON_TRACE", trace.to_str().expect("trace path")),
        ],
        None,
    );
    assert!(!get.status.success());
    assert!(stdout(&get).is_empty());
    assert!(stderr(&get).contains("pass-cli"));
    let trace = std::fs::read_to_string(&trace).unwrap_or_default();
    assert!(
        !trace.lines().any(|line| line == "item"),
        "an item command ran for a non-PAT session"
    );
}

#[test]
fn proton_token_mode_refuses_a_session_outside_the_isolated_directory() {
    let directory = tempfile_dir();
    let trace = directory.join("trace");
    let script = directory.join("pass-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$*" in
  "info --output json") printf '%s\n' '{"personal_access_token_name":"other-pat"}' ;;
  "login") exit 0 ;;
  *) printf 'item\n' >> "$PROTON_TRACE"; printf 'leaked\n' ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
token_env = "PROTON_TEST_PAT"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let get = run(
        &directory,
        &["get", "DB#password"],
        &[
            ("PROTON_TEST_PAT", "not-a-real-token"),
            ("PROTON_TRACE", trace.to_str().expect("trace path")),
        ],
        None,
    );
    assert!(!get.status.success());
    assert!(stdout(&get).is_empty());
    assert!(stderr(&get).contains("did not create"));
    let trace = std::fs::read_to_string(&trace).unwrap_or_default();
    assert!(
        !trace.lines().any(|line| line == "item"),
        "an item command ran against a session outside the isolated directory"
    );
}

#[test]
fn proton_session_mode_keeps_the_configured_session_directory() {
    let directory = tempfile_dir();
    let trace = directory.join("trace");
    let ambient = directory.join("ambient-session");
    let script = directory.join("pass-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$PROTON_TRACE"
printf 'session=%s\n' "${PROTON_PASS_SESSION_DIR:-}" >> "$PROTON_TRACE"
printf 'key=%s\n' "${PROTON_PASS_KEY_PROVIDER:-}" >> "$PROTON_TRACE"
case "$*" in
  *"item list"*)
    printf '%s' '{"items":[{"id":"i","title":"DB","share_id":"s","content":{"password":"hidden-value"}}]}'
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
token_env = "PROTON_TEST_UNSET_PAT"
"#,
            script.display()
        ),
    )
    .expect("write config");
    let listing = run(
        &directory,
        &["ls"],
        &[
            ("PROTON_TRACE", trace.to_str().expect("trace path")),
            (
                "PROTON_PASS_SESSION_DIR",
                ambient.to_str().expect("ambient path"),
            ),
        ],
        None,
    );
    assert!(listing.status.success(), "{}", stderr(&listing));
    assert_eq!(stdout(&listing), "DB\n");
    assert!(!stdout(&listing).contains("hidden-value"));
    let trace = std::fs::read_to_string(&trace).expect("trace");
    let sessions: Vec<&str> = trace
        .lines()
        .filter_map(|line| line.strip_prefix("session="))
        .collect();
    assert!(!sessions.is_empty(), "no session directory recorded");
    assert!(
        sessions
            .iter()
            .all(|session| *session == ambient.to_str().expect("ambient path"))
    );
    assert!(
        trace
            .lines()
            .filter_map(|line| line.strip_prefix("key="))
            .all(str::is_empty)
    );
    assert!(!trace.contains("info --output json"));
}

#[test]
fn proton_create_uses_stdin_template_and_refuses_existing_items() {
    let directory = tempfile_dir();
    let script = directory.join("pass-cli");
    let trace = directory.join("trace");
    let input = directory.join("input");
    let listing = directory.join("listing");
    std::fs::write(
        &script,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$TRACE"
case "$*" in
  "item list --output json --vault-name Work") cat "$LISTING" ;;
  "item create login --from-template - --vault-name Work") cat > "$INPUT" ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(&listing, r#"{"items":[]}"#).expect("listing");
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "p"
[providers.p]
kind = "proton"
command = "{}"
vault = "Work"
token_env = "PROTON_TEST_UNSET_PAT"
"#,
            script.display()
        ),
    )
    .expect("config");
    let env = [
        ("TRACE", trace.to_str().expect("trace")),
        ("INPUT", input.to_str().expect("input")),
        ("LISTING", listing.to_str().expect("listing")),
    ];
    let result = run(
        &directory,
        &["set", "DB#username"],
        &env,
        Some(b"fake-value\n"),
    );
    assert!(result.status.success(), "{}", stderr(&result));
    let args = std::fs::read_to_string(&trace).expect("trace");
    assert!(args.contains("item create login --from-template - --vault-name Work"));
    assert!(!args.contains("fake-value"));
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&input).expect("input")).expect("json");
    assert_eq!(
        json,
        serde_json::json!({"title":"DB", "username":"fake-value"})
    );
    std::fs::write(&listing, r#"{"items":[{"title":"DB","share_id":"x"}]}"#).expect("listing");
    std::fs::write(&trace, "").expect("clear trace");
    let result = run(&directory, &["set", "DB"], &env, Some(b"fake-value\n"));
    assert!(!result.status.success());
    assert!(stderr(&result).contains("already exists"));
    assert!(
        !std::fs::read_to_string(&trace)
            .expect("trace")
            .contains("create")
    );
    std::fs::write(&listing, "{}").expect("malformed listing");
    let result = run(&directory, &["set", "DB"], &env, Some(b"fake-value\n"));
    assert!(!result.status.success());
    assert!(
        !std::fs::read_to_string(&trace)
            .expect("trace")
            .contains("create")
    );
    let result = run(&directory, &["ensure", "DB"], &env, Some(b"fake-value\n"));
    assert!(!result.status.success());
    assert!(stderr(&result).contains("does not support ensure"));
    assert!(!stderr(&result).contains("fake-value"));
}

#[test]
fn keepass_fixture_writes_the_password_on_stdin_and_never_in_argv() {
    let directory = tempfile_dir();
    let script = keepass_write_fixture(&directory);
    let environment = [("KP_PW", "not-a-real-password")];

    let providers = run(&directory, &["providers"], &environment, None);
    assert!(providers.status.success(), "{}", stderr(&providers));
    assert!(
        stdout(&providers).contains("write=true\tensure=false"),
        "{}",
        stdout(&providers)
    );

    let updated = run(
        &directory,
        &["set", "Entry"],
        &environment,
        Some(b"replacement-value\n"),
    );
    assert!(updated.status.success(), "{}", stderr(&updated));
    assert!(
        stderr(&updated).contains("stored Entry"),
        "{}",
        stderr(&updated)
    );
    assert!(!stderr(&updated).contains("replacement-value"));
    assert!(!stderr(&updated).contains("not-a-real-password"));

    let argv = read_fixture_log(&directory.join("write-argv.log"));
    assert!(argv.contains("edit"), "{argv}");
    assert!(!argv.contains("replacement-value"), "{argv}");
    assert!(!argv.contains("not-a-real-password"), "{argv}");
    let input = read_fixture_log(&directory.join("write-stdin.log"));
    assert_eq!(
        input, "---\nnot-a-real-password\nreplacement-value\n",
        "{input}"
    );

    let created = run(
        &directory,
        &["set", "Group/New"],
        &environment,
        Some(b"created-value\n"),
    );
    assert!(created.status.success(), "{}", stderr(&created));
    let argv = read_fixture_log(&directory.join("write-argv.log"));
    assert!(argv.contains("add"), "{argv}");
    assert!(!argv.contains("created-value"), "{argv}");

    let refused_ensure = run(&directory, &["ensure", "Entry"], &environment, None);
    assert!(!refused_ensure.status.success());
    assert!(
        stderr(&refused_ensure).contains("does not support ensure"),
        "{}",
        stderr(&refused_ensure)
    );
    let after_ensure = read_fixture_log(&directory.join("write-argv.log"));
    assert_eq!(after_ensure.matches("add").count(), 1, "{after_ensure}");
    assert_eq!(after_ensure.matches("edit").count(), 1, "{after_ensure}");

    let refused = run(
        &directory,
        &["set", "Entry#UserName"],
        &environment,
        Some(b"must-not-be-written\n"),
    );
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("only the Password field"),
        "{}",
        stderr(&refused)
    );
    assert!(!stderr(&refused).contains("must-not-be-written"));
    let after_refusal = read_fixture_log(&directory.join("write-argv.log"));
    assert_eq!(after_refusal.matches("add").count(), 1, "{after_refusal}");
    assert_eq!(after_refusal.matches("edit").count(), 1, "{after_refusal}");
    assert!(!script.as_os_str().is_empty());
}

fn keepass_write_fixture(directory: &Path) -> std::path::PathBuf {
    let script = directory.join("keepassxc-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
root=$(dirname "$0")
case "$1" in
  ls) printf '%s\n' 'Entry' 'Group/' 'Group/Other' ;;
  show) printf '%s\n' 'old-value' ;;
  add|edit)
    printf '%s\n' '---' >> "$root/write-argv.log"
    printf '%s\n' "$*" >> "$root/write-argv.log"
    printf '%s\n' '---' >> "$root/write-stdin.log"
    cat >> "$root/write-stdin.log"
    ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(directory.join("test.kdbx"), b"not-a-real-database").expect("database fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory.join("test.kdbx"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("database mode");
    }
    std::fs::write(
        directory.join(".nvault.toml"),
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
    script
}

fn read_fixture_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
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
        directory.join(".nvault.toml"),
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

#[test]
fn keepass_fixture_serializes_concurrent_writers() {
    let directory = tempfile_dir();
    let script = keepass_overlap_script(&directory);
    std::fs::write(directory.join("test.kdbx"), b"not-a-real-database").expect("database fixture");
    keepass_config(&directory, ".nvault.toml", "test.kdbx", &script);
    let lock_dir = keepass_lock_dir();

    let first = spawn_keepass_set(&directory, None, &lock_dir, b"one-value\n");
    let second = spawn_keepass_set(&directory, None, &lock_dir, b"two-value\n");
    assert_keepass_writers_serialized(&directory, first, second);
}

#[test]
fn keepass_fixture_serializes_writers_through_distinct_hardlink_paths() {
    let directory = tempfile_dir();
    let script = keepass_overlap_script(&directory);
    std::fs::write(directory.join("one.kdbx"), b"not-a-real-database").expect("database fixture");
    std::fs::hard_link(directory.join("one.kdbx"), directory.join("two.kdbx")).expect("hard link");
    keepass_config(&directory, "one.toml", "one.kdbx", &script);
    keepass_config(&directory, "two.toml", "two.kdbx", &script);
    let lock_dir = keepass_lock_dir();
    let one = directory.join("one.toml");
    let two = directory.join("two.toml");

    let first = spawn_keepass_set(&directory, Some(&one), &lock_dir, b"one-value\n");
    let second = spawn_keepass_set(&directory, Some(&two), &lock_dir, b"two-value\n");
    assert_keepass_writers_serialized(&directory, first, second);
}

fn keepass_overlap_script(directory: &Path) -> std::path::PathBuf {
    let script = directory.join("keepassxc-cli");
    std::fs::write(
        &script,
        r#"#!/bin/sh
root=$(dirname "$0")
if ! mkdir "$root/active" 2>/dev/null; then
  printf 'overlap\n' >> "$root/overlap.log"
fi
trap 'rmdir "$root/active" 2>/dev/null' EXIT
sleep 0.3
case "$1" in
  ls) printf '%s\n' 'Entry' ;;
  add|edit) cat >/dev/null ;;
  *) exit 2 ;;
esac
"#,
    )
    .expect("write fixture");
    make_executable(&script);
    script
}

fn keepass_config(directory: &Path, file: &str, database: &str, script: &Path) {
    std::fs::write(
        directory.join(file),
        format!(
            r#"version = 1
provider = "k"
[providers.k]
kind = "keepass"
database = "{database}"
command = "{}"
password_env = "KP_PW"
"#,
            script.display()
        ),
    )
    .expect("write config");
}

fn keepass_lock_dir() -> std::path::PathBuf {
    let lock_dir = std::env::temp_dir().join(format!("nvault-locks-{}", std::process::id()));
    std::fs::create_dir_all(&lock_dir).expect("lock dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700))
            .expect("lock dir mode");
    }
    lock_dir
}

fn spawn_keepass_set(
    directory: &Path,
    config: Option<&Path>,
    lock_dir: &Path,
    value: &[u8],
) -> std::process::Child {
    let mut command = Command::new(binary());
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    command
        .args(["set", "Entry"])
        .current_dir(directory)
        .env("NVAULT_LOCK_DIR", lock_dir)
        .env("KP_PW", "not-a-real-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn nvault");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(value)
        .expect("write stdin");
    drop(child.stdin.take());
    child
}

fn assert_keepass_writers_serialized(
    directory: &Path,
    first: std::process::Child,
    second: std::process::Child,
) {
    let first = first.wait_with_output().expect("first writer");
    let second = second.wait_with_output().expect("second writer");
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(
        !directory.join("overlap.log").exists(),
        "two writers entered keepassxc-cli at the same time"
    );
}

fn infisical_config(directory: &Path, port: u16) {
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "i"
[providers.i]
kind = "infisical"
address = "http://127.0.0.1:{port}"
project_id = "test-project"
environment = "dev"
path = "/"
token_env = "TEST_INFISICAL_TOKEN"
allow_http_loopback = true
"#
        ),
    )
    .expect("write infisical config");
}

#[test]
fn infisical_ensure_uses_create_and_reports_a_duplicate_as_present() {
    let fixture = InfisicalFixture::start();
    let directory = tempfile_dir();
    infisical_config(&directory, fixture.port);
    let environment = [("TEST_INFISICAL_TOKEN", "test-token")];

    let providers = run(&directory, &["providers"], &environment, None);
    assert!(providers.status.success(), "{}", stderr(&providers));
    assert!(
        stdout(&providers).contains("ensure=true"),
        "{}",
        stdout(&providers)
    );

    let present = run(
        &directory,
        &["ensure", "--json", "APP_DB"],
        &environment,
        Some(b"must-not-replace\n"),
    );
    assert!(present.status.success(), "{}", stderr(&present));
    assert_eq!(stdout(&present), "{\"status\":\"present\"}\n");
    assert!(!stdout(&present).contains("must-not-replace"));
    assert!(!stderr(&present).contains("must-not-replace"));

    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "POST"
                && request.path.starts_with("/api/v4/secrets/APP_DB?"))
            .count(),
        1,
        "ensure must send one Create request"
    );
    assert!(
        !requests.iter().any(|request| {
            request.method == "GET" || request.method == "PATCH" || request.method == "PUT"
        }),
        "ensure must not read or update before/after the atomic create"
    );

    let ambiguous = run(
        &directory,
        &["ensure", "--json", "AMBIGUOUS"],
        &environment,
        Some(b"must-not-land\n"),
    );
    assert!(!ambiguous.status.success());
    assert!(
        stderr(&ambiguous).contains("HTTP 500"),
        "{}",
        stderr(&ambiguous)
    );
    assert!(!stdout(&ambiguous).contains("present"));
    assert!(!stdout(&ambiguous).contains("must-not-land"));
    assert!(!stderr(&ambiguous).contains("must-not-land"));
    let requests = fixture.requests();
    assert!(
        requests.iter().any(|request| {
            request.method == "POST" && request.path.starts_with("/api/v4/secrets/AMBIGUOUS?")
        }),
        "an ambiguous create result must be surfaced as an error"
    );

    let approval = run(
        &directory,
        &["ensure", "--json", "APPROVAL"],
        &environment,
        Some(b"must-not-land\n"),
    );
    assert!(!approval.status.success());
    assert!(
        stderr(&approval).contains("did not confirm creating"),
        "{}",
        stderr(&approval)
    );
    assert!(!stdout(&approval).contains("created"));
    assert!(!stdout(&approval).contains("must-not-land"));

    for key in ["MALFORMED", "EMPTY", "MISMATCH"] {
        let rejected = run(
            &directory,
            &["ensure", "--json", key],
            &environment,
            Some(b"must-not-land\n"),
        );
        assert!(!rejected.status.success(), "{key} must fail");
        assert!(!stdout(&rejected).contains("created"), "{key}");
        assert!(!stdout(&rejected).contains("present"), "{key}");
        assert!(!stdout(&rejected).contains("must-not-land"), "{key}");
        assert!(!stderr(&rejected).contains("must-not-land"), "{key}");
        assert!(
            !stderr(&rejected).contains("OTHER"),
            "{key} leaked a response field"
        );
        assert!(!stderr(&rejected).is_empty(), "{key} must report an error");
    }
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

#[test]
fn two_profiles_do_not_overlap_writes_to_the_same_vault() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("port").port();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_in_flight = Arc::clone(&in_flight);
    let thread_max = Arc::clone(&max_in_flight);
    let thread_release = Arc::clone(&release);
    let thread_stop = Arc::clone(&stop);
    thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let in_flight = Arc::clone(&thread_in_flight);
                    let max_in_flight = Arc::clone(&thread_max);
                    let release = Arc::clone(&thread_release);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let Some(request) = read_request(&mut stream) else {
                            return;
                        };
                        if request.method == "PATCH" || request.method == "POST" {
                            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            max_in_flight.fetch_max(now, Ordering::SeqCst);
                            while !release.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(20));
                            }
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                        }
                        let body = "";
                        let response = simple_response("204 No Content", body);
                        let _ = stream.write_all(response.as_bytes());
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let lock_dir = tempfile_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
    let lock_dir = lock_dir.to_string_lossy().to_string();
    let alpha = tempfile_dir();
    let beta = tempfile_dir();
    vault_config(&alpha, port);
    std::fs::write(
        beta.join(".nvault.toml"),
        std::fs::read_to_string(alpha.join(".nvault.toml"))
            .expect("read config")
            .replace("provider = \"v\"", "provider = \"other\"")
            .replace("[providers.v]", "[providers.other]"),
    )
    .expect("second config");

    let alpha_dir = alpha.clone();
    let beta_dir = beta.clone();
    let lock_for_first = lock_dir.clone();
    let lock_for_second = lock_dir.clone();
    let first = thread::spawn(move || {
        run(
            &alpha_dir,
            &["set", "apps/prod/db"],
            &[
                ("TEST_VAULT_TOKEN", "test-token"),
                ("NVAULT_LOCK_DIR", lock_for_first.as_str()),
            ],
            Some(b"from-alpha\n"),
        )
    });
    let started = std::time::Instant::now();
    while in_flight.load(Ordering::SeqCst) == 0 {
        if started.elapsed() > Duration::from_secs(10) {
            release.store(true, Ordering::SeqCst);
            stop.store(true, Ordering::SeqCst);
            panic!("first write never reached the fixture");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let second = thread::spawn(move || {
        run(
            &beta_dir,
            &["set", "apps/prod/db"],
            &[
                ("TEST_VAULT_TOKEN", "test-token"),
                ("NVAULT_LOCK_DIR", lock_for_second.as_str()),
            ],
            Some(b"from-beta\n"),
        )
    });
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        in_flight.load(Ordering::SeqCst),
        1,
        "second nvault process reached the provider while the first write was held"
    );
    release.store(true, Ordering::SeqCst);
    let first = first.join().expect("first thread");
    let second = second.join().expect("second thread");
    stop.store(true, Ordering::SeqCst);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(!stderr(&first).contains("test-token"));
    assert!(!stderr(&second).contains("test-token"));
    assert!(!stderr(&first).contains("from-alpha"));
    assert!(!stderr(&second).contains("from-beta"));
    assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
}

fn aws_config(
    directory: &Path,
    port: u16,
    endpoint_suffix: &str,
    provider_name: &str,
    access_key: &str,
    secret_key: &str,
) {
    for (name, value) in [("access-key", access_key), ("secret-key", secret_key)] {
        let path = directory.join(name);
        std::fs::write(&path, value).expect("write AWS credential fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("AWS credential fixture mode");
        }
    }
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "{provider_name}"
[providers.{provider_name}]
kind = "aws-secrets-manager"
region = "us-east-1"
endpoint = "http://127.0.0.1:{port}{endpoint_suffix}"
access_key_file = "access-key"
secret_key_file = "secret-key"
allow_http_loopback = true
"#
        ),
    )
    .expect("write AWS config");
}

fn gcp_config(directory: &Path, port: u16, project: &str, provider_name: &str) {
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "{provider_name}"
[providers.{provider_name}]
kind = "gcp-secret-manager"
project = "{project}"
endpoint = "http://127.0.0.1:{port}"
allow_anonymous = true
allow_http_loopback = true
"#
        ),
    )
    .expect("write GCP config");
}

#[test]
fn two_cloud_profiles_share_one_write_lock_across_processes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("port").port();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_in_flight = Arc::clone(&in_flight);
    let thread_max = Arc::clone(&max_in_flight);
    let thread_release = Arc::clone(&release);
    let thread_stop = Arc::clone(&stop);
    thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let in_flight = Arc::clone(&thread_in_flight);
                    let max_in_flight = Arc::clone(&thread_max);
                    let release = Arc::clone(&thread_release);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let Some(request) = read_request(&mut stream) else {
                            return;
                        };
                        if request.target.as_deref() == Some("secretsmanager.PutSecretValue") {
                            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            max_in_flight.fetch_max(now, Ordering::SeqCst);
                            while !release.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(20));
                            }
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                        }
                        let response = simple_response("200 OK", "{}");
                        let _ = stream.write_all(response.as_bytes());
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let lock_dir = private_dir();
    let lock_dir = lock_dir.to_string_lossy().to_string();
    let alpha = tempfile_dir();
    let beta = tempfile_dir();
    // Same region and endpoint; one spelling has a trailing slash and the
    // second profile uses a different name and different fake credentials.
    aws_config(&alpha, port, "", "aws", "alpha-key", "alpha-secret");
    aws_config(&beta, port, "/", "other", "beta-key", "beta-secret");

    let alpha_dir = alpha.clone();
    let beta_dir = beta.clone();
    let lock_for_first = lock_dir.clone();
    let lock_for_second = lock_dir.clone();
    let first = thread::spawn(move || {
        run(
            &alpha_dir,
            &["set", "nvault-lock-aws"],
            &[("NVAULT_LOCK_DIR", lock_for_first.as_str())],
            Some(b"from-alpha\n"),
        )
    });
    let started = std::time::Instant::now();
    while in_flight.load(Ordering::SeqCst) == 0 {
        if started.elapsed() > Duration::from_secs(10) {
            release.store(true, Ordering::SeqCst);
            stop.store(true, Ordering::SeqCst);
            panic!("first AWS write never reached the fixture");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let second = thread::spawn(move || {
        run(
            &beta_dir,
            &["set", "nvault-lock-aws"],
            &[("NVAULT_LOCK_DIR", lock_for_second.as_str())],
            Some(b"from-beta\n"),
        )
    });
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        in_flight.load(Ordering::SeqCst),
        1,
        "second AWS profile reached the emulator while the first write was held"
    );
    release.store(true, Ordering::SeqCst);
    let first = first.join().expect("first thread");
    let second = second.join().expect("second thread");
    stop.store(true, Ordering::SeqCst);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(!stderr(&first).contains("alpha-secret"));
    assert!(!stderr(&second).contains("beta-secret"));
    assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
}

#[test]
fn gcp_project_id_and_number_share_one_write_lock_across_processes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("port").port();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_in_flight = Arc::clone(&in_flight);
    let thread_max = Arc::clone(&max_in_flight);
    let thread_release = Arc::clone(&release);
    let thread_stop = Arc::clone(&stop);
    thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let in_flight = Arc::clone(&thread_in_flight);
                    let max_in_flight = Arc::clone(&thread_max);
                    let release = Arc::clone(&thread_release);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let Some(request) = read_request(&mut stream) else {
                            return;
                        };
                        if request.method == "POST" && request.path.ends_with(":addVersion") {
                            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            max_in_flight.fetch_max(now, Ordering::SeqCst);
                            while !release.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(20));
                            }
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                        }
                        let response = simple_response("200 OK", "{}");
                        let _ = stream.write_all(response.as_bytes());
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let lock_dir = private_dir();
    let lock_dir = lock_dir.to_string_lossy().to_string();
    let alpha = tempfile_dir();
    let beta = tempfile_dir();
    // One profile names the project by id, the other by number. Both resolve
    // to one vault, and the lock must not use the project string.
    gcp_config(&alpha, port, "floci-local", "gcp-id");
    gcp_config(&beta, port, "123456789012", "gcp-number");

    let alpha_dir = alpha.clone();
    let beta_dir = beta.clone();
    let lock_for_first = lock_dir.clone();
    let lock_for_second = lock_dir.clone();
    let first = thread::spawn(move || {
        run(
            &alpha_dir,
            &["set", "nvault-lock-gcp"],
            &[("NVAULT_LOCK_DIR", lock_for_first.as_str())],
            Some(b"from-alpha\n"),
        )
    });
    let started = std::time::Instant::now();
    while in_flight.load(Ordering::SeqCst) == 0 {
        if started.elapsed() > Duration::from_secs(10) {
            release.store(true, Ordering::SeqCst);
            stop.store(true, Ordering::SeqCst);
            panic!("first GCP write never reached the fixture");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let second = thread::spawn(move || {
        run(
            &beta_dir,
            &["set", "nvault-lock-gcp"],
            &[("NVAULT_LOCK_DIR", lock_for_second.as_str())],
            Some(b"from-beta\n"),
        )
    });
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        in_flight.load(Ordering::SeqCst),
        1,
        "GCP project number reached the emulator while the project id write was held"
    );
    release.store(true, Ordering::SeqCst);
    let first = first.join().expect("first thread");
    let second = second.join().expect("second thread");
    stop.store(true, Ordering::SeqCst);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
}

#[test]
fn cloud_writes_fail_closed_when_the_lock_directory_is_not_private() {
    let fixture = Fixture::start();
    let lock_dir = tempfile_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755))
            .expect("caller directory mode");
    }
    let lock_dir = lock_dir.to_str().expect("lock directory").to_owned();

    let aws = tempfile_dir();
    aws_config(&aws, fixture.port, "", "aws", "test", "test");
    let gcp = tempfile_dir();
    std::fs::write(
        gcp.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "gcp"
[providers.gcp]
kind = "gcp-secret-manager"
project = "floci-local"
endpoint = "http://127.0.0.1:{}/"
allow_anonymous = true
allow_http_loopback = true
"#,
            fixture.port
        ),
    )
    .expect("write GCP config");
    let azure = tempfile_dir();
    std::fs::write(azure.join("token"), "floci-fake-token").expect("write Azure token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(azure.join("token"), std::fs::Permissions::from_mode(0o600))
            .expect("Azure token mode");
    }
    std::fs::write(
        azure.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "azure"
[providers.azure]
kind = "azure-key-vault"
vault_url = "http://127.0.0.1:{}/devstoreaccount1-keyvault"
token_file = "token"
allow_http_loopback = true
"#,
            fixture.port
        ),
    )
    .expect("write Azure config");

    for (directory, command) in [
        (&aws, "set"),
        (&aws, "ensure"),
        (&gcp, "set"),
        (&azure, "set"),
    ] {
        let output = run(
            directory,
            &[command, "nvault-lock-refused"],
            &[("NVAULT_LOCK_DIR", lock_dir.as_str())],
            Some(b"must-not-land\n"),
        );
        assert!(!output.status.success(), "{command} must fail closed");
        assert!(
            stderr(&output).contains("not private"),
            "{}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("must-not-land"));
    }
    assert!(
        fixture.requests().is_empty(),
        "a cloud write must not contact the provider without the lock"
    );
}

#[test]
fn write_lock_rejects_a_relative_directory() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &[
            ("TEST_VAULT_TOKEN", "test-token"),
            ("NVAULT_LOCK_DIR", "nvault-relative-locks"),
        ],
        Some(b"must-not-land\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("absolute"), "{}", stderr(&set));
    assert!(!stderr(&set).contains("must-not-land"));
    assert!(fixture.requests().is_empty());
    assert!(
        !directory.join("nvault-relative-locks").exists(),
        "a relative lock path must not be created in the working directory"
    );
}

fn private_dir() -> std::path::PathBuf {
    let path = tempfile_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    path
}

#[test]
fn write_lock_refuses_a_non_private_directory_without_changing_it() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let lock_dir = tempfile_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755))
            .expect("caller directory mode");
    }
    let lock_dir = lock_dir.to_str().expect("lock directory").to_owned();
    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &[
            ("TEST_VAULT_TOKEN", "test-token"),
            ("NVAULT_LOCK_DIR", lock_dir.as_str()),
        ],
        Some(b"must-not-land\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("not private"), "{}", stderr(&set));
    assert!(!stderr(&set).contains("must-not-land"));
    assert!(
        fixture.requests().is_empty(),
        "the provider must not be contacted before the lock is held"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&lock_dir)
            .expect("lock directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "an existing caller-supplied lock directory must not be chmodded"
        );
    }
}

#[cfg(unix)]
#[test]
fn write_lock_rejects_a_symlinked_directory() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let target = private_dir();
    let link = tempfile_dir().join("locks");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let link = link.to_str().expect("lock link").to_owned();
    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &[
            ("TEST_VAULT_TOKEN", "test-token"),
            ("NVAULT_LOCK_DIR", link.as_str()),
        ],
        Some(b"must-not-land\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("symbolic link"), "{}", stderr(&set));
    assert!(!stderr(&set).contains("must-not-land"));
    assert!(fixture.requests().is_empty());
    let mode = std::fs::metadata(&target)
        .expect("target metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o700,
        "the symlink target must not be used or changed"
    );
    assert!(
        std::fs::read_dir(&target)
            .expect("target entries")
            .next()
            .is_none(),
        "no lock file may be written through the symlink"
    );
}

#[cfg(unix)]
#[test]
fn write_lock_rejects_a_symlinked_parent() {
    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let real = private_dir();
    let link = tempfile_dir().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let lock_dir = link.join("locks");
    let lock_dir = lock_dir.to_str().expect("lock directory").to_owned();
    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &[
            ("TEST_VAULT_TOKEN", "test-token"),
            ("NVAULT_LOCK_DIR", lock_dir.as_str()),
        ],
        Some(b"must-not-land\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("symbolic link"), "{}", stderr(&set));
    assert!(!stderr(&set).contains("must-not-land"));
    assert!(fixture.requests().is_empty());
    assert!(
        !real.join("locks").exists(),
        "nothing may be created through a symlinked ancestor"
    );
}

#[cfg(unix)]
#[test]
fn write_lock_creates_a_missing_private_directory() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::start();
    let directory = tempfile_dir();
    vault_config(&directory, fixture.port);
    let lock_dir = private_dir().join("locks");
    let lock_dir = lock_dir.to_str().expect("lock directory").to_owned();
    let set = run(
        &directory,
        &["set", "apps/prod/db"],
        &[
            ("TEST_VAULT_TOKEN", "test-token"),
            ("NVAULT_LOCK_DIR", lock_dir.as_str()),
        ],
        Some(b"new-value\n"),
    );
    assert!(set.status.success(), "{}", stderr(&set));
    let mode = std::fs::metadata(&lock_dir)
        .expect("lock directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "a missing lock directory is created 0700");
    let entries: Vec<_> = std::fs::read_dir(&lock_dir)
        .expect("lock directory entries")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "one lock file for one identity");
    assert!(
        entries[0]
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .starts_with("write-")
    );
    let file_mode = std::fs::metadata(&entries[0])
        .expect("lock file metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "lock files are created 0600");
    assert!(!stderr(&set).contains("new-value"));
}

struct InfisicalFixture {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
}

impl InfisicalFixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind infisical fixture");
        listener
            .set_nonblocking(true)
            .expect("nonblocking infisical fixture");
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
                        if let Some(request) = read_request(&mut stream) {
                            let response = infisical_response(&request);
                            thread_requests.lock().expect("requests").push(request);
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

impl Drop for InfisicalFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn infisical_created_response(key: &str) -> String {
    simple_response(
        "200 OK",
        &json!({
            "secret": {
                "id": "secret-id",
                "_id": "secret-id",
                "workspace": "test-project",
                "environment": "dev",
                "version": 1,
                "type": "shared",
                "secretKey": key,
                "secretValue": "written",
                "secretComment": "",
                "createdAt": "2026-11-17T00:00:00.000Z",
                "updatedAt": "2026-11-17T00:00:00.000Z",
            }
        })
        .to_string(),
    )
}

fn infisical_response(request: &Request) -> String {
    let path = request.path.split('?').next().unwrap_or_default();
    match (request.method.as_str(), path) {
        ("GET", "/api/v4/secrets") => {
            simple_response("200 OK", r#"{"secrets":[{"secretKey":"APP_DB"}]}"#)
        }
        ("GET", "/api/v4/secrets/APP_DB") => simple_response(
            "200 OK",
            r#"{"secret":{"secretKey":"APP_DB","secretValue":"stored-value","secretValueHidden":false}}"#,
        ),
        ("GET", _) => simple_response("404 Not Found", r#"{"message":"not found"}"#),
        ("POST", "/api/v4/secrets/APP_DB") => simple_response(
            "400 Bad Request",
            r#"{"statusCode":400,"message":"Secret 'APP_DB' already exists in path '/' of environment 'dev'","error":"BadRequest"}"#,
        ),
        ("POST", "/api/v4/secrets/AMBIGUOUS") => simple_response(
            "500 Internal Server Error",
            r#"{"statusCode":500,"message":"Something went wrong","error":"Create"}"#,
        ),
        ("POST", "/api/v4/secrets/APPROVAL") => simple_response(
            "200 OK",
            r#"{"approval":{"id":"approval-id","slug":"approval-slug"}}"#,
        ),
        ("POST", "/api/v4/secrets/MALFORMED") => simple_response("200 OK", r#"{"secret":false}"#),
        ("POST", "/api/v4/secrets/EMPTY") => simple_response("200 OK", r#"{"secret":{}}"#),
        ("POST", "/api/v4/secrets/MISMATCH") => infisical_created_response("OTHER"),
        ("POST", path) if path.starts_with("/api/v4/secrets/") => {
            infisical_created_response(path.trim_start_matches("/api/v4/secrets/"))
        }
        ("PATCH", _) => simple_response("200 OK", r#"{"secret":{"secretKey":"written"}}"#),
        _ => simple_response("405 Method Not Allowed", "{}"),
    }
}

#[test]
fn infisical_fixture_sends_bearer_auth_and_writes() {
    let fixture = InfisicalFixture::start();
    let directory = tempfile_dir();
    std::fs::write(
        directory.join(".nvault.toml"),
        format!(
            r#"version = 1
provider = "i"
[providers.i]
kind = "infisical"
address = "http://127.0.0.1:{}"
project_id = "test-project"
environment = "dev"
path = "/"
token_env = "TEST_INFISICAL_TOKEN"
allow_http_loopback = true
"#,
            fixture.port
        ),
    )
    .expect("write config");
    let environment = [("TEST_INFISICAL_TOKEN", "test-token")];

    let listing = run(&directory, &["ls"], &environment, None);
    assert!(listing.status.success(), "{}", stderr(&listing));
    assert_eq!(stdout(&listing), "APP_DB\n");

    let get = run(&directory, &["get", "APP_DB"], &environment, None);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(stdout(&get), "stored-value");

    let set = run(
        &directory,
        &["set", "APP_DB"],
        &environment,
        Some(b"replacement"),
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert!(!stdout(&set).contains("replacement"));
    assert!(!stderr(&set).contains("replacement"));

    let set_new = run(
        &directory,
        &["set", "APP_NEW"],
        &environment,
        Some(b"replacement"),
    );
    assert!(set_new.status.success(), "{}", stderr(&set_new));

    let ensured = run(
        &directory,
        &["ensure", "APP_NEW2", "--json"],
        &environment,
        Some(b"created-value"),
    );
    assert!(ensured.status.success(), "{}", stderr(&ensured));
    assert_eq!(stdout(&ensured), "{\"status\":\"created\"}\n");
    assert!(!stdout(&ensured).contains("created-value"));
    assert!(!stderr(&ensured).contains("created-value"));

    let requests = fixture.requests();
    assert!(requests.len() >= 6, "expected several requests");
    for request in &requests {
        let authorization = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str());
        assert_eq!(authorization, Some("Bearer test-token"));
        assert!(!request.path.contains("stored-value"));
    }
    assert!(requests.iter().any(|request| {
        request.method == "GET" && request.path.starts_with("/api/v4/secrets?")
    }));
    assert!(requests.iter().any(|request| {
        request.method == "GET"
            && request.path.starts_with("/api/v4/secrets/APP_DB?")
            && !request.path.contains("viewSecretValue=true")
    }));
    assert!(requests.iter().any(|request| {
        request.method == "PATCH" && request.path.starts_with("/api/v4/secrets/APP_DB?")
    }));
    assert!(requests.iter().any(|request| {
        request.method == "POST" && request.path.starts_with("/api/v4/secrets/APP_NEW?")
    }));
    assert!(
        requests.iter().any(|request| {
            request.method == "POST" && request.path.starts_with("/api/v4/secrets/APP_NEW2?")
        }),
        "ensure must use the Create request"
    );
    assert!(
        !requests
            .iter()
            .any(|request| { request.path.contains("APP_NEW2") && request.method != "POST" }),
        "ensure must not check for existence before creating"
    );
}

#[test]
fn vaultwarden_sync_failure_does_not_write() {
    let directory = tempfile_dir();
    let script = directory.join("bw");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{dir}/argv.log"
case "$*" in
  *" sync"*) exit 1 ;;
  *"list items"*) printf '[]' ;;
  *"create item"*|*"edit item"*) cat > /dev/null ;;
  *) exit 2 ;;
esac
"#,
            dir = directory.display()
        ),
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
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

    let set = run(
        &directory,
        &["set", "ITEM"],
        &[("BW_SESSION", "test-session")],
        Some(b"must-not-write\n"),
    );
    assert!(!set.status.success());
    assert!(stderr(&set).contains("sync failed"));
    assert!(!stderr(&set).contains("must-not-write"));
    assert!(!stdout(&set).contains("must-not-write"));
    let argv = std::fs::read_to_string(directory.join("argv.log")).expect("argv log");
    assert_eq!(argv.trim(), "--nointeraction sync");
}

fn decode_recorded_item(path: &Path) -> Value {
    let encoded = std::fs::read_to_string(path).expect("recorded stdin");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .expect("base64 item");
    serde_json::from_slice(&bytes).expect("item json")
}

#[test]
fn vaultwarden_set_writes_through_stdin_and_keeps_sibling_fields() {
    let directory = tempfile_dir();
    let script = directory.join("bw");
    let item = r#"{"id":"123e4567-e89b-12d3-a456-426614174000","type":1,"name":"DB","notes":"","login":{"username":"alice","password":"old-password"},"fields":[{"name":"api","value":"api-key"}]}"#;
    std::fs::write(directory.join("item.json"), item).expect("item fixture");
    std::fs::write(directory.join("items.json"), format!("[{item}]")).expect("items fixture");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{dir}/argv.log"
case "$*" in
  *" sync"*) : ;;
  *"list items"*) cat "{dir}/items.json" ;;
  *"get item"*) cat "{dir}/item.json" ;;
  *"create item"*|*"edit item"*)
    cat > "{dir}/stdin.b64"
    cat "{dir}/stdin.b64"
    ;;
  *) exit 2 ;;
esac
"#,
            dir = directory.display()
        ),
    )
    .expect("write fixture");
    make_executable(&script);
    std::fs::write(
        directory.join(".nvault.toml"),
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

    let providers = run(&directory, &["providers"], &environment, None);
    assert!(providers.status.success(), "{}", stderr(&providers));
    assert!(stdout(&providers).contains("vaultwarden\tread=true\twrite=true\tensure=false"));

    let set = run(
        &directory,
        &["set", "DB#password"],
        &environment,
        Some(b"new-password"),
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert!(!stdout(&set).contains("new-password"));
    assert!(!stderr(&set).contains("new-password"));
    let argv = std::fs::read_to_string(directory.join("argv.log")).expect("argv log");
    assert_eq!(
        argv.lines().last(),
        Some("--nointeraction edit item 123e4567-e89b-12d3-a456-426614174000")
    );
    assert!(!argv.contains("new-password"));
    let written = decode_recorded_item(&directory.join("stdin.b64"));
    assert_eq!(written["name"], "DB");
    assert_eq!(written["login"]["password"], "new-password");
    assert_eq!(written["login"]["username"], "alice");
    assert_eq!(written["fields"][0]["value"], "api-key");

    let created = run(
        &directory,
        &["set", "FRESH"],
        &environment,
        Some(b"fresh-secret"),
    );
    assert!(created.status.success(), "{}", stderr(&created));
    let argv = std::fs::read_to_string(directory.join("argv.log")).expect("argv log");
    assert_eq!(argv.lines().last(), Some("--nointeraction create item"));
    assert!(!argv.contains("fresh-secret"));
    let written = decode_recorded_item(&directory.join("stdin.b64"));
    assert_eq!(written["name"], "FRESH");
    assert_eq!(written["type"], 1);
    assert_eq!(written["login"]["password"], "fresh-secret");

    let invoked = argv.lines().count();
    let refused = run(
        &directory,
        &["set", "DB#id"],
        &environment,
        Some(b"not-written"),
    );
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("ids cannot be set"));
    assert!(!stderr(&refused).contains("not-written"));
    let argv = std::fs::read_to_string(directory.join("argv.log")).expect("argv log");
    assert_eq!(argv.lines().count(), invoked, "refusal reached the CLI");
}

#[test]
fn vaultwarden_profiles_with_different_command_paths_share_one_write_lock() {
    struct ReleaseOnDrop(std::path::PathBuf);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::write(self.0.join("release"), b"release");
        }
    }

    let root = tempfile_dir();
    let _release = ReleaseOnDrop(root.clone());
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    std::fs::create_dir_all(&alpha).expect("alpha directory");
    std::fs::create_dir_all(&beta).expect("beta directory");
    for (directory, label) in [(&alpha, "alpha"), (&beta, "beta")] {
        let script = directory.join("bw");
        std::fs::write(
            &script,
            format!(
                r#"#!/bin/sh
root="{root}"
if mkdir "$root/held" 2>/dev/null; then
  : > "$root/first-entered"
  while [ ! -f "$root/release" ]; do sleep 0.1; done
fi
printf '%s %s\n' "{label}" "$*" >> "$root/invocations.log"
case "$*" in
  *" sync"*) : ;;
  *"list items"*) printf '[]' ;;
  *"create item"*|*"edit item"*) cat > /dev/null ;;
  *) exit 2 ;;
esac
"#,
                root = root.display(),
                label = label
            ),
        )
        .expect("write fixture");
        make_executable(&script);
        std::fs::write(
            directory.join(".nvault.toml"),
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
    }

    let alpha_dir = alpha.clone();
    let first = thread::spawn(move || {
        run(
            &alpha_dir,
            &["set", "ITEM"],
            &[("BW_SESSION", "test-session")],
            Some(b"first-value\n"),
        )
    });
    let started = std::time::Instant::now();
    while !root.join("first-entered").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the first profile never reached its CLI"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let beta_dir = beta.clone();
    let second = thread::spawn(move || {
        run(
            &beta_dir,
            &["set", "ITEM"],
            &[("BW_SESSION", "test-session")],
            Some(b"second-value\n"),
        )
    });
    thread::sleep(Duration::from_millis(500));
    let held_invocations =
        std::fs::read_to_string(root.join("invocations.log")).unwrap_or_default();
    std::fs::write(root.join("release"), b"release").expect("release the first CLI");
    let first = first.join().expect("join the first write");
    let second = second.join().expect("join the second write");
    assert!(
        !held_invocations
            .lines()
            .any(|line| line.starts_with("beta ")),
        "the second profile reached its CLI while the first profile held the write lock"
    );
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    for output in [&first, &second] {
        assert!(!stderr(output).contains("first-value"));
        assert!(!stderr(output).contains("second-value"));
    }
    let invocations =
        std::fs::read_to_string(root.join("invocations.log")).expect("invocation log");
    assert!(invocations.lines().any(|line| line.starts_with("alpha ")));
    assert!(invocations.lines().any(|line| line.starts_with("beta ")));
}

fn tempfile_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nvault-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("temp dir");
    path
}
