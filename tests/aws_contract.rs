//! AWS Secrets Manager request-contract test.
//!
//! This is a loopback fixture, not a cloud test. It records the JSON bodies
//! that `set` sends and checks the required `ClientRequestToken` contract:
//! every write has one, it matches the documented character set, and the token
//! is stable across the retry that follows a create conflict.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use nvault::{Client, EnsureStatus, Secret};
use serde_json::Value;

#[derive(Clone)]
struct Recorded {
    target: String,
    body: Vec<u8>,
}

struct Fixture {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind AWS fixture");
        listener
            .set_nonblocking(true)
            .expect("nonblocking AWS fixture");
        let port = listener.local_addr().expect("fixture address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        thread::spawn(move || {
            let puts = AtomicUsize::new(0);
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        if let Some((target, body)) = read_request(&mut stream) {
                            thread_requests.lock().expect("requests").push(Recorded {
                                target: target.clone(),
                                body,
                            });
                            let (status, response_body) = match target.as_str() {
                                "secretsmanager.PutSecretValue" => {
                                    if puts.fetch_add(1, Ordering::SeqCst) == 0 {
                                        (
                                            "400 Bad Request",
                                            r#"{"__type":"ResourceNotFoundException"}"#,
                                        )
                                    } else {
                                        ("200 OK", "{}")
                                    }
                                }
                                "secretsmanager.CreateSecret" => {
                                    ("400 Bad Request", r#"{"__type":"ResourceExistsException"}"#)
                                }
                                _ => ("400 Bad Request", "{}"),
                            };
                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                                response_body.len()
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

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("requests").clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, Vec<u8>)> {
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
    let mut target = None;
    let mut content_length = 0_usize;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("x-amz-target") {
            target = Some(value.trim().to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok()?;
        }
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut chunk).ok()?;
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
    }
    body.truncate(content_length);
    Some((target?, body))
}

fn token<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get("ClientRequestToken")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} has no ClientRequestToken"))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[test]
fn create_and_put_carry_stable_valid_client_request_tokens() {
    let fixture = Fixture::start();
    let directory = std::env::temp_dir().join(format!(
        "nvault-aws-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir mode");
    }
    write_credential(&directory.join("access"), "test");
    write_credential(&directory.join("secret"), "test");
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"version = 1
provider = "aws"
[providers.aws]
kind = "aws-secrets-manager"
region = "us-east-1"
endpoint = "http://127.0.0.1:{}"
access_key_file = "access"
secret_key_file = "secret"
allow_http_loopback = true
"#,
            fixture.port
        ),
    )
    .expect("write AWS config");
    let client = Client::open(&config).expect("open AWS client");
    client
        .set(
            Some("aws"),
            "app-db",
            &Secret::new(b"not-a-real-secret".to_vec()),
        )
        .expect("AWS set through fixture");

    let requests = fixture.requests();
    assert_eq!(requests.len(), 3, "expected Put, Create, Put");
    assert_eq!(requests[0].target, "secretsmanager.PutSecretValue");
    assert_eq!(requests[1].target, "secretsmanager.CreateSecret");
    assert_eq!(requests[2].target, "secretsmanager.PutSecretValue");

    let first_put: Value = serde_json::from_slice(&requests[0].body).expect("first Put body");
    let create: Value = serde_json::from_slice(&requests[1].body).expect("Create body");
    let retried_put: Value = serde_json::from_slice(&requests[2].body).expect("retried Put body");

    let first_token = token(&first_put, "PutSecretValue");
    let create_token = token(&create, "CreateSecret");
    let retried_token = token(&retried_put, "PutSecretValue");
    assert!(valid_token(first_token), "invalid Put token");
    assert!(valid_token(create_token), "invalid Create token");
    assert!(valid_token(retried_token), "invalid retried Put token");
    assert_eq!(
        first_token, retried_token,
        "the Put retry must reuse its logical request token"
    );
    assert_ne!(
        create_token, first_token,
        "CreateSecret must use its own logical request token"
    );
    assert_eq!(
        first_put.get("SecretString").and_then(Value::as_str),
        Some("not-a-real-secret")
    );
    assert_eq!(
        create.get("SecretString").and_then(Value::as_str),
        Some("not-a-real-secret")
    );

    let ensured = client
        .ensure(
            Some("aws"),
            "app-ensure",
            &Secret::new(b"not-a-real-secret".to_vec()),
        )
        .expect("AWS ensure through fixture");
    assert_eq!(ensured, EnsureStatus::Present);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 4, "expected a CreateSecret from ensure");
    assert_eq!(requests[3].target, "secretsmanager.CreateSecret");
    let ensure_body: Value = serde_json::from_slice(&requests[3].body).expect("ensure body");
    let ensure_token = token(&ensure_body, "CreateSecret from ensure");
    assert!(valid_token(ensure_token), "invalid ensure token");

    std::fs::remove_dir_all(directory).expect("remove temp dir");
}

fn write_credential(path: &Path, value: &str) {
    std::fs::write(path, value).expect("write credential fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("credential mode");
    }
}
