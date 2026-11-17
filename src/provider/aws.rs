//! AWS Secrets Manager provider.
//!
//! The adapter speaks the JSON 1.1 API directly and signs each request with
//! AWS Signature Version 4. Credentials are static for the process lifetime:
//! an access key id, secret access key, and optional session token are read
//! from named environment variables or owner-only files. There is no SDK,
//! credential-provider chain, IMDS, or STS exchange in this build.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config::AwsSecretsManagerConfig;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::provider::{
    Capabilities, EnsureStatus, HttpClient, HttpResponse, ListedKey, Provider, load_credential,
};
use crate::secret::Secret;

/// The SigV4 service name for Secrets Manager.
const SERVICE: &str = "secretsmanager";

/// The JSON 1.1 content type used by Secrets Manager.
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// Maximum pages followed for one listing.
const MAX_PAGES: usize = 100;

/// Maximum keys returned by one listing.
const MAX_LISTED: usize = 10_000;

/// AWS Secrets Manager provider.
#[derive(Debug)]
pub struct AwsSecretsManagerProvider {
    name: String,
    base: url::Url,
    region: String,
    access_key: Secret,
    secret_key: Secret,
    session_token: Option<Secret>,
    client: HttpClient,
}

impl AwsSecretsManagerProvider {
    /// Builds an AWS Secrets Manager provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint or region, or when a named
    /// credential cannot be read.
    pub fn new(name: &str, config: &AwsSecretsManagerConfig, root: &Path) -> Result<Self> {
        if !crate::config::valid_aws_region(&config.region) {
            return Err(Error::new("AWS region is invalid"));
        }
        if let Some(endpoint) = &config.endpoint {
            crate::config::validate_http_base(endpoint, config.allow_http_loopback)
                .map_err(|error| Error::new(format!("AWS endpoint: {}", error.message())))?;
        }
        let base = match &config.endpoint {
            Some(endpoint) => url::Url::parse(endpoint)
                .map_err(|_| Error::new("AWS endpoint is not a valid URL"))?,
            None => url::Url::parse(&format!(
                "https://secretsmanager.{}.amazonaws.com",
                config.region
            ))
            .map_err(|_| Error::new("AWS endpoint could not be derived from the region"))?,
        };
        let access_key = load_credential(
            config.access_key_env.as_deref(),
            config
                .access_key_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
            "AWS access key id",
        )?;
        let secret_key = load_credential(
            config.secret_key_env.as_deref(),
            config
                .secret_key_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
            "AWS secret access key",
        )?;
        let session_token = optional_credential(
            config.session_token_env.as_deref(),
            config
                .session_token_file
                .as_deref()
                .map(|path| root.join(path))
                .as_deref(),
        )?;
        Ok(Self {
            name: name.to_owned(),
            base,
            region: config.region.clone(),
            access_key,
            secret_key,
            session_token,
            client: HttpClient::new(),
        })
    }

    fn request(&self, action: &str, body: &Value) -> Result<HttpResponse> {
        let payload = serde_json::to_vec(body)
            .map_err(|_| Error::new("AWS request body could not be encoded"))?;
        let amz_date = amz_date_now();
        let payload_hash = hex(&Sha256::digest(&payload));
        let host = host_header(&self.base)?;
        let target = format!("{SERVICE}.{action}");
        let access_key = text(&self.access_key, "AWS access key id")?;
        let secret_key = text(&self.secret_key, "AWS secret access key")?;
        let session_token = self
            .session_token
            .as_ref()
            .map(|token| text(token, "AWS session token"))
            .transpose()?;

        let mut headers = vec![
            ("content-type", CONTENT_TYPE),
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
            ("x-amz-target", target.as_str()),
        ];
        if let Some(token) = session_token {
            headers.push(("x-amz-security-token", token));
        }
        let authorization = authorization(&SigningRequest {
            access_key,
            secret_key,
            region: &self.region,
            service: SERVICE,
            method: "POST",
            url: &self.base,
            headers: &headers,
            payload: &payload,
            amz_date: &amz_date,
        })?;

        let mut extra_headers = vec![
            ("X-Amz-Target", target.as_str()),
            ("X-Amz-Date", amz_date.as_str()),
            ("X-Amz-Content-Sha256", payload_hash.as_str()),
        ];
        if let Some(token) = session_token {
            extra_headers.push(("X-Amz-Security-Token", token));
        }
        extra_headers.push(("Authorization", authorization.as_str()));
        self.client.request(
            "POST",
            &self.base,
            None,
            &extra_headers,
            CONTENT_TYPE,
            Some(&payload),
        )
    }

    fn list_page(&self, next_token: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        let mut body = json!({ "MaxResults": 100 });
        if let Some(token) = next_token {
            body["NextToken"] = Value::String(token.to_owned());
        }
        let response = self.request("ListSecrets", &body)?;
        if response.status != 200 {
            return Err(aws_status_error(&response, "secret list"));
        }
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "SecretList", default)]
            secrets: Vec<SecretEntry>,
            #[serde(rename = "NextToken", default)]
            next_token: Option<String>,
        }
        #[derive(Deserialize)]
        struct SecretEntry {
            #[serde(rename = "Name")]
            name: String,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        Ok((
            envelope
                .secrets
                .into_iter()
                .map(|entry| entry.name)
                .collect(),
            envelope.next_token,
        ))
    }

    fn create_secret(&self, name: &str, text: &str) -> Result<HttpResponse> {
        self.request(
            "CreateSecret",
            &json!({ "Name": name, "SecretString": text }),
        )
    }

    fn put_secret_value(&self, name: &str, text: &str) -> Result<HttpResponse> {
        self.request(
            "PutSecretValue",
            &json!({ "SecretId": name, "SecretString": text }),
        )
    }
}

impl Provider for AwsSecretsManagerProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "aws-secrets-manager"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            read: true,
            write: true,
            list: true,
            ensure: true,
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<ListedKey>> {
        let mut keys = Vec::new();
        let mut next_token = None;
        for _ in 0..MAX_PAGES {
            let (page, token) = self.list_page(next_token.as_deref())?;
            for name in page {
                if prefix.is_empty() || name.starts_with(prefix) {
                    keys.push(ListedKey::new(name));
                    if keys.len() >= MAX_LISTED {
                        return Err(Error::new(format!(
                            "AWS Secrets Manager listing exceeded {MAX_LISTED} keys"
                        )));
                    }
                }
            }
            match token {
                Some(token) if !token.is_empty() => next_token = Some(token),
                _ => return Ok(keys),
            }
        }
        Err(Error::new(
            "AWS Secrets Manager listing exceeded the page limit",
        ))
    }

    fn get(&self, raw_key: &str) -> Result<Secret> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("AWS Secrets Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "AWS secret names must contain only letters, digits, '/', '_', '+', '=', '.', '@', and '-'",
            ));
        }
        let response = self.request("GetSecretValue", &json!({ "SecretId": key.path() }))?;
        if response.status != 200 {
            return Err(aws_status_error(&response, key.path()));
        }
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "SecretString", default)]
            secret_string: Option<String>,
            #[serde(rename = "SecretBinary", default)]
            secret_binary: Option<String>,
        }
        let envelope: Envelope = HttpClient::json(&response)?;
        if let Some(value) = envelope.secret_string {
            return Ok(Secret::new(value.into_bytes()));
        }
        if let Some(value) = envelope.secret_binary {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| Error::new("AWS returned a binary secret that is not valid base64"))?;
            return Ok(Secret::new(bytes));
        }
        Err(Error::new(format!(
            "AWS Secrets Manager response for {:?} has no value",
            key.path()
        )))
    }

    fn set(&self, raw_key: &str, value: &Secret) -> Result<()> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("AWS Secrets Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "AWS secret names must contain only letters, digits, '/', '_', '+', '=', '.', '@', and '-'",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("AWS Secrets Manager values must be UTF-8 text"))?;
        let response = self.put_secret_value(key.path(), text)?;
        if response.status == 200 {
            return Ok(());
        }
        if response.status == 400
            && aws_error_type(&response).as_deref() == Some("ResourceNotFoundException")
        {
            let created = self.create_secret(key.path(), text)?;
            if created.status == 200 {
                return Ok(());
            }
            if created.status == 400
                && aws_error_type(&created).as_deref() == Some("ResourceExistsException")
            {
                let retried = self.put_secret_value(key.path(), text)?;
                if retried.status == 200 {
                    return Ok(());
                }
                return Err(aws_status_error(&retried, key.path()));
            }
            return Err(aws_status_error(&created, key.path()));
        }
        Err(aws_status_error(&response, key.path()))
    }

    fn ensure(&self, raw_key: &str, value: &Secret) -> Result<EnsureStatus> {
        let key = Key::parse(raw_key)?;
        if key.field().is_some() {
            return Err(Error::new("AWS Secrets Manager keys do not have fields"));
        }
        if !valid_secret_name(key.path()) {
            return Err(Error::new(
                "AWS secret names must contain only letters, digits, '/', '_', '+', '=', '.', '@', and '-'",
            ));
        }
        let text = std::str::from_utf8(value.expose())
            .map_err(|_| Error::new("AWS Secrets Manager values must be UTF-8 text"))?;
        let response = self.create_secret(key.path(), text)?;
        match response.status {
            200 => Ok(EnsureStatus::Created),
            400 if aws_error_type(&response).as_deref() == Some("ResourceExistsException") => {
                Ok(EnsureStatus::Present)
            }
            _ => Err(aws_status_error(&response, key.path())),
        }
    }
}

/// Maps a response status to a fixed message without echoing response fields.
fn aws_status_error(response: &HttpResponse, key: &str) -> Error {
    match response.status {
        400 => match aws_error_type(response).as_deref() {
            Some("ResourceNotFoundException") => {
                Error::new(format!("AWS Secrets Manager has no secret {key:?}"))
            }
            Some("ResourceExistsException") => {
                Error::new(format!("AWS Secrets Manager already has a secret {key:?}"))
            }
            Some("AccessDeniedException") => {
                Error::new(format!("AWS Secrets Manager denied access to {key:?}"))
            }
            _ => Error::new(format!("AWS Secrets Manager returned HTTP 400 for {key:?}")),
        },
        401 | 403 => Error::new(format!("AWS Secrets Manager denied access to {key:?}")),
        404 => Error::new(format!("AWS Secrets Manager has no secret {key:?}")),
        status => Error::new(format!(
            "AWS Secrets Manager returned HTTP {status} for {key:?}"
        )),
    }
}

fn optional_credential(environment: Option<&str>, file: Option<&Path>) -> Result<Option<Secret>> {
    if let Some(variable) = environment
        && std::env::var_os(variable).is_some()
    {
        return crate::provider::credential_from_env(variable).map(Some);
    }
    match file {
        Some(path) => crate::provider::credential_from_file(path).map(Some),
        None => Ok(None),
    }
}

fn text<'a>(secret: &'a Secret, what: &str) -> Result<&'a str> {
    std::str::from_utf8(secret.expose())
        .map_err(|_| Error::new(format!("{what} is not valid UTF-8")))
}

/// Returns whether a name matches the documented Secrets Manager pattern.
fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'_' | b'+' | b'=' | b'.' | b'@' | b'-')
        })
}

fn aws_error_type(response: &HttpResponse) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(rename = "__type")]
        kind: Option<String>,
    }
    let envelope: Envelope = serde_json::from_slice(&response.body).ok()?;
    let kind = envelope.kind?;
    Some(kind.rsplit(['#', '.']).next().unwrap_or(&kind).to_owned())
}

fn host_header(url: &url::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::new("AWS endpoint has no host"))?;
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host.to_owned()),
    }
}

/// Returns the current UTC time in the `YYYYMMDDTHHMMSSZ` SigV4 form.
fn amz_date_now() -> String {
    amz_date(SystemTime::now())
}

fn amz_date(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

/// Converts days since 1970-01-01 to a Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = (days - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

struct SigningRequest<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    service: &'a str,
    method: &'a str,
    url: &'a url::Url,
    headers: &'a [(&'a str, &'a str)],
    payload: &'a [u8],
    amz_date: &'a str,
}

fn authorization(request: &SigningRequest<'_>) -> Result<String> {
    let SigningRequest {
        access_key,
        secret_key,
        region,
        service,
        method,
        url,
        headers,
        payload,
        amz_date,
    } = *request;
    let mut canonical = BTreeMap::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        canonical.insert(name, value);
    }
    let canonical_headers = canonical
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let signed_headers = canonical
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{}\n{}\n{}\n{signed_headers}\n{}",
        canonical_uri(url),
        canonical_query(url),
        canonical_headers,
        hex(&Sha256::digest(payload))
    );
    let date = amz_date
        .get(..8)
        .ok_or_else(|| Error::new("invalid AWS signing date"))?;
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    let mut initial = Zeroizing::new(format!("AWS4{secret_key}").into_bytes());
    let date_key = Zeroizing::new(hmac(&initial, date.as_bytes()));
    initial.zeroize();
    let region_key = Zeroizing::new(hmac(&date_key[..], region.as_bytes()));
    let service_key = Zeroizing::new(hmac(&region_key[..], service.as_bytes()));
    let signing_key = Zeroizing::new(hmac(&service_key[..], b"aws4_request"));
    let signature = hex(&hmac(&signing_key[..], string_to_sign.as_bytes()));

    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    ))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn canonical_uri(url: &url::Url) -> String {
    // `url.path()` is already serialized. Preserve existing `%XX` escapes
    // (notably `%2F`, which must not become a path separator) and encode only
    // bytes that are still literal and outside the unreserved set.
    let bytes = url.path().as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            output.push('%');
            output.push(char::from(bytes[index + 1]).to_ascii_uppercase());
            output.push(char::from(bytes[index + 2]).to_ascii_uppercase());
            index += 3;
            continue;
        }
        if byte == b'/' {
            output.push('/');
        } else {
            push_encoded(byte, &mut output);
        }
        index += 1;
    }
    if output.is_empty() {
        output.push('/');
    }
    output
}

fn canonical_query(url: &url::Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (aws_encode(name.as_bytes()), aws_encode(value.as_bytes())))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_encode(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        push_encoded(*byte, &mut output);
    }
    output
}

fn push_encoded(byte: u8, output: &mut String) {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
        output.push(char::from(byte));
    } else {
        output.push('%');
        output.push_str(&format!("{byte:02X}"));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    use super::{
        AwsSecretsManagerProvider, SigningRequest, amz_date, authorization, aws_status_error,
        valid_secret_name,
    };
    use crate::config::AwsSecretsManagerConfig;
    use crate::provider::HttpResponse;

    #[test]
    fn formats_the_sigv4_date_in_utc() {
        assert_eq!(
            amz_date(UNIX_EPOCH + Duration::from_secs(1_440_938_160)),
            "20150830T123600Z"
        );
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
    }

    #[test]
    fn matches_the_aws_get_vanilla_vector() {
        let url = url::Url::parse("https://example.amazonaws.com/").expect("url");
        let headers = [
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        let value = authorization(&SigningRequest {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "service",
            method: "GET",
            url: &url,
            headers: &headers,
            payload: b"",
            amz_date: "20150830T123600Z",
        })
        .expect("signature");
        assert_eq!(
            value,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn matches_the_aws_post_vanilla_query_vector() {
        let url = url::Url::parse("https://example.amazonaws.com/?Param1=value1").expect("url");
        let headers = [
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        let value = authorization(&SigningRequest {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "service",
            method: "POST",
            url: &url,
            headers: &headers,
            payload: b"",
            amz_date: "20150830T123600Z",
        })
        .expect("signature");
        assert_eq!(
            value,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11"
        );
    }

    #[test]
    fn canonical_uri_preserves_escapes_and_encodes_literal_reserved_bytes() {
        let url = url::Url::parse("https://example.test/a%2Fb+c").expect("url");
        assert_eq!(super::canonical_uri(&url), "/a%2Fb%2Bc");
        let url = url::Url::parse("https://example.test/a b").expect("url");
        assert_eq!(super::canonical_uri(&url), "/a%20b");
        let url = url::Url::parse("https://example.test").expect("url");
        assert_eq!(super::canonical_uri(&url), "/");
    }

    #[test]
    fn host_header_includes_a_non_default_port_and_brackets_ipv6() {
        let url = url::Url::parse("http://127.0.0.1:4566/").expect("url");
        assert_eq!(super::host_header(&url).expect("host"), "127.0.0.1:4566");
        let url = url::Url::parse("https://example.amazonaws.com/").expect("url");
        assert_eq!(
            super::host_header(&url).expect("host"),
            "example.amazonaws.com"
        );
        let url = url::Url::parse("http://[::1]:4566/").expect("url");
        assert_eq!(super::host_header(&url).expect("host"), "[::1]:4566");
    }

    #[test]
    fn constructor_revalidates_endpoint_security() {
        let config = AwsSecretsManagerConfig {
            region: "us-east-1".to_owned(),
            endpoint: Some("http://secrets.example".to_owned()),
            access_key_env: None,
            access_key_file: None,
            secret_key_env: None,
            secret_key_file: None,
            session_token_env: None,
            session_token_file: None,
            allow_http_loopback: false,
        };
        let error = AwsSecretsManagerProvider::new("aws", &config, Path::new("."))
            .expect_err("plaintext endpoint must be refused");
        assert!(error.message().contains("endpoint"));

        let config = AwsSecretsManagerConfig {
            region: "us/east/1".to_owned(),
            endpoint: None,
            access_key_env: None,
            access_key_file: None,
            secret_key_env: None,
            secret_key_file: None,
            session_token_env: None,
            session_token_file: None,
            allow_http_loopback: false,
        };
        assert!(AwsSecretsManagerProvider::new("aws", &config, Path::new(".")).is_err());
    }

    #[test]
    fn error_messages_do_not_echo_response_fields() {
        let response = HttpResponse {
            status: 400,
            body: br#"{"__type":"InjectedException","message":"INJECTED_MESSAGE"}"#.to_vec(),
        };
        let error = aws_status_error(&response, "app-db");
        assert!(!error.message().contains("INJECTED"));
        assert!(error.message().contains("HTTP 400"));
    }

    #[test]
    fn rejects_names_outside_the_documented_pattern() {
        assert!(valid_secret_name("apps/prod/db"));
        assert!(valid_secret_name("db@example.com"));
        assert!(!valid_secret_name("db password"));
        assert!(!valid_secret_name(""));
    }
}
