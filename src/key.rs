//! Provider-neutral key grammar.
//!
//! A key is a provider path with an optional `#field` suffix. The grammar is
//! intentionally small and unambiguous: the first `#` separates the path from
//! the field, and neither side may be empty. Providers that do not have fields
//! reject a field rather than silently ignoring it.

use crate::error::{Error, Result};

/// A parsed key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key<'a> {
    path: &'a str,
    field: Option<&'a str>,
}

impl<'a> Key<'a> {
    /// Parses a key.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty path, an empty field, or a second `#`.
    pub fn parse(raw: &'a str) -> Result<Self> {
        let (path, field) = match raw.split_once('#') {
            Some((path, field)) => {
                if field.contains('#') {
                    return Err(Error::new(
                        "invalid key: a key may contain at most one '#' field separator",
                    ));
                }
                if field.is_empty() {
                    return Err(Error::new("invalid key: the field after '#' is empty"));
                }
                (path, Some(field))
            }
            None => (raw, None),
        };
        if path.is_empty() {
            return Err(Error::new("invalid key: the path before '#' is empty"));
        }
        Ok(Self { path, field })
    }

    /// Returns the provider path.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// Returns the optional field name.
    #[must_use]
    pub const fn field(&self) -> Option<&'a str> {
        self.field
    }
}

/// Returns the environment variable name used for a key.
///
/// The basename becomes upper case, every non-alphanumeric byte becomes `_`,
/// and a field is appended as `_FIELD`. The result is checked so a malformed
/// key can never produce an invalid environment entry.
///
/// # Errors
///
/// Returns an error when the derived name is empty or does not begin with a
/// letter or underscore.
pub fn env_name(key: &str, prefix: &str) -> Result<String> {
    let parsed = Key::parse(key)?;
    let base = parsed
        .path()
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(parsed.path());
    let mut name = String::new();
    if !prefix.is_empty() {
        name.push_str(prefix);
    }
    push_env_component(&mut name, base);
    if let Some(field) = parsed.field() {
        if !name.is_empty() {
            name.push('_');
        }
        push_env_component(&mut name, field);
    }
    if name.is_empty() {
        return Err(Error::new(
            "key cannot be converted to an environment variable name",
        ));
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(Error::new(
            "derived environment variable name must start with a letter or underscore",
        ));
    }
    Ok(name)
}

fn push_env_component(output: &mut String, component: &str) {
    let mut started = false;
    for byte in component.bytes() {
        let valid = byte.is_ascii_alphanumeric();
        if valid {
            output.push(char::from(byte.to_ascii_uppercase()));
            started = true;
        } else if started {
            output.push('_');
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, env_name};

    #[test]
    fn parses_a_path_and_field() {
        let key = Key::parse("apps/prod/db#password").expect("key");
        assert_eq!(key.path(), "apps/prod/db");
        assert_eq!(key.field(), Some("password"));
    }

    #[test]
    fn rejects_ambiguous_keys() {
        assert!(Key::parse("").is_err());
        assert!(Key::parse("#field").is_err());
        assert!(Key::parse("path#").is_err());
        assert!(Key::parse("path#a#b").is_err());
    }

    #[test]
    fn derives_stable_environment_names() {
        assert_eq!(env_name("apps/prod/db", "").expect("name"), "DB");
        assert_eq!(
            env_name("apps/prod/db#password", "APP_").expect("name"),
            "APP_DB_PASSWORD"
        );
        assert_eq!(env_name("github-token", "").expect("name"), "GITHUB_TOKEN");
        assert!(env_name("1password", "").is_err());
    }
}
