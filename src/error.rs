//! Error type whose messages never carry secret material.
//!
//! Callers may include provider names, key names, configuration field names,
//! and HTTP status codes. They must not include response bodies, child-process
//! output, or values read from a secret store.

use std::fmt;

/// A user-facing failure.
#[derive(Debug)]
pub struct Error {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Creates an error from a message that contains no secret material.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Adds a lower-level cause. The cause is never printed as part of
    /// [`Display`](fmt::Display); callers decide whether it is safe to debug.
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the redacted message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// A result using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Creates an unsupported-operation error.
#[must_use]
pub fn unsupported(operation: &str, provider: &str) -> Error {
    Error::new(format!(
        "{provider} does not support {operation} in this build"
    ))
}
