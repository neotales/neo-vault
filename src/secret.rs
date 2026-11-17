//! A secret byte buffer that redacts itself in debug output.

use std::fmt;

use zeroize::Zeroizing;

/// Secret bytes held for the shortest possible time.
///
/// There is deliberately no `Display` implementation and no accessor that
/// returns an owned `String`; printing a secret requires an explicit call to
/// [`Secret::expose`] at the point where the bytes are written to the intended
/// destination.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wraps bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Returns the secret bytes. The caller must not log them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_contains_the_value() {
        let secret = Secret::new(b"correct horse battery staple".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    }
}
