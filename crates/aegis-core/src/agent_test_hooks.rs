//! Test-only access to private agent helpers.

//! Test-only access to private agent helpers.

/// Expose [`crate::agent`] internals for integration tests.
pub mod test_hooks {
    /// POSIX shell-quote a string (mirrors `agent::shell_quote`).
    pub fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}
