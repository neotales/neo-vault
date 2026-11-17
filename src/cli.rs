//! Command-line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Automation-first secrets proxy.
#[derive(Debug, Parser)]
#[command(
    name = "nsvault",
    version,
    about = "Resolve secrets from a directory-scoped provider without putting values in argv",
    after_help = "Secrets are read from stdin (never --value) and written to stdout or a child environment. Errors never echo a value."
)]
pub struct Cli {
    /// Configuration file. Defaults to `NSVAULT_CONFIG`, then the nearest
    /// `.nsvault.toml`/`.nsvault.yaml`, then `~/.config/nsvault/config.toml`
    /// (or `config.yaml`).
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Provider profile. Defaults to `provider` in the configuration.
    #[arg(long, global = true, value_name = "NAME")]
    pub provider: Option<String>,

    /// Default key prefix for list, search, exec, and env.
    #[arg(long = "prefix", global = true, value_name = "PATH")]
    pub prefix: Option<String>,

    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List key names under a prefix. Never reads values.
    Ls {
        /// Optional key prefix.
        prefix: Option<String>,
        /// Emit a JSON array of key names.
        #[arg(long)]
        json: bool,
    },
    /// Print one secret value to stdout.
    Get {
        /// Key, optionally with a `#field` suffix.
        key: String,
        /// Field name, as an alternative to `key#field`.
        #[arg(long)]
        field: Option<String>,
        /// Append a newline after the value.
        #[arg(long)]
        newline: bool,
    },
    /// Create a secret from stdin when the provider confirms it is absent.
    ///
    /// Does not replace an existing secret and does not delete. Providers
    /// without a race-safe create-if-absent path refuse this command.
    Ensure {
        /// Key, optionally with a `#field` suffix.
        key: String,
        /// Field name, as an alternative to `key#field`.
        #[arg(long)]
        field: Option<String>,
        /// Read from stdin even when stdin is a terminal.
        #[arg(long)]
        stdin: bool,
        /// Print `{"status":"created"}` or `{"status":"present"}`. Never a value.
        #[arg(long)]
        json: bool,
    },
    /// Read a secret from stdin (or a hidden prompt) and write it to the provider.
    Set {
        /// Key, optionally with a `#field` suffix.
        key: String,
        /// Field name, as an alternative to `key#field`.
        #[arg(long)]
        field: Option<String>,
        /// Read from stdin even when stdin is a terminal.
        #[arg(long)]
        stdin: bool,
    },
    /// Search key names only. Values are never fetched.
    Search {
        /// Case-insensitive substring for names.
        query: String,
        /// Maximum results.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Emit a JSON array of matches.
        #[arg(long)]
        json: bool,
    },
    /// Run a command with secrets exported into its environment.
    #[command(alias = "x")]
    Exec {
        /// Environment variable prefix for exported keys.
        #[arg(long, value_name = "PREFIX")]
        env_prefix: Option<String>,
        /// Only export these keys (comma-separated).
        #[arg(long, value_name = "KEYS")]
        only: Option<String>,
        /// Command and arguments. A leading `--` is accepted.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Print shell exports for the current directory.
    Env {
        /// Output shell syntax.
        #[arg(long, value_enum, default_value_t = EnvShell::Bash)]
        shell: EnvShell,
        /// Environment variable prefix for exported keys.
        #[arg(long, value_name = "PREFIX")]
        env_prefix: Option<String>,
        /// Only export these keys (comma-separated).
        #[arg(long, value_name = "KEYS")]
        only: Option<String>,
    },
    /// Generate shell completion.
    Completion {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print a directory hook for the requested shell.
    Hook {
        /// Shell to emit a hook for.
        #[arg(value_enum)]
        shell: HookShell,
    },
    /// Print the nearest configuration directory, or nothing.
    Dir,
    /// Describe configured provider profiles without reading credentials.
    Providers,
}

/// Shells supported by the directory hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HookShell {
    /// Bourne Again Shell.
    Bash,
    /// Z shell.
    Zsh,
    /// Friendly Interactive Shell.
    Fish,
}

/// Shells supported by `env`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EnvShell {
    /// Bourne Again Shell.
    Bash,
    /// Z shell.
    Zsh,
    /// Friendly Interactive Shell.
    Fish,
}
