//! `nsvault` binary entry point.

#![forbid(unsafe_code)]

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = nsvault::cli::Cli::parse();
    std::process::ExitCode::from(nsvault::commands::run(cli))
}
