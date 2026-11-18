//! `nvault` binary entry point.

#![forbid(unsafe_code)]

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = nvault::cli::Cli::parse();
    std::process::ExitCode::from(nvault::commands::run(cli))
}
