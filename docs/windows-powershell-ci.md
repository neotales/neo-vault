# Windows PowerShell 5.1 CI

`.github/workflows/windows-powershell.yml` runs the PowerShell directory hook on
a GitHub-hosted `windows-2022` runner. It exists because the 5.1 claim in the
README was never executed: this repository's Linux worktree can run PowerShell 7
(`pwsh`), not Windows PowerShell 5.1.

## What it runs

```powershell
cargo test --lib windows_powershell_51 -- --test-threads=1 --nocapture
```

Six 5.1 tests in `src/shell.rs`, plus a host-independent invariant:

- `windows_driver_never_overwrites_the_hook` — runs in ordinary `cargo test` on
  every host. Each 5.1 test writes a hook and a separate driver script; the
  helper refuses a shared path and re-reads the hook after the driver is
  written, so `. __HOOK__` cannot dot-source the driver itself.
- `windows_powershell_51_hook_loads_and_cleans_up` — source the hook,
  load `dir` + `env --shell json-base64`, keep the previous `prompt`, re-source
  the hook, then change directory and confirm every loaded name and
  `NVAULT_LOADED_KEYS` are removed. Restoration is a separate test: a successful
  load is cleaned up by removing the tracked names, not by restoring them.
- `windows_powershell_51_rendered_values_stay_literal` — evaluate
  `env --shell powershell` output (`quote_powershell`) containing all five
  characters PowerShell reads as a single quote, a newline, a backtick, `$env:`,
  and a `New-Item` payload. The payload must stay a value and must not run.
- `windows_powershell_51_hook_retries_after_a_transient_failure` — the first
  `nvault dir` exits 1. The hook prints `nvault: could not load this directory;
  will retry`, applies nothing, and the next invocation succeeds.
- `windows_powershell_51_retries_a_failed_cleanup` — seed the in-memory record a
  failed restore leaves behind, then confirm the next invocation restores a
  value that existed and removes one that did not, without printing either.
- `windows_powershell_51_refuses_env_that_is_not_json` — malformed `env` output
  is refused with the retry line and no names are set.
- `windows_powershell_51_refuses_mismatched_tracking` — `NVAULT_LOADED_KEYS`
  that does not match the decoded names is refused before anything is applied.

Every 5.1 test asserts `$PSVersionTable.PSEdition -eq 'Desktop'` and
`$PSVersionTable.PSVersion` 5.1 in the script, and the Rust helper probes the
engine first. A different engine exits 90 instead of skipping. The workflow
repeats the assertion in its own `shell: powershell` step and rejects a run that
reports anything other than `6 passed; 0 failed; 0 ignored`, so an accidental
`cargo test` unrelated to 5.1 cannot satisfy it.

## Fake CLI

The tests never contact a provider and never read a secret. A generated
`nvault.cmd` answers `dir` and `env --shell json-base64` from files; its values
are base64 of obviously fake strings. This is deliberate: provider writes and
the same-user write lock are unimplemented or unexercised on Windows, so the
test covers the consumer side of the contract (the hook), not Windows vault
writes.

## Running it

Manual, once the file is on the default branch:

```text
Actions > windows-powershell51 > Run workflow
```

GitHub registers a `workflow_dispatch` workflow only from the default branch, so
a copy that exists only on `feat/windows-ci` cannot be dispatched, even with
`gh workflow run --ref`. The workflow therefore also has exactly one automatic
trigger: a `push` to `feat/windows-ci`. There is no `pull_request`, tag, path
filter, or other branch. Once the file reaches the default branch the manual
trigger works there, and the branch-limited push trigger is inert elsewhere.

On a Windows machine with Windows PowerShell 5.1:

```powershell
cargo test --lib windows_powershell_51 -- --test-threads=1 --nocapture
```

Off Windows the tests compile and are listed as ignored, so `cargo test` locally
reports `6 ignored`, never passed.

## Failure modes

- `exit 90` — the script was run by PowerShell 7 or another engine. The hook is
  supported there, but this test is specifically the 5.1 path; the workflow
  fails rather than skipping.
- `exit 20`–`exit 39` — a specific assertion: value mismatch, a payload that
  executed, a name that was not cleaned up, a value not restored, or a probe
  that did not retry.
- `expected rustc 1.100.0` — `rust-toolchain.toml` was not honoured, so the
  build would not match the rest of the repository.
- `does not all run and pass` — the filtered test count was wrong, or tests were
  ignored, which is how a silently skipped 5.1 suite is caught.
- `nvault: fake: unexpected arguments` on stderr with a test failure — the hook
  invoked the fake CLI with an argument shape the test fixtures do not serve.

The workflow captures the native test command through `cmd.exe` with
`$ErrorActionPreference = 'Continue'`, saves `$LASTEXITCODE` immediately, then
restores `Stop` and checks the exit code and the `6 passed; 0 failed; 0 ignored`
summary. Windows PowerShell 5.1 turns a native command's normal stderr into an
`ErrorRecord` when `2>&1` is used, and `Stop` would otherwise end the step before
the code is read.

## Not covered

- Provider writes on Windows. `src/provider/lock.rs` returns an error for the
  same-user write lock off Unix, and the README says so; this workflow does not
  change that claim.
- `bw`, `keepassxc-cli`, and `pass-cli` process adapters on Windows.
- 5.1 is unverified until this workflow has actually produced a green run. A
  successful local `cargo test` on Linux is not evidence for it.
