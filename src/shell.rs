//! Shell quoting, export rendering, and directory hooks.

use std::fmt::Write as _;

use crate::cli::{EnvShell, HookShell};
use crate::error::{Error, Result};
use crate::provider::ListedKey;
use crate::secret::Secret;

/// One resolved key/value pair.
pub struct Export {
    /// Environment variable name.
    pub name: String,
    /// Secret bytes.
    pub value: Secret,
}

/// Renders `export`/`set -gx` lines for a shell.
///
/// # Errors
///
/// Returns an error when a value is not UTF-8 or contains NUL.
pub fn render_env(exports: &[Export], shell: EnvShell) -> Result<String> {
    let mut output = String::new();
    let mut names = Vec::with_capacity(exports.len());
    for export in exports {
        let value = std::str::from_utf8(export.value.expose())
            .map_err(|_| Error::new(format!("value for {} is not UTF-8", export.name)))?;
        if value.contains('\0') {
            return Err(Error::new(format!(
                "value for {} contains NUL",
                export.name
            )));
        }
        match shell {
            EnvShell::Bash | EnvShell::Zsh => {
                writeln!(output, "export {}={}", export.name, quote_posix(value))
                    .map_err(|_| Error::new("cannot render shell exports"))?;
            }
            EnvShell::Fish => {
                writeln!(output, "set -gx {} {}", export.name, quote_fish(value))
                    .map_err(|_| Error::new("cannot render shell exports"))?;
            }
        }
        names.push(export.name.clone());
    }
    let loaded = names.join(" ");
    match shell {
        EnvShell::Bash | EnvShell::Zsh => {
            writeln!(output, "export NVAULT_LOADED_KEYS={}", quote_posix(&loaded))
                .map_err(|_| Error::new("cannot render shell exports"))?;
        }
        EnvShell::Fish => {
            writeln!(output, "set -gx NVAULT_LOADED_KEYS {}", quote_fish(&loaded))
                .map_err(|_| Error::new("cannot render shell exports"))?;
        }
    }
    Ok(output)
}

/// Quotes a value for POSIX shells.
#[must_use]
pub fn quote_posix(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('\'');
    for character in value.chars() {
        if character == '\'' {
            output.push_str("'\\''");
        } else {
            output.push(character);
        }
    }
    output.push('\'');
    output
}

/// Quotes a value for fish.
#[must_use]
pub fn quote_fish(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('\'');
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\'' => output.push_str("\\'"),
            _ => output.push(character),
        }
    }
    output.push('\'');
    output
}

/// Filters listed keys by a comma-separated exact-name selection.
///
/// A requested key that was not listed is still returned: fields such as
/// `Entry#UserName` are intentionally not part of a metadata listing, and the
/// provider's `get` is the authority on whether the key exists.
///
/// # Errors
///
/// Returns an error when the selection is empty.
pub fn select_keys(keys: &[ListedKey], only: Option<&str>) -> Result<Vec<ListedKey>> {
    let Some(only) = only else {
        return Ok(keys.to_vec());
    };
    let wanted: Vec<&str> = only
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if wanted.is_empty() {
        return Err(Error::new("--only did not name any keys"));
    }
    let mut selected = Vec::new();
    for name in &wanted {
        match keys.iter().find(|key| key.key == *name) {
            Some(key) => selected.push(key.clone()),
            None => selected.push(ListedKey::new(*name)),
        }
    }
    Ok(selected)
}

/// Generates a directory hook.
///
/// The hook tracks the working directory and sets `NVAULT_DIR`. It evaluates
/// the provider environment only when `NVAULT_AUTOLOAD=1`, so a shell does not
/// fetch secrets merely because it changed directory. Previously exported keys
/// are unset through `NVAULT_LOADED_KEYS` before each reload.
#[must_use]
pub fn hook(shell: HookShell) -> String {
    match shell {
        HookShell::Bash => bash_hook(),
        HookShell::Zsh => zsh_hook(),
        HookShell::Fish => fish_hook(),
    }
}

fn bash_hook() -> String {
    r#"_nvault_hook() {
  [ "${PWD:-}" = "${NVAULT_LAST_DIR:-}" ] && return 0
  NVAULT_LAST_DIR="$PWD"
  local root
  root="$(nvault dir 2>/dev/null)"
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
  else
    unset NVAULT_DIR
  fi
  if [ -n "${NVAULT_LOADED_KEYS:-}" ]; then
    for key in $NVAULT_LOADED_KEYS; do unset "$key"; done
    unset NVAULT_LOADED_KEYS
  fi
  if [ "${NVAULT_AUTOLOAD:-0}" = "1" ] && [ -n "$root" ]; then
    eval "$(nvault env --shell bash 2>/dev/null)"
  fi
}
case ";${PROMPT_COMMAND:-};" in
  *";_nvault_hook;"*) ;;
  *) PROMPT_COMMAND="_nvault_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
_nvault_hook
"#
    .to_owned()
}

fn zsh_hook() -> String {
    r#"_nvault_hook() {
  local root
  root="$(nvault dir 2>/dev/null)"
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
  else
    unset NVAULT_DIR
  fi
  if [ -n "${NVAULT_LOADED_KEYS:-}" ]; then
    for key in ${(z)NVAULT_LOADED_KEYS}; do unset "$key"; done
    unset NVAULT_LOADED_KEYS
  fi
  if [ "${NVAULT_AUTOLOAD:-0}" = "1" ] && [ -n "$root" ]; then
    eval "$(nvault env --shell zsh 2>/dev/null)"
  fi
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _nvault_hook
_nvault_hook
"#
    .to_owned()
}

fn fish_hook() -> String {
    r#"function _nvault_hook --on-variable PWD
    set -l root (nvault dir 2>/dev/null)
    if test -n "$root"
        set -gx NVAULT_DIR $root
    else
        set -e NVAULT_DIR
    end
    if set -q NVAULT_LOADED_KEYS
        for key in (string split ' ' -- $NVAULT_LOADED_KEYS)
            set -e $key
        end
        set -e NVAULT_LOADED_KEYS
    end
    if test "$NVAULT_AUTOLOAD" = "1"; and test -n "$root"
        nvault env --shell fish 2>/dev/null | source
    end
end
_nvault_hook
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Export, hook, quote_fish, quote_posix, render_env};
    use crate::cli::{EnvShell, HookShell};
    use crate::secret::Secret;

    #[test]
    fn posix_quoting_handles_quotes_and_newlines() {
        assert_eq!(quote_posix("a'b"), "'a'\\''b'");
        assert_eq!(quote_posix("a\nb"), "'a\nb'");
    }

    #[test]
    fn fish_quoting_handles_escapes() {
        assert_eq!(quote_fish("a'b\\c"), "'a\\'b\\\\c'");
    }

    #[test]
    fn hooks_clean_loaded_names_before_considering_autoload() {
        for shell in [HookShell::Bash, HookShell::Zsh, HookShell::Fish] {
            let script = hook(shell);
            let cleanup = script
                .find("NVAULT_LOADED_KEYS")
                .expect("cleanup bookkeeping");
            let autoload = script.find("NVAULT_AUTOLOAD").expect("autoload check");
            assert!(
                cleanup < autoload,
                "{shell:?} hook checks autoload before cleanup"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn bash_hook_cleans_exports_when_autoload_is_disabled() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let base = std::env::temp_dir().join(format!(
            "nvault-hook-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let fake = bin.join("nvault");
        std::fs::write(
            &fake,
            r#"#!/bin/sh
case "$1" in
  dir) printf '%s\n' "$FAKE_NVAULT_DIR" ;;
  env) printf '%s\n' "export FAKE_SECRET='loaded'" "export NVAULT_LOADED_KEYS='FAKE_SECRET'" ;;
  *) exit 2 ;;
esac
"#,
        )
        .expect("fake nvault");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700))
            .expect("chmod fake nvault");

        let hook_file = base.join("hook.bash");
        std::fs::write(&hook_file, hook(HookShell::Bash)).expect("hook file");
        let script = base.join("test.bash");
        std::fs::write(
            &script,
            format!(
                r#"export PATH="{}:$PATH"
export FAKE_NVAULT_DIR="{}"
export NVAULT_AUTOLOAD=1
source "{}"
_nvault_hook
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 20
[ "${{NVAULT_LOADED_KEYS:-}}" = "FAKE_SECRET" ] || exit 21
export NVAULT_AUTOLOAD=0
cd "{}"
_nvault_hook
[ -z "${{FAKE_SECRET+x}}" ] || exit 22
[ -z "${{NVAULT_LOADED_KEYS+x}}" ] || exit 23
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                other.display(),
            ),
        )
        .expect("test script");

        let output = Command::new("bash")
            .arg("--noprofile")
            .arg("--norc")
            .arg(&script)
            .output()
            .expect("bash is required for the hook regression test");
        let mut stderr = std::io::stderr();
        stderr.write_all(&output.stderr).expect("write bash stderr");
        assert!(
            output.status.success(),
            "bash hook transition failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }
    #[test]
    fn fish_bookkeeping_never_uses_posix_export_syntax() {
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(b"value".to_vec()),
        }];
        let output = render_env(&exports, EnvShell::Fish).expect("env");
        assert!(output.contains("set -gx TOKEN 'value'"));
        assert!(output.contains("set -gx NVAULT_LOADED_KEYS 'TOKEN'"));
        assert!(!output.contains("export NVAULT_LOADED_KEYS"));
    }

    #[test]
    fn renders_exports_without_echoing_values_in_names() {
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(b"value".to_vec()),
        }];
        let output = render_env(&exports, EnvShell::Bash).expect("env");
        assert!(output.contains("export TOKEN='value'"));
        assert!(output.contains("NVAULT_LOADED_KEYS='TOKEN'"));
    }
}
