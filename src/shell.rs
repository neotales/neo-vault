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
            writeln!(
                output,
                "export NSVAULT_LOADED_KEYS={}",
                quote_posix(&loaded)
            )
            .map_err(|_| Error::new("cannot render shell exports"))?;
        }
        EnvShell::Fish => {
            writeln!(
                output,
                "set -gx NSVAULT_LOADED_KEYS {}",
                quote_fish(&loaded)
            )
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
/// The hook tracks the working directory and sets `NSVAULT_DIR`. It evaluates
/// the provider environment only when `NSVAULT_AUTOLOAD=1`, so a shell does not
/// fetch secrets merely because it changed directory. Previously exported keys
/// are unset through `NSVAULT_LOADED_KEYS` before each reload.
#[must_use]
pub fn hook(shell: HookShell) -> String {
    match shell {
        HookShell::Bash => bash_hook(),
        HookShell::Zsh => zsh_hook(),
        HookShell::Fish => fish_hook(),
    }
}

fn bash_hook() -> String {
    r#"_nsvault_hook() {
  [ "${PWD:-}" = "${NSVAULT_LAST_DIR:-}" ] && return 0
  NSVAULT_LAST_DIR="$PWD"
  local root
  root="$(nsvault dir 2>/dev/null)"
  if [ -n "$root" ]; then
    export NSVAULT_DIR="$root"
  else
    unset NSVAULT_DIR
  fi
  if [ "${NSVAULT_AUTOLOAD:-0}" = "1" ]; then
    if [ -n "${NSVAULT_LOADED_KEYS:-}" ]; then
      for key in $NSVAULT_LOADED_KEYS; do unset "$key"; done
      unset NSVAULT_LOADED_KEYS
    fi
    [ -n "$root" ] && eval "$(nsvault env --shell bash 2>/dev/null)"
  fi
}
case ";${PROMPT_COMMAND:-};" in
  *";_nsvault_hook;"*) ;;
  *) PROMPT_COMMAND="_nsvault_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
_nsvault_hook
"#
    .to_owned()
}

fn zsh_hook() -> String {
    r#"_nsvault_hook() {
  local root
  root="$(nsvault dir 2>/dev/null)"
  if [ -n "$root" ]; then
    export NSVAULT_DIR="$root"
  else
    unset NSVAULT_DIR
  fi
  if [ "${NSVAULT_AUTOLOAD:-0}" = "1" ]; then
    if [ -n "${NSVAULT_LOADED_KEYS:-}" ]; then
      for key in ${(z)NSVAULT_LOADED_KEYS}; do unset "$key"; done
      unset NSVAULT_LOADED_KEYS
    fi
    [ -n "$root" ] && eval "$(nsvault env --shell zsh 2>/dev/null)"
  fi
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _nsvault_hook
_nsvault_hook
"#
    .to_owned()
}

fn fish_hook() -> String {
    r#"function _nsvault_hook --on-variable PWD
    set -l root (nsvault dir 2>/dev/null)
    if test -n "$root"
        set -gx NSVAULT_DIR $root
    else
        set -e NSVAULT_DIR
    end
    if test "$NSVAULT_AUTOLOAD" = "1"
        if set -q NSVAULT_LOADED_KEYS
            for key in (string split ' ' -- $NSVAULT_LOADED_KEYS)
                set -e $key
            end
            set -e NSVAULT_LOADED_KEYS
        end
        if test -n "$root"
            nsvault env --shell fish 2>/dev/null | source
        end
    end
end
_nsvault_hook
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Export, quote_fish, quote_posix, render_env};
    use crate::cli::EnvShell;
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
    fn fish_bookkeeping_never_uses_posix_export_syntax() {
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(b"value".to_vec()),
        }];
        let output = render_env(&exports, EnvShell::Fish).expect("env");
        assert!(output.contains("set -gx TOKEN 'value'"));
        assert!(output.contains("set -gx NSVAULT_LOADED_KEYS 'TOKEN'"));
        assert!(!output.contains("export NSVAULT_LOADED_KEYS"));
    }

    #[test]
    fn renders_exports_without_echoing_values_in_names() {
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(b"value".to_vec()),
        }];
        let output = render_env(&exports, EnvShell::Bash).expect("env");
        assert!(output.contains("export TOKEN='value'"));
        assert!(output.contains("NSVAULT_LOADED_KEYS='TOKEN'"));
    }
}
