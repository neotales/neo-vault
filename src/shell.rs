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

/// Renders `export`/`set -gx`/`$env:` assignments for a shell.
///
/// `EnvShell::Nu` renders a JSON object instead of statements: Nushell has no
/// `eval`, so the hook feeds the object to `from json | load-env`. The object
/// also carries `NVAULT_LOADED_KEYS` as a space-separated string.
///
/// # Errors
///
/// Returns an error when a value is not UTF-8 or contains NUL.
pub fn render_env(exports: &[Export], shell: EnvShell) -> Result<String> {
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(exports.len() + 1);
    for export in exports {
        let value = std::str::from_utf8(export.value.expose())
            .map_err(|_| Error::new(format!("value for {} is not UTF-8", export.name)))?;
        if value.contains('\0') {
            return Err(Error::new(format!(
                "value for {} contains NUL",
                export.name
            )));
        }
        pairs.push((export.name.as_str(), value));
    }
    let loaded = pairs
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(" ");
    pairs.push(("NVAULT_LOADED_KEYS", loaded.as_str()));

    if shell == EnvShell::Nu {
        return render_json(&pairs);
    }

    let mut output = String::new();
    for (name, value) in pairs {
        match shell {
            EnvShell::Bash | EnvShell::Zsh => {
                writeln!(output, "export {name}={}", quote_posix(value))
            }
            EnvShell::Fish => writeln!(output, "set -gx {name} {}", quote_fish(value)),
            EnvShell::PowerShell | EnvShell::Pwsh => {
                writeln!(output, "$env:{name} = {}", quote_powershell(value))
            }
            EnvShell::Nu => unreachable!("Nu is rendered before this loop"),
        }
        .map_err(|_| Error::new("cannot render shell exports"))?;
    }
    Ok(output)
}

/// Renders the pairs as a JSON object with one trailing newline.
fn render_json(pairs: &[(&str, &str)]) -> Result<String> {
    let mut object = serde_json::Map::with_capacity(pairs.len());
    for (name, value) in pairs {
        object.insert((*name).to_owned(), serde_json::Value::from(*value));
    }
    let mut output = serde_json::to_string(&serde_json::Value::Object(object))
        .map_err(|_| Error::new("cannot render shell exports"))?;
    output.push('\n');
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

/// Quotes a value for PowerShell.
///
/// PowerShell single-quoted strings are literal; the only escape is a doubled
/// quote. `$`, backticks, and newlines therefore stay inside the value, which
/// keeps an export from being code when a hook passes it to
/// `Invoke-Expression`.
#[must_use]
pub fn quote_powershell(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('\'');
    for character in value.chars() {
        if character == '\'' {
            output.push_str("''");
        } else {
            output.push(character);
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
/// are removed through `NVAULT_LOADED_KEYS` before each reload.
///
/// The PowerShell hooks wrap the existing `prompt` function instead of
/// replacing it and use no PowerShell 7-only syntax, so one body targets
/// Windows PowerShell 5.1 and PowerShell 7 alike. The Nushell hook registers a
/// `pre_prompt` hook and loads the JSON that `env --shell nu` prints; Nushell
/// has no `eval`, so no provider output is executed as code.
#[must_use]
pub fn hook(shell: HookShell) -> String {
    match shell {
        HookShell::Bash => bash_hook(),
        HookShell::Zsh => zsh_hook(),
        HookShell::Fish => fish_hook(),
        HookShell::PowerShell => powershell_hook("powershell", "Windows PowerShell 5.1"),
        HookShell::Pwsh => powershell_hook("pwsh", "PowerShell 7 and later (pwsh)"),
        HookShell::Nu => nu_hook(),
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

/// PowerShell has no directory-change hook, so the hook wraps `prompt`.
///
/// `edition` names the shell flag to pass back to `nvault env`; `label` is the
/// human-readable edition for the header comment. The body uses only syntax
/// that Windows PowerShell 5.1 and PowerShell 7 both accept.
fn powershell_hook(edition: &str, label: &str) -> String {
    let template = r#"# nvault directory hook for __LABEL__.
# Install it once from the profile named by $PROFILE:
#   Invoke-Expression (& nvault hook __EDITION__ | Out-String)
# It sets NVAULT_DIR on a directory change and removes the names in
# NVAULT_LOADED_KEYS first. Values load only while NVAULT_AUTOLOAD = '1'.
function global:_nvault_hook {
    if ($env:NVAULT_LAST_DIR -eq $PWD.Path) { return }
    $env:NVAULT_LAST_DIR = $PWD.Path
    $root = ''
    try { $root = [string](& nvault dir 2>$null | Select-Object -First 1) } catch { $root = '' }
    $root = $root.Trim()
    if ($root) {
        $env:NVAULT_DIR = $root
    } else {
        Remove-Item Env:\NVAULT_DIR -ErrorAction SilentlyContinue
    }
    if ($env:NVAULT_LOADED_KEYS) {
        foreach ($key in ($env:NVAULT_LOADED_KEYS -split ' ')) {
            if ($key -match '^[A-Za-z_][A-Za-z0-9_]*$') {
                Remove-Item -LiteralPath ('Env:\' + $key) -ErrorAction SilentlyContinue
            }
        }
        Remove-Item Env:\NVAULT_LOADED_KEYS -ErrorAction SilentlyContinue
    }
    if ($root -and $env:NVAULT_AUTOLOAD -eq '1') {
        $script = ''
        $encoding = $null
        try {
            $encoding = [Console]::OutputEncoding
            [Console]::OutputEncoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
            $script = (& nvault env --shell __EDITION__ 2>$null | Out-String)
        } catch {
            $script = ''
        } finally {
            if ($encoding) {
                try { [Console]::OutputEncoding = $encoding } catch { }
            }
        }
        if ($script.Trim()) { Invoke-Expression $script }
    }
}
if (-not $global:_nvault_prompt_hooked) {
    $global:_nvault_prompt_hooked = $true
    $global:_nvault_prompt_previous = $function:prompt
    function global:prompt {
        _nvault_hook
        if ($global:_nvault_prompt_previous) {
            & $global:_nvault_prompt_previous
        } else {
            "PS $($PWD.Path)> "
        }
    }
}
_nvault_hook
"#;
    template
        .replace("__LABEL__", label)
        .replace("__EDITION__", edition)
}

/// Nushell has no `eval`, so the hook decodes the JSON that `env --shell nu`
/// prints and applies it with `load-env`.
fn nu_hook() -> String {
    r#"# nvault directory hook for Nushell.
# Save it once and source that file from config.nu:
#   nvault hook nu | save -f ~/.config/nvault/nvault.nu
#   source ~/.config/nvault/nvault.nu
# It sets NVAULT_DIR on a directory change and hides the names in
# NVAULT_LOADED_KEYS first. Values load only while NVAULT_AUTOLOAD = '1'.
def --env _nvault_hook [] {
    if (($env.NVAULT_LAST_DIR? | default '') == ($env.PWD | into string)) { return }
    $env.NVAULT_LAST_DIR = ($env.PWD | into string)
    let probe = (try { ^nvault dir | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
    let root = if $probe.exit_code == 0 { ($probe.stdout | str trim) } else { '' }
    if ($root | is-empty) {
        hide-env -i NVAULT_DIR
    } else {
        $env.NVAULT_DIR = $root
    }
    if (($env.NVAULT_LOADED_KEYS? | default '') | is-not-empty) {
        for key in ($env.NVAULT_LOADED_KEYS | split row ' ') {
            if (($key | is-not-empty) and ($key =~ '^[A-Za-z_][A-Za-z0-9_]*$')) {
                hide-env -i $key
            }
        }
        hide-env -i NVAULT_LOADED_KEYS
    }
    if ((not ($root | is-empty)) and (($env.NVAULT_AUTOLOAD? | default '0') == '1')) {
        let loaded = (try { ^nvault env --shell nu | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
        if $loaded.exit_code == 0 {
            let values = (try { $loaded.stdout | from json } catch { {} })
            if ($values | is-not-empty) { load-env $values }
        }
    }
}
if (($env.NVAULT_NU_HOOK? | default '0') != '1') {
    $env.NVAULT_NU_HOOK = '1'
    $env.config = ($env.config | upsert hooks.pre_prompt (
        ($env.config.hooks?.pre_prompt? | default []) | append {|| _nvault_hook }
    ))
}
_nvault_hook
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Export, hook, quote_fish, quote_posix, quote_powershell, render_env};
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
        for shell in [
            HookShell::Bash,
            HookShell::Zsh,
            HookShell::Fish,
            HookShell::PowerShell,
            HookShell::Pwsh,
            HookShell::Nu,
        ] {
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

    #[test]
    fn every_hook_is_complete_and_names_its_install_step() {
        for shell in [
            HookShell::Bash,
            HookShell::Zsh,
            HookShell::Fish,
            HookShell::PowerShell,
            HookShell::Pwsh,
            HookShell::Nu,
        ] {
            let script = hook(shell);
            assert!(!script.contains("__EDITION__"), "{shell:?} placeholder");
            assert!(!script.contains("__LABEL__"), "{shell:?} placeholder");
            assert!(script.contains("NVAULT_DIR"), "{shell:?} tracks the root");
        }
        assert!(hook(HookShell::PowerShell).contains("Windows PowerShell 5.1"));
        assert!(hook(HookShell::Pwsh).contains("PowerShell 7"));
        assert!(hook(HookShell::PowerShell).contains("nvault hook powershell"));
        assert!(hook(HookShell::Pwsh).contains("nvault hook pwsh"));
        assert!(hook(HookShell::Nu).contains("source ~/.config/nvault/nvault.nu"));
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

    #[test]
    fn powershell_quoting_handles_single_quotes_and_newlines() {
        assert_eq!(quote_powershell("a'b"), "'a''b'");
        assert_eq!(quote_powershell("a\nb"), "'a\nb'");
        assert_eq!(quote_powershell("$env:X `id`"), "'$env:X `id`'");
    }

    #[test]
    fn powershell_export_stays_a_literal_string() {
        let payload = "x'; New-Item -ItemType File -Path 'PWNED-MARKER' -Force; #";
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(payload.as_bytes().to_vec()),
        }];
        for shell in [EnvShell::PowerShell, EnvShell::Pwsh] {
            let output = render_env(&exports, shell).expect("env");
            let line = output
                .lines()
                .find(|line| line.starts_with("$env:TOKEN = "))
                .expect("assignment");
            assert_eq!(line, format!("$env:TOKEN = {}", quote_powershell(payload)));
            assert!(
                !line.contains("x';"),
                "the quote that could end the string is not doubled: {line}"
            );
            assert!(line.ends_with("#'"), "{line}");
            assert_eq!(
                output
                    .lines()
                    .filter(|line| line.starts_with("$env:TOKEN"))
                    .count(),
                1,
                "an export must stay one assignment"
            );
        }
    }

    #[test]
    fn nu_exports_are_json_data() {
        let payload = "x'); touch PWNED-MARKER; # héllo\nnext";
        let exports = vec![Export {
            name: "TOKEN".to_owned(),
            value: Secret::new(payload.as_bytes().to_vec()),
        }];
        let output = render_env(&exports, EnvShell::Nu).expect("env");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("nu output is one JSON object");
        assert_eq!(value["TOKEN"], payload);
        assert_eq!(value["NVAULT_LOADED_KEYS"], "TOKEN");
        assert!(!output.contains("export"));
        assert!(!output.contains("$env:"));
    }

    #[test]
    fn powershell_hook_validates_names_before_removing_them() {
        for edition in [HookShell::PowerShell, HookShell::Pwsh] {
            let script = hook(edition);
            assert!(
                script.contains("'^[A-Za-z_][A-Za-z0-9_]*$'"),
                "{edition:?} removes the name guard"
            );
            assert!(
                script.contains("-LiteralPath"),
                "{edition:?} removes literal path handling"
            );
            assert!(
                script.contains("$global:_nvault_prompt_previous = $function:prompt"),
                "{edition:?} does not preserve the prompt"
            );
        }
    }

    #[test]
    fn nu_hook_applies_json_instead_of_evaluating_code() {
        let script = hook(HookShell::Nu);
        assert!(script.contains("from json"));
        assert!(script.contains("load-env"));
        assert!(!script.contains("eval"), "Nushell hook evaluates text");
        assert!(script.contains("'^[A-Za-z_][A-Za-z0-9_]*$'"));
    }

    fn temp_base(label: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "nvault-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("temp base");
        base
    }

    /// Returns whether `name --version` runs.
    ///
    /// The generation tests always run; the execution tests are skipped with an
    /// explicit note when the binary is absent. This environment had no `pwsh`
    /// or `nu`, so those paths were not executed here.
    #[cfg(unix)]
    fn shell_binary(name: &str) -> Option<String> {
        let output = std::process::Command::new(name)
            .arg("--version")
            .output()
            .ok()?;
        if output.status.success() {
            Some(name.to_owned())
        } else {
            None
        }
    }

    /// Writes a fake `nvault` that answers `dir` and `env`.
    #[cfg(unix)]
    fn fake_nvault(dir: &std::path::Path, env_body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("nvault");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  dir) printf '%s\\n' \"$FAKE_NVAULT_DIR\" ;;\n  env) cat <<'NVAULT_FAKE_ENV_END'\n{env_body}NVAULT_FAKE_ENV_END\n  ;;\n  *) exit 2 ;;\nesac\n"
            ),
        )
        .expect("fake nvault");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("chmod fake nvault");
        path
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_loads_and_cleans_exports_when_pwsh_is_available() {
        use std::process::Command;

        let Some(pwsh) = shell_binary("pwsh") else {
            // No pwsh here: the generation and escaping tests above still
            // cover the script, and the README states that execution against a
            // real PowerShell was not exercised in this environment.
            let script = hook(HookShell::Pwsh);
            assert!(script.contains("NVAULT_AUTOLOAD"));
            assert!(script.contains("$env:NVAULT_DIR"));
            return;
        };

        let base = temp_base("pwsh-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let marker = base.join("injected");
        let payload = format!(
            "x'; New-Item -ItemType File -Path '{}' -Force; #",
            marker.display()
        );
        let rendered = render_env(
            &[
                Export {
                    name: "FAKE_SECRET".to_owned(),
                    value: Secret::new(payload.as_bytes().to_vec()),
                },
                Export {
                    name: "SECOND_KEY".to_owned(),
                    value: Secret::new(b"second".to_vec()),
                },
            ],
            EnvShell::Pwsh,
        )
        .expect("env");
        fake_nvault(&bin, &rendered);

        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let hook_file = base.join("hook.ps1");
        std::fs::write(&hook_file, hook(HookShell::Pwsh)).expect("hook file");

        let script = r#"
$ErrorActionPreference = 'Stop'
function global:prompt { 'ORIGINAL> ' }
$env:PATH = '__BIN__' + [IO.Path]::PathSeparator + $env:PATH
$env:FAKE_NVAULT_DIR = '__ROOT__'
$env:NVAULT_AUTOLOAD = '1'
. '__HOOK__'
_nvault_hook
if ((prompt) -ne 'ORIGINAL> ') { exit 26 }
if ($env:FAKE_SECRET -ne [IO.File]::ReadAllText('__PAYLOAD__')) { exit 20 }
if ($env:NVAULT_LOADED_KEYS -ne 'FAKE_SECRET SECOND_KEY') { exit 21 }
if (Test-Path -LiteralPath '__MARKER__') { exit 24 }
$env:NVAULT_AUTOLOAD = '0'
Set-Location -LiteralPath '__OTHER__'
_nvault_hook
if (Test-Path Env:\FAKE_SECRET) { exit 22 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 23 }
"#
        .replace("__BIN__", &bin.display().to_string())
        .replace("__ROOT__", &root.display().to_string())
        .replace("__OTHER__", &other.display().to_string())
        .replace("__HOOK__", &hook_file.display().to_string())
        .replace("__PAYLOAD__", &payload_file.display().to_string())
        .replace("__MARKER__", &marker.display().to_string());
        let script_file = base.join("test.ps1");
        std::fs::write(&script_file, script).expect("test script");

        let output = Command::new(pwsh)
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(&script_file)
            .current_dir(&base)
            .output()
            .expect("run pwsh");
        assert!(
            output.status.success(),
            "pwsh hook transition failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!marker.exists(), "a rendered value executed as code");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_loads_and_cleans_exports_when_nu_is_available() {
        use std::process::Command;

        let Some(nu) = shell_binary("nu") else {
            let script = hook(HookShell::Nu);
            assert!(script.contains("NVAULT_AUTOLOAD"));
            assert!(script.contains("load-env"));
            return;
        };

        let base = temp_base("nu-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let marker = base.join("injected");
        let payload = format!("x'); touch {}; # héllo\nnext", marker.display());
        let rendered = render_env(
            &[
                Export {
                    name: "FAKE_SECRET".to_owned(),
                    value: Secret::new(payload.as_bytes().to_vec()),
                },
                Export {
                    name: "SECOND_KEY".to_owned(),
                    value: Secret::new(b"second".to_vec()),
                },
            ],
            EnvShell::Nu,
        )
        .expect("env");
        fake_nvault(&bin, &rendered);

        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let hook_file = base.join("hook.nu");
        std::fs::write(&hook_file, hook(HookShell::Nu)).expect("hook file");

        let script = r#"
$env.PATH = ($env.PATH | prepend '__BIN__')
$env.FAKE_NVAULT_DIR = '__ROOT__'
$env.NVAULT_AUTOLOAD = '1'
source '__HOOK__'
_nvault_hook
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) { exit 25 }
source '__HOOK__'
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) { exit 26 }
if (($env.FAKE_SECRET? | default '') != (open --raw '__PAYLOAD__')) { exit 20 }
if (($env.NVAULT_LOADED_KEYS? | default '') != 'FAKE_SECRET SECOND_KEY') { exit 21 }
if ('__MARKER__' | path exists) { exit 24 }
$env.NVAULT_AUTOLOAD = '0'
cd '__OTHER__'
_nvault_hook
if (($env.FAKE_SECRET? | default '') | is-not-empty) { exit 22 }
if (($env.NVAULT_LOADED_KEYS? | default '') | is-not-empty) { exit 23 }
"#
        .replace("__BIN__", &bin.display().to_string())
        .replace("__ROOT__", &root.display().to_string())
        .replace("__OTHER__", &other.display().to_string())
        .replace("__HOOK__", &hook_file.display().to_string())
        .replace("__PAYLOAD__", &payload_file.display().to_string())
        .replace("__MARKER__", &marker.display().to_string());

        let output = Command::new(nu)
            .arg("--no-config-file")
            .arg("--commands")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run nu");
        assert!(
            output.status.success(),
            "nu hook transition failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!marker.exists(), "a rendered value executed as code");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }
}
