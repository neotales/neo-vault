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
/// `EnvShell::Nu` and `EnvShell::Json` render a JSON object instead of
/// statements: Nushell has no `eval`, and the PowerShell hook applies the JSON
/// as data rather than executing it. The object also carries
/// `NVAULT_LOADED_KEYS` as a space-separated string.
///
/// Every export name must be a plain environment identifier and must not be
/// one of the names this module manages, because the name is written into
/// shell code.
///
/// # Errors
///
/// Returns an error when a name is not a plain identifier, collides with a
/// reserved `nvault` name, when a value is not UTF-8, or when a value contains
/// NUL.
pub fn render_env(exports: &[Export], shell: EnvShell) -> Result<String> {
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(exports.len() + 1);
    for export in exports {
        validate_export_name(&export.name)?;
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

    if matches!(shell, EnvShell::Nu | EnvShell::Json) {
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
            EnvShell::Nu | EnvShell::Json => {
                unreachable!("JSON shells are rendered before this loop")
            }
        }
        .map_err(|_| Error::new("cannot render shell exports"))?;
    }
    Ok(output)
}

/// Names the hooks read or write themselves.
const RESERVED_NAMES: [&str; 4] = [
    "NVAULT_AUTOLOAD",
    "NVAULT_DIR",
    "NVAULT_LAST_DIR",
    "NVAULT_LOADED_KEYS",
];

/// Rejects a name that must not become shell code or hook bookkeeping.
fn validate_export_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid {
        // Do not echo the name: it is untrusted and may contain control bytes.
        return Err(Error::new(
            "refusing an export whose name is not a plain environment identifier",
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(Error::new(format!(
            "refusing an export named {name}, which nvault reserves"
        )));
    }
    Ok(())
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
/// PowerShell reads five characters as a single quote: `'`, U+2018 (left
/// single quotation mark), U+2019 (right single quotation mark), U+201A
/// (single low-9 quotation mark), and U+201B (single high-reversed-9 quotation
/// mark). Any of them closes a quoted string, so each is doubled. `$`,
/// backticks, and newlines stay inside the literal string.
///
/// The set matches `CharTraits.IsSingleQuote` in the PowerShell source. The
/// runtime regression tests in this module execute a value containing U+2019.
#[must_use]
pub fn quote_powershell(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('\'');
    for character in value.chars() {
        if is_powershell_single_quote(character) {
            output.push(character);
        }
        output.push(character);
    }
    output.push('\'');
    output
}

/// Returns whether PowerShell treats `character` as a single-quote delimiter.
fn is_powershell_single_quote(character: char) -> bool {
    matches!(
        character,
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}'
    )
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
/// Windows PowerShell 5.1 and PowerShell 7 alike. They apply `env --shell
/// json` as data instead of evaluating it. The Nushell hook registers a
/// `pre_prompt` hook and also loads that JSON with `load-env`; Nushell has no
/// `eval`, so no provider output is executed as code.
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
  local dir="${PWD:-}"
  local root output
  [ "$dir" = "${NVAULT_LAST_DIR:-}" ] && return 0
  if ! root="$(nvault dir 2>/dev/null)"; then
    return 0
  fi
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
  else
    unset NVAULT_DIR
  fi
  if [ -n "${NVAULT_LOADED_KEYS:-}" ]; then
    local key
    read -r -a _nvault_keys <<< "$NVAULT_LOADED_KEYS"
    for key in "${_nvault_keys[@]}"; do
      case "$key" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) continue ;;
      esac
      unset "$key"
    done
    unset _nvault_keys
    unset NVAULT_LOADED_KEYS
  fi
  if [ "${NVAULT_AUTOLOAD:-0}" = "1" ] && [ -n "$root" ]; then
    if ! output="$(nvault env --shell bash 2>/dev/null)"; then
      printf '%s\n' 'nvault: could not load this directory; will retry' >&2
      return 0
    fi
    eval "$output"
  fi
  NVAULT_LAST_DIR="$dir"
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
  local dir="$PWD"
  local root output key
  if [ "$dir" = "${NVAULT_LAST_DIR:-}" ]; then return 0; fi
  if ! root="$(nvault dir 2>/dev/null)"; then
    return 0
  fi
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
  else
    unset NVAULT_DIR
  fi
  if [ -n "${NVAULT_LOADED_KEYS:-}" ]; then
    for key in ${(z)NVAULT_LOADED_KEYS}; do
      case "$key" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) continue ;;
      esac
      unset "$key"
    done
    unset NVAULT_LOADED_KEYS
  fi
  if [ "${NVAULT_AUTOLOAD:-0}" = "1" ] && [ -n "$root" ]; then
    if ! output="$(nvault env --shell zsh 2>/dev/null)"; then
      print -u2 'nvault: could not load this directory; will retry'
      return 0
    fi
    eval "$output"
  fi
  NVAULT_LAST_DIR="$dir"
}
typeset -ga chpwd_functions
if (( ${chpwd_functions[(I)_nvault_hook]:-0} == 0 )); then
  chpwd_functions+=(_nvault_hook)
fi
_nvault_hook
"#
    .to_owned()
}

fn fish_hook() -> String {
    r#"function _nvault_hook --on-variable PWD --on-event fish_prompt
    set -l dir $PWD
    if set -q NVAULT_LAST_DIR; and test "$NVAULT_LAST_DIR" = "$dir"
        return
    end
    set -l root (nvault dir 2>/dev/null)
    if test $status -ne 0
        return
    end
    if test -n "$root"
        set -gx NVAULT_DIR $root
    else
        set -e NVAULT_DIR
    end
    if set -q NVAULT_LOADED_KEYS
        for key in (string split ' ' -- $NVAULT_LOADED_KEYS)
            if string match -qr '^[A-Za-z_][A-Za-z0-9_]*$' -- $key
                set -e $key
            end
        end
        set -e NVAULT_LOADED_KEYS
    end
    if test "$NVAULT_AUTOLOAD" = "1"; and test -n "$root"
        set -l output (nvault env --shell fish 2>/dev/null)
        if test $status -ne 0
            echo 'nvault: could not load this directory; will retry' >&2
            return
        end
        printf '%s\n' $output | source
    end
    set -g NVAULT_LAST_DIR $dir
end
_nvault_hook
"#
    .to_owned()
}

/// PowerShell has no directory-change hook, so the hook wraps `prompt`.
///
/// `edition` is the name used in the install comment; `label` is the
/// human-readable edition for the header. The body uses only syntax that
/// Windows PowerShell 5.1 and PowerShell 7 both accept.
///
/// The hook never evaluates provider output: `env --shell json` produces a
/// JSON object and the hook copies its properties into `Env:` after validating
/// each name. `$global:_nvault_last_dir` is a shell-local variable, so a child
/// PowerShell starts with its own state.
fn powershell_hook(edition: &str, label: &str) -> String {
    let template = r#"# nvault directory hook for __LABEL__.
# Install it once from the profile named by $PROFILE:
#   Invoke-Expression (& nvault hook __EDITION__ | Out-String)
# It sets NVAULT_DIR on a directory change and removes the names in
# NVAULT_LOADED_KEYS first. Values load only while NVAULT_AUTOLOAD = '1'.
function global:_nvault_hook {
    $here = $PWD.Path
    if ($global:_nvault_last_dir -eq $here) { return }
    $probe = $null
    try { $probe = & nvault dir 2>$null } catch { return }
    if ($LASTEXITCODE -ne 0) { return }
    $root = ([string]($probe | Select-Object -First 1)).Trim()
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
        $json = ''
        $encoding = $null
        try {
            $encoding = [Console]::OutputEncoding
            [Console]::OutputEncoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
            $json = (& nvault env --shell json 2>$null | Out-String)
        } catch {
            $json = ''
        } finally {
            if ($encoding) {
                try { [Console]::OutputEncoding = $encoding } catch { }
            }
        }
        $values = $null
        if ($LASTEXITCODE -ne 0 -or -not $json.Trim()) {
            $values = $null
        } else {
            try { $values = $json | ConvertFrom-Json } catch { $values = $null }
        }
        if ($null -eq $values) {
            [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
            return
        }
        foreach ($property in $values.PSObject.Properties) {
            if ($property.Name -match '^[A-Za-z_][A-Za-z0-9_]*$') {
                Set-Item -LiteralPath ('Env:\' + $property.Name) -Value ([string]$property.Value)
            }
        }
    }
    $global:_nvault_last_dir = $here
}
if (-not $global:_nvault_prompt_hooked) {
    $global:_nvault_prompt_hooked = $true
    Remove-Item Env:\NVAULT_LAST_DIR -ErrorAction SilentlyContinue
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

/// Nushell has no `eval`, so the hook decodes the JSON that `env --shell json`
/// prints and applies it with `load-env`.
///
/// Nushell keeps no shell-local variable across `source` calls, so the install
/// marker and the last directory are keyed by `$nu.pid`: a child shell inherits
/// the parent's value, sees a different pid, and installs its own hook.
fn nu_hook() -> String {
    r#"# nvault directory hook for Nushell.
# Save it once and source that file from config.nu:
#   nvault hook nu | save -f ~/.config/nvault/nvault.nu
#   source ~/.config/nvault/nvault.nu
# It sets NVAULT_DIR on a directory change and hides the names in
# NVAULT_LOADED_KEYS first. Values load only while NVAULT_AUTOLOAD = '1'.
def --env _nvault_hook [] {
    let here = (($nu.pid | into string) + '|' + ($env.PWD | into string))
    if (($env.NVAULT_LAST_DIR? | default '') == $here) { return }
    let probe = (try { ^nvault dir | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
    if $probe.exit_code != 0 { return }
    let root = ($probe.stdout | str trim)
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
        let loaded = (try { ^nvault env --shell json | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
        if $loaded.exit_code != 0 {
            print -e 'nvault: could not load this directory; will retry'
            return
        }
        let values = (try { $loaded.stdout | from json } catch { {} })
        if ($values | is-not-empty) { load-env $values }
    }
    $env.NVAULT_LAST_DIR = $here
}
let marker_ok = (($env.NVAULT_NU_HOOK? | default '') == ($nu.pid | into string))
let hook_ok = ((($env.config.hooks?.pre_prompt? | default []) | length) > 0)
if (not ($marker_ok and $hook_ok)) {
    $env.NVAULT_NU_HOOK = ($nu.pid | into string)
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

    const ALL_ENV_SHELLS: [EnvShell; 7] = [
        EnvShell::Bash,
        EnvShell::Zsh,
        EnvShell::Fish,
        EnvShell::PowerShell,
        EnvShell::Pwsh,
        EnvShell::Nu,
        EnvShell::Json,
    ];
    const ALL_HOOK_SHELLS: [HookShell; 6] = [
        HookShell::Bash,
        HookShell::Zsh,
        HookShell::Fish,
        HookShell::PowerShell,
        HookShell::Pwsh,
        HookShell::Nu,
    ];

    fn export(name: &str, value: &str) -> Export {
        Export {
            name: name.to_owned(),
            value: Secret::new(value.as_bytes().to_vec()),
        }
    }

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
    fn powershell_quoting_doubles_every_recognized_quote() {
        assert_eq!(quote_powershell("a'b"), "'a''b'");
        assert_eq!(quote_powershell("a\nb"), "'a\nb'");
        assert_eq!(quote_powershell("$env:X `id`"), "'$env:X `id`'");
        // U+2018, U+2019, U+201A, U+201B are single quotes to PowerShell.
        assert_eq!(
            quote_powershell("‘a’b‚c‛d"),
            "'‘‘a’’b‚‚c‛‛d'",
            "a smart single quote must be doubled"
        );
    }

    #[test]
    fn powershell_export_with_a_smart_quote_cannot_terminate_the_string() {
        let payload = "x’ ; New-Item -ItemType File -Path 'PWNED-MARKER' -Force; ’y";
        let rendered = render_env(&[export("TOKEN", payload)], EnvShell::Pwsh).expect("env");
        let line = rendered
            .lines()
            .find(|line| line.starts_with("$env:TOKEN = "))
            .expect("assignment");
        assert_eq!(line, format!("$env:TOKEN = {}", quote_powershell(payload)));
        assert!(
            !line.contains("x’ ;"),
            "an undoubled smart quote remains: {line}"
        );
        assert!(line.ends_with("’y'"), "{line}");
    }

    #[test]
    fn render_env_rejects_names_that_are_not_identifiers() {
        for shell in ALL_ENV_SHELLS {
            for name in ["BAD-NAME", "1BAD", "", "A B", "A;id", "PÄTH"] {
                assert!(
                    render_env(&[export(name, "value")], shell).is_err(),
                    "{shell:?} accepted the name {name:?}"
                );
            }
        }
    }

    #[test]
    fn render_env_rejects_reserved_nvault_names() {
        for shell in ALL_ENV_SHELLS {
            for name in [
                "NVAULT_AUTOLOAD",
                "NVAULT_DIR",
                "NVAULT_LAST_DIR",
                "NVAULT_LOADED_KEYS",
            ] {
                let error = render_env(&[export(name, "value")], shell)
                    .expect_err("reserved name must fail");
                assert!(error.to_string().contains("reserves"), "{shell:?}: {error}");
            }
        }
    }

    #[test]
    fn nu_and_json_outputs_match() {
        let exports = [export("TOKEN", "value"), export("OTHER", "two")];
        let nu = render_env(&exports, EnvShell::Nu).expect("nu");
        let json = render_env(&exports, EnvShell::Json).expect("json");
        assert_eq!(nu, json);
        let value: serde_json::Value = serde_json::from_str(&json).expect("json object");
        assert_eq!(value["TOKEN"], "value");
        assert_eq!(value["NVAULT_LOADED_KEYS"], "TOKEN OTHER");
    }

    #[test]
    fn nu_exports_are_json_data() {
        let payload = "x'); touch PWNED-MARKER; # héllo\nnext";
        let output = render_env(&[export("TOKEN", payload)], EnvShell::Nu).expect("env");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("nu output is one JSON object");
        assert_eq!(value["TOKEN"], payload);
        assert!(!output.contains("export"));
        assert!(!output.contains("$env:"));
    }

    #[test]
    fn hooks_clean_loaded_names_before_considering_autoload() {
        for shell in ALL_HOOK_SHELLS {
            let script = hook(shell);
            let cleanup = script.find("NVAULT_LOADED_KEYS").expect("cleanup");
            let autoload = script.find("NVAULT_AUTOLOAD").expect("autoload check");
            assert!(
                cleanup < autoload,
                "{shell:?} checks autoload before cleanup"
            );
        }
    }

    #[test]
    fn hooks_record_the_directory_only_after_a_successful_load() {
        for shell in ALL_HOOK_SHELLS {
            let script = hook(shell);
            let autoload = script.find("NVAULT_AUTOLOAD").expect("autoload");
            let assignment = script.rfind("NVAULT_LAST_DIR").expect("last dir");
            assert!(
                assignment > autoload,
                "{shell:?} records the directory before loading"
            );
            assert!(
                script.contains("will retry"),
                "{shell:?} has no redacted retry diagnostic"
            );
        }
    }

    #[test]
    fn every_hook_is_complete_and_names_its_install_step() {
        for shell in ALL_HOOK_SHELLS {
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
    fn powershell_hook_applies_json_instead_of_evaluating_it() {
        for edition in [HookShell::PowerShell, HookShell::Pwsh] {
            let script = hook(edition);
            assert!(
                !script.contains("Invoke-Expression $json"),
                "{edition:?} evaluates provider output"
            );
            assert!(
                !script.contains("Invoke-Expression $script"),
                "{edition:?} evaluates provider output"
            );
            assert!(
                script.contains("ConvertFrom-Json"),
                "{edition:?} parses data"
            );
            assert!(script.contains("Set-Item"), "{edition:?} sets Env: entries");
            assert!(
                script.contains("$global:_nvault_last_dir"),
                "{edition:?} uses shell-local state"
            );
        }
    }

    #[test]
    fn nu_hook_registers_per_shell_and_never_evaluates() {
        let script = hook(HookShell::Nu);
        assert!(script.contains("from json"));
        assert!(script.contains("load-env"));
        assert!(!script.contains("eval"), "Nushell hook evaluates text");
        assert!(script.contains("'^[A-Za-z_][A-Za-z0-9_]*$'"));
        assert!(
            script.contains(
                "let marker_ok = (($env.NVAULT_NU_HOOK? | default '') == ($nu.pid | into string))"
            ),
            "the install marker is not keyed to the shell process"
        );
        assert!(
            script.contains(
                "let hook_ok = ((($env.config.hooks?.pre_prompt? | default []) | length) > 0)"
            ),
            "the hook config is not inspected"
        );
        assert!(
            script.contains("if (not ($marker_ok and $hook_ok))"),
            "a missing hook is not repaired"
        );
        assert!(
            !script.contains("| default '0') != '1'"),
            "the inherited marker still skips a child shell"
        );
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
    /// Generation tests always run; execution tests skip with an explicit
    /// limitation when the binary is absent.
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
    ///
    /// With a counter, the first `failures` calls to `env` exit 1 and print a
    /// transient error, so a retry can be observed.
    #[cfg(unix)]
    fn fake_nvault(
        dir: &std::path::Path,
        env_body: &str,
        counter: Option<&std::path::Path>,
        failures: usize,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let count = counter
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let path = dir.join("nvault");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  dir) printf '%s\\n' \"$FAKE_NVAULT_DIR\" ;;\n  env)\n    COUNT='{count}'\n    FAILS={failures}\n    if [ -n \"$COUNT\" ]; then\n      n=0\n      [ -f \"$COUNT\" ] && n=$(cat \"$COUNT\")\n      n=$((n + 1))\n      printf '%s' \"$n\" > \"$COUNT\"\n      if [ \"$n\" -le \"$FAILS\" ]; then\n        printf '%s\\n' 'transient failure' >&2\n        exit 1\n      fi\n    fi\n    cat <<'NVAULT_FAKE_ENV_END'\n{env_body}NVAULT_FAKE_ENV_END\n    ;;\n  *) exit 2 ;;\nesac\n"
            ),
        )
        .expect("fake nvault");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("chmod fake nvault");
        path
    }

    #[cfg(unix)]
    fn write_hook(base: &std::path::Path, shell: HookShell, name: &str) -> std::path::PathBuf {
        let path = base.join(name);
        std::fs::write(&path, hook(shell)).expect("hook file");
        path
    }

    #[cfg(unix)]
    fn run(
        shell: &str,
        argument: &str,
        script: &std::path::Path,
        base: &std::path::Path,
    ) -> std::process::Output {
        std::process::Command::new(shell)
            .arg(argument)
            .arg(script)
            .current_dir(base)
            .output()
            .expect("run the shell")
    }

    #[cfg(unix)]
    fn assert_ok(output: &std::process::Output, label: &str) {
        assert!(
            output.status.success(),
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn bash_hook_cleans_exports_when_autoload_is_disabled() {
        let base = temp_base("bash-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Bash).expect("env");
        fake_nvault(&bin, &rendered, None, 0);
        let hook_file = write_hook(&base, HookShell::Bash, "hook.bash");
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

        let output = run("bash", "--noprofile", &script, &base);
        assert_ok(&output, "bash hook");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn bash_hook_retries_the_same_directory_after_a_transient_failure() {
        let base = temp_base("bash-retry");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Bash).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1);
        let hook_file = write_hook(&base, HookShell::Bash, "hook.bash");
        let script = base.join("test.bash");
        std::fs::write(
            &script,
            format!(
                r#"export PATH="{}:$PATH"
export FAKE_NVAULT_DIR="{}"
export NVAULT_AUTOLOAD=1
source "{}"
[ -z "${{NVAULT_LAST_DIR+x}}" ] || exit 30
[ -z "${{FAKE_SECRET+x}}" ] || exit 31
_nvault_hook
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 20
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
            ),
        )
        .expect("test script");

        let output = run("bash", "--noprofile", &script, &base);
        assert_ok(&output, "bash retry");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn zsh_hook_loads_and_cleans_exports_when_zsh_is_available() {
        let Some(zsh) = shell_binary("zsh") else {
            assert!(hook(HookShell::Zsh).contains("chpwd_functions"));
            return;
        };
        let base = temp_base("zsh-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Zsh).expect("env");
        fake_nvault(&bin, &rendered, None, 0);
        let hook_file = write_hook(&base, HookShell::Zsh, "hook.zsh");
        let script = base.join("test.zsh");
        std::fs::write(
            &script,
            format!(
                r#"export PATH="{}:$PATH"
export FAKE_NVAULT_DIR="{}"
export NVAULT_AUTOLOAD=1
source "{}"
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 20
export NVAULT_AUTOLOAD=0
cd "{}"
[ -z "${{FAKE_SECRET+x}}" ] || exit 22
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                other.display(),
            ),
        )
        .expect("test script");

        let output = run(&zsh, "-f", &script, &base);
        assert_ok(&output, "zsh hook");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn zsh_hook_retries_and_registers_once() {
        let Some(zsh) = shell_binary("zsh") else {
            return;
        };
        let base = temp_base("zsh-retry");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Zsh).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1);
        let hook_file = write_hook(&base, HookShell::Zsh, "hook.zsh");
        let script = base.join("test.zsh");
        std::fs::write(
            &script,
            format!(
                r#"export PATH="{}:$PATH"
export FAKE_NVAULT_DIR="{}"
export NVAULT_AUTOLOAD=1
source "{}"
[ -z "${{NVAULT_LAST_DIR+x}}" ] || exit 30
[ -z "${{FAKE_SECRET+x}}" ] || exit 31
_nvault_hook
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 20
source "{}"
(( $#chpwd_functions == 1 )) || exit 27
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                hook_file.display(),
            ),
        )
        .expect("test script");

        let output = run(&zsh, "-f", &script, &base);
        assert_ok(&output, "zsh retry");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn fish_hook_retries_the_same_directory_after_a_transient_failure() {
        let Some(fish) = shell_binary("fish") else {
            return;
        };
        let base = temp_base("fish-retry");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Fish).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1);
        let hook_file = write_hook(&base, HookShell::Fish, "hook.fish");
        let script = base.join("test.fish");
        std::fs::write(
            &script,
            format!(
                r#"set -gx PATH "{}" $PATH
set -gx FAKE_NVAULT_DIR "{}"
set -gx NVAULT_AUTOLOAD 1
source "{}"
not set -q NVAULT_LAST_DIR; or exit 30
not set -q FAKE_SECRET; or exit 31
_nvault_hook
test "$FAKE_SECRET" = "loaded"; or exit 20
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
            ),
        )
        .expect("test script");

        let output = run(&fish, "--no-config", &script, &base);
        assert_ok(&output, "fish retry");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn fish_hook_loads_and_cleans_exports_when_fish_is_available() {
        let Some(fish) = shell_binary("fish") else {
            assert!(hook(HookShell::Fish).contains("--on-variable PWD"));
            return;
        };
        let base = temp_base("fish-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Fish).expect("env");
        fake_nvault(&bin, &rendered, None, 0);
        let hook_file = write_hook(&base, HookShell::Fish, "hook.fish");
        let script = base.join("test.fish");
        std::fs::write(
            &script,
            format!(
                r#"set -gx PATH "{}" $PATH
set -gx FAKE_NVAULT_DIR "{}"
set -gx NVAULT_AUTOLOAD 1
source "{}"
test "$FAKE_SECRET" = "loaded"; or exit 20
set -gx NVAULT_AUTOLOAD 0
cd "{}"
_nvault_hook
not set -q FAKE_SECRET; or exit 22
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                other.display(),
            ),
        )
        .expect("test script");

        let output = run(&fish, "--no-config", &script, &base);
        assert_ok(&output, "fish hook");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_loads_and_cleans_exports_when_pwsh_is_available() {
        let Some(pwsh) = shell_binary("pwsh") else {
            assert!(hook(HookShell::Pwsh).contains("NVAULT_AUTOLOAD"));
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
            "x’ ; New-Item -ItemType File -Path '{}' -Force; ’y",
            marker.display()
        );
        let rendered = render_env(
            &[
                export("FAKE_SECRET", &payload),
                export("SECOND_KEY", "second"),
            ],
            EnvShell::Json,
        )
        .expect("env");
        fake_nvault(&bin, &rendered, None, 0);

        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let hook_file = write_hook(&base, HookShell::Pwsh, "hook.ps1");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
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
            .replace("__MARKER__", &marker.display().to_string()),
        )
        .expect("test script");

        let output = std::process::Command::new(&pwsh)
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run pwsh");
        assert_ok(&output, "pwsh hook");
        assert!(!marker.exists(), "a rendered value executed as code");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn powershell_assignments_stay_literal_when_evaluated() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-quote");
        let marker = base.join("injected");
        let payload = format!(
            "a'b’c‘d‚e‛f ; New-Item -ItemType File -Path '{}' -Force; #",
            marker.display()
        );
        let rendered = render_env(&[export("FAKE_SECRET", &payload)], EnvShell::Pwsh).expect("env");
        let rendered_file = base.join("rendered.ps1");
        std::fs::write(&rendered_file, &rendered).expect("rendered file");
        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
$ErrorActionPreference = 'Stop'
Invoke-Expression ([IO.File]::ReadAllText('__RENDERED__'))
if ($env:FAKE_SECRET -ne [IO.File]::ReadAllText('__PAYLOAD__')) { exit 20 }
if (Test-Path -LiteralPath '__MARKER__') { exit 24 }
"#
            .replace("__RENDERED__", &rendered_file.display().to_string())
            .replace("__PAYLOAD__", &payload_file.display().to_string())
            .replace("__MARKER__", &marker.display().to_string()),
        )
        .expect("test script");
        let output = std::process::Command::new(&pwsh)
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run pwsh");
        assert_ok(&output, "powershell quoting");
        assert!(!marker.exists(), "a rendered value executed as code");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_retries_the_same_directory_after_a_transient_failure() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-retry");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Json).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1);
        let hook_file = write_hook(&base, HookShell::Pwsh, "hook.ps1");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
$ErrorActionPreference = 'Stop'
$env:PATH = '__BIN__' + [IO.Path]::PathSeparator + $env:PATH
$env:FAKE_NVAULT_DIR = '__ROOT__'
$env:NVAULT_AUTOLOAD = '1'
. '__HOOK__'
if ($null -ne $global:_nvault_last_dir) { exit 30 }
if (Test-Path Env:\FAKE_SECRET) { exit 31 }
_nvault_hook
if ($env:FAKE_SECRET -ne 'loaded') { exit 20 }
"#
            .replace("__BIN__", &bin.display().to_string())
            .replace("__ROOT__", &root.display().to_string())
            .replace("__HOOK__", &hook_file.display().to_string()),
        )
        .expect("test script");
        let output = std::process::Command::new(&pwsh)
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run pwsh");
        assert_ok(&output, "pwsh retry");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_loads_and_cleans_exports_when_nu_is_available() {
        let Some(nu) = shell_binary("nu") else {
            assert!(hook(HookShell::Nu).contains("load-env"));
            return;
        };
        let base = temp_base("nu-hook");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let payload = "x'); touch PWNED-MARKER; # héllo\nnext";
        let rendered = render_env(
            &[
                export("FAKE_SECRET", payload),
                export("SECOND_KEY", "second"),
            ],
            EnvShell::Json,
        )
        .expect("env");
        fake_nvault(&bin, &rendered, None, 0);

        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let hook_file = write_hook(&base, HookShell::Nu, "hook.nu");
        let script = base.join("test.nu");
        std::fs::write(
            &script,
            r#"
$env.PATH = ($env.PATH | prepend '__BIN__')
$env.FAKE_NVAULT_DIR = '__ROOT__'
$env.NVAULT_AUTOLOAD = '1'
source '__HOOK__'
_nvault_hook
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) { exit 25 }
source '__HOOK__'
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) { exit 26 }
$env.config = ($env.config | upsert hooks.pre_prompt [])
source '__HOOK__'
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) { exit 27 }
if (($env.FAKE_SECRET? | default '') != (open --raw '__PAYLOAD__')) { exit 20 }
if (($env.NVAULT_LOADED_KEYS? | default '') != 'FAKE_SECRET SECOND_KEY') { exit 21 }
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
            .replace("__PAYLOAD__", &payload_file.display().to_string()),
        )
        .expect("test script");

        let output = std::process::Command::new(&nu)
            .arg("--no-config-file")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run nu");
        assert_ok(&output, "nu hook");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_installs_in_a_nested_shell() {
        let Some(nu) = shell_binary("nu") else {
            return;
        };
        let base = temp_base("nu-nested");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Json).expect("env");
        fake_nvault(&bin, &rendered, None, 0);
        let hook_file = write_hook(&base, HookShell::Nu, "hook.nu");

        let child = base.join("child.nu");
        std::fs::write(
            &child,
            format!(
                r#"source "{}"
print (((($env.config.hooks.pre_prompt? | default []) | length)) | into string)
"#,
                hook_file.display()
            ),
        )
        .expect("child script");
        let script = base.join("parent.nu");
        std::fs::write(
            &script,
            format!(
                r#"$env.PATH = ($env.PATH | prepend '{}')
$env.FAKE_NVAULT_DIR = '{}'
$env.NVAULT_AUTOLOAD = '1'
source "{}"
if ((($env.config.hooks.pre_prompt? | default []) | length) != 1) {{ exit 20 }}
let hooks = (^{} --no-config-file "{}" | complete)
if $hooks.exit_code != 0 {{ print -e $hooks.stderr; exit 21 }}
if (($hooks.stdout | str trim) != '1') {{ exit 22 }}
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                nu,
                child.display()
            ),
        )
        .expect("parent script");

        let output = std::process::Command::new(&nu)
            .arg("--no-config-file")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run nu");
        assert_ok(&output, "nu nested install");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_retries_the_same_directory_after_a_transient_failure() {
        let Some(nu) = shell_binary("nu") else {
            return;
        };
        let base = temp_base("nu-retry");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Json).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1);
        let hook_file = write_hook(&base, HookShell::Nu, "hook.nu");
        let script = base.join("test.nu");
        std::fs::write(
            &script,
            format!(
                r#"$env.PATH = ($env.PATH | prepend '{}')
$env.FAKE_NVAULT_DIR = '{}'
$env.NVAULT_AUTOLOAD = '1'
source "{}"
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 30 }}
if (($env.FAKE_SECRET? | default '') | is-not-empty) {{ exit 31 }}
_nvault_hook
if (($env.FAKE_SECRET? | default '') != 'loaded') {{ exit 20 }}
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
            ),
        )
        .expect("test script");

        let output = std::process::Command::new(&nu)
            .arg("--no-config-file")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run nu");
        assert_ok(&output, "nu retry");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }
}
