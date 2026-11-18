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
/// statements, and `EnvShell::JsonBase64` renders the same object with each
/// value base64-encoded. The PowerShell hook uses the encoded form because
/// `ConvertFrom-Json` can reinterpret a timestamp-looking string as a
/// `DateTime`; decoding the bytes preserves the value. The object also carries
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

    if shell == EnvShell::JsonBase64 {
        return render_json_base64(&pairs);
    }
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
            EnvShell::Nu | EnvShell::Json | EnvShell::JsonBase64 => {
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

/// Renders the pairs as JSON with every value base64-encoded.
///
/// The PowerShell hook decodes these bytes, so a value such as
/// `2020-01-01T00:00:00Z` is never coerced to `DateTime` by
/// `ConvertFrom-Json`.
fn render_json_base64(pairs: &[(&str, &str)]) -> Result<String> {
    use base64::Engine as _;

    let mut object = serde_json::Map::with_capacity(pairs.len());
    for (name, value) in pairs {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        object.insert((*name).to_owned(), serde_json::Value::from(encoded));
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
  unset NVAULT_LAST_DIR
  unset NVAULT_DIR
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
  if ! root="$(nvault dir 2>/dev/null)"; then
    printf '%s\n' 'nvault: could not load this directory; will retry' >&2
    return 0
  fi
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
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
  unset NVAULT_LAST_DIR
  unset NVAULT_DIR
  if [ -n "${NVAULT_LOADED_KEYS:-}" ]; then
    for key in ${(z)NVAULT_LOADED_KEYS}; do
      case "$key" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) continue ;;
      esac
      unset "$key"
    done
    unset NVAULT_LOADED_KEYS
  fi
  if ! root="$(nvault dir 2>/dev/null)"; then
    print -u2 'nvault: could not load this directory; will retry'
    return 0
  fi
  if [ -n "$root" ]; then
    export NVAULT_DIR="$root"
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
typeset -ga chpwd_functions precmd_functions
if (( ${chpwd_functions[(I)_nvault_hook]:-0} == 0 )); then
  chpwd_functions+=(_nvault_hook)
fi
if (( ${precmd_functions[(I)_nvault_hook]:-0} == 0 )); then
  precmd_functions+=(_nvault_hook)
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
    set -e NVAULT_LAST_DIR
    set -e NVAULT_DIR
    if set -q NVAULT_LOADED_KEYS
        for key in (string split ' ' -- $NVAULT_LOADED_KEYS)
            if string match -qr '^[A-Za-z_][A-Za-z0-9_]*$' -- $key
                set -e $key
            end
        end
        set -e NVAULT_LOADED_KEYS
    end
    set -l root (nvault dir 2>/dev/null)
    if test $status -ne 0
        echo 'nvault: could not load this directory; will retry' >&2
        return
    end
    if test -n "$root"
        set -gx NVAULT_DIR $root
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
    $pending = @($global:_nvault_pending_cleanup | Where-Object { $_ })
    if ($pending.Count -gt 0) {
        $still = @()
        foreach ($name in $pending) {
            try {
                $path = 'Env:\' + $name
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -ErrorAction Stop
                }
            } catch {
                $still += $name
            }
        }
        $global:_nvault_pending_cleanup = $still
        if ($still.Count -gt 0) {
            [Console]::Error.WriteLine('nvault: could not clean up a failed load; will retry')
            return
        }
    }
    if ($global:_nvault_last_dir -ceq $here) { return }
    $global:_nvault_last_dir = $null
    Remove-Item Env:\NVAULT_DIR -ErrorAction SilentlyContinue
    if ($env:NVAULT_LOADED_KEYS) {
        foreach ($key in ($env:NVAULT_LOADED_KEYS -split ' ')) {
            if ($key -match '^[A-Za-z_][A-Za-z0-9_]*$') {
                Remove-Item -LiteralPath ('Env:\' + $key) -ErrorAction SilentlyContinue
            }
        }
        Remove-Item Env:\NVAULT_LOADED_KEYS -ErrorAction SilentlyContinue
    }
    $probe = $null
    try { $probe = & nvault dir 2>$null } catch {
        [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
        return
    }
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
        return
    }
    $root = ([string]($probe | Select-Object -First 1)).Trim()
    if ($root) { $env:NVAULT_DIR = $root }
    if ($root -and $env:NVAULT_AUTOLOAD -eq '1') {
        $json = ''
        $encoding = $null
        try {
            $encoding = [Console]::OutputEncoding
            [Console]::OutputEncoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
            $json = (& nvault env --shell json-base64 2>$null | Out-String)
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
        if ($null -eq $values -or $values -isnot [System.Management.Automation.PSCustomObject]) {
            [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
            return
        }
        $names = @()
        $tracking = $null
        $decoded = @{}
        $strict = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false, $true
        try {
            foreach ($property in $values.PSObject.Properties) {
                if ($property.Name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'invalid name' }
                if (-not ($property.Value -is [string])) { throw 'non-string value' }
                $bytes = [Convert]::FromBase64String([string]$property.Value)
                $text = $strict.GetString($bytes)
                if ($property.Name -ceq 'NVAULT_LOADED_KEYS') {
                    $tracking = $text
                } else {
                    if ($text.Length -eq 0) { throw 'empty value' }
                    $names += $property.Name
                    $decoded[$property.Name] = $text
                }
            }
            if ($null -eq $tracking) { throw 'missing tracking' }
            $tracked = @()
            if ($tracking.Length -gt 0) { $tracked = @($tracking -split ' ') }
            if ($tracked.Count -ne $names.Count) { throw 'mismatched tracking' }
            foreach ($name in $tracked) {
                if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'mismatched tracking' }
            }
            if ((($tracked | Sort-Object) -join ' ') -cne (($names | Sort-Object) -join ' ')) {
                throw 'mismatched tracking'
            }
        } catch {
            [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
            return
        }
        if ($names.Count -eq 0) {
            $global:_nvault_last_dir = $here
            return
        }
        $previous = @{}
        try {
            foreach ($name in ($names + @('NVAULT_LOADED_KEYS'))) {
                $path = 'Env:\' + $name
                if (Test-Path -LiteralPath $path) {
                    $previous[$name] = (Get-Item -LiteralPath $path -ErrorAction Stop).Value
                } else {
                    $previous[$name] = $null
                }
            }
        } catch {
            [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
            return
        }
        $global:_nvault_pending_cleanup = @($names + @('NVAULT_LOADED_KEYS'))
        $applied = @()
        try {
            foreach ($name in $names) {
                $applied += $name
                Set-Item -LiteralPath ('Env:\' + $name) -Value $decoded[$name] -ErrorAction Stop
            }
            $applied += 'NVAULT_LOADED_KEYS'
            Set-Item -LiteralPath 'Env:\NVAULT_LOADED_KEYS' -Value $tracking -ErrorAction Stop
        } catch {
            $still = @()
            foreach ($name in $applied) {
                $path = 'Env:\' + $name
                $old = $previous[$name]
                try {
                    if ($null -eq $old) {
                        if (Test-Path -LiteralPath $path) {
                            Remove-Item -LiteralPath $path -ErrorAction Stop
                        }
                    } else {
                        Set-Item -LiteralPath $path -Value $old -ErrorAction Stop
                    }
                } catch {
                    # Keep the name for the next invocation; never print the value or exception.
                    $still += $name
                }
            }
            $global:_nvault_pending_cleanup = $still
            [Console]::Error.WriteLine('nvault: could not load this directory; will retry')
            if ($still.Count -gt 0) {
                [Console]::Error.WriteLine('nvault: could not clean up a failed load; will retry')
            }
            return
        }
        $global:_nvault_pending_cleanup = @()
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
    hide-env -i NVAULT_LAST_DIR
    hide-env -i NVAULT_DIR
    if (($env.NVAULT_LOADED_KEYS? | default '') | is-not-empty) {
        for key in ($env.NVAULT_LOADED_KEYS | split row ' ') {
            if (($key | is-not-empty) and ($key =~ '^[A-Za-z_][A-Za-z0-9_]*$')) {
                hide-env -i $key
            }
        }
        hide-env -i NVAULT_LOADED_KEYS
    }
    let probe = (try { ^nvault dir | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
    if $probe.exit_code != 0 {
        print -e 'nvault: could not load this directory; will retry'
        return
    }
    let root = ($probe.stdout | str trim)
    if (not ($root | is-empty)) { $env.NVAULT_DIR = $root }
    if ((not ($root | is-empty)) and (($env.NVAULT_AUTOLOAD? | default '0') == '1')) {
        let loaded = (try { ^nvault env --shell json | complete } catch { { stdout: '', stderr: '', exit_code: 127 } })
        if $loaded.exit_code != 0 {
            print -e 'nvault: could not load this directory; will retry'
            return
        }
        let values = (try { $loaded.stdout | from json } catch { null })
        let ok = (try {
            if (not ((($values | describe) | str starts-with 'record'))) { error make { msg: 'not a record' } }
            let columns = ($values | columns)
            if (not ('NVAULT_LOADED_KEYS' in $columns)) { error make { msg: 'missing tracking' } }
            if (not ($columns | all {|column| $column =~ '^[A-Za-z_][A-Za-z0-9_]*$'})) { error make { msg: 'invalid name' } }
            if (not ($values | values | all {|value| ($value | describe) == 'string'})) { error make { msg: 'non-string value' } }
            let names = ($columns | where {|column| $column != 'NVAULT_LOADED_KEYS'})
            let tracked = (if ($values.NVAULT_LOADED_KEYS | is-empty) { [] } else { $values.NVAULT_LOADED_KEYS | split row ' ' })
            if (($tracked | length) != ($names | length)) { error make { msg: 'mismatched tracking' } }
            if (not ($tracked | all {|name| $name =~ '^[A-Za-z_][A-Za-z0-9_]*$'})) { error make { msg: 'mismatched tracking' } }
            if ((($tracked | sort) | str join ' ') != (($names | sort) | str join ' ')) { error make { msg: 'mismatched tracking' } }
            if (($names | length) > 0) { load-env $values }
            true
        } catch { false })
        if (not $ok) {
            print -e 'nvault: could not load this directory; will retry'
            return
        }
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

    const ALL_ENV_SHELLS: [EnvShell; 8] = [
        EnvShell::Bash,
        EnvShell::Zsh,
        EnvShell::Fish,
        EnvShell::PowerShell,
        EnvShell::Pwsh,
        EnvShell::Nu,
        EnvShell::Json,
        EnvShell::JsonBase64,
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
    fn json_base64_preserves_exact_values() {
        use base64::Engine as _;

        let exports = [
            export("STAMP", "2020-01-01T00:00:00Z"),
            export("UNICODE", "héllo"),
            export("EMPTY", ""),
        ];
        let output = render_env(&exports, EnvShell::JsonBase64).expect("json-base64");
        assert!(
            !output.contains("2020-01-01"),
            "the timestamp appears plainly in {output}"
        );
        let value: serde_json::Value = serde_json::from_str(&output).expect("json object");
        let decode = |name: &str| {
            let encoded = value[name].as_str().expect("base64 string");
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("base64");
            String::from_utf8(bytes).expect("utf8")
        };
        assert_eq!(decode("STAMP"), "2020-01-01T00:00:00Z");
        assert_eq!(decode("UNICODE"), "héllo");
        assert_eq!(decode("EMPTY"), "");
        assert_eq!(decode("NVAULT_LOADED_KEYS"), "STAMP UNICODE EMPTY");
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
    fn hooks_clean_before_probing_and_probe_before_autoload() {
        for shell in ALL_HOOK_SHELLS {
            let script = hook(shell);
            let cleanup = script.find("NVAULT_LOADED_KEYS").expect("cleanup");
            let probe = script.find("nvault dir ").expect("directory probe");
            let autoload = script.rfind("NVAULT_AUTOLOAD").expect("autoload check");
            assert!(cleanup < probe, "{shell:?} probes before cleaning exports");
            assert!(probe < autoload, "{shell:?} loads before probing");
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
        assert!(script.contains("columns"));
        assert!(script.contains("error make"));
        assert!(script.contains("str join"));
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
        dir_fail: Option<&std::path::Path>,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let count = counter
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let dir_fail = dir_fail
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let path = dir.join("nvault");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  dir)\n    DIR_FAIL='{dir_fail}'\n    if [ -n \"$DIR_FAIL\" ] && [ -f \"$DIR_FAIL\" ]; then exit 1; fi\n    printf '%s\\n' \"$FAKE_NVAULT_DIR\"\n    ;;\n  env)\n    COUNT='{count}'\n    FAILS={failures}\n    if [ -n \"$COUNT\" ]; then\n      n=0\n      [ -f \"$COUNT\" ] && n=$(cat \"$COUNT\")\n      n=$((n + 1))\n      printf '%s' \"$n\" > \"$COUNT\"\n      if [ \"$n\" -le \"$FAILS\" ]; then\n        printf '%s\\n' 'transient failure' >&2\n        exit 1\n      fi\n    fi\n    cat <<'NVAULT_FAKE_ENV_END'\n{env_body}NVAULT_FAKE_ENV_END\n    ;;\n  *) exit 2 ;;\nesac\n"
            ),
        )
        .expect("fake nvault");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("chmod fake nvault");
        path
    }

    /// Writes a fake `nvault` that serves a different `env` body per call.
    ///
    /// Call N prints `bodies[N - 1]`, or the last body after that.
    #[cfg(unix)]
    fn fake_nvault_sequence(
        dir: &std::path::Path,
        counter: &std::path::Path,
        bodies: &[&str],
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let body_dir = counter.parent().expect("counter parent");
        for (index, body) in bodies.iter().enumerate() {
            std::fs::write(body_dir.join(format!("body.{}", index + 1)), body).expect("body file");
        }
        std::fs::write(
            body_dir.join("body.last"),
            bodies.last().expect("at least one body"),
        )
        .expect("last body");

        let path = dir.join("nvault");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  dir) printf '%s\\n' \"$FAKE_NVAULT_DIR\" ;;\n  env)\n    COUNT='{}'\n    n=0\n    [ -f \"$COUNT\" ] && n=$(cat \"$COUNT\")\n    n=$((n + 1))\n    printf '%s' \"$n\" > \"$COUNT\"\n    BODY='{}/body.'\"$n\"\n    [ -f \"$BODY\" ] || BODY='{}/body.last'\n    cat \"$BODY\"\n    ;;\n  *) exit 2 ;;\nesac\n",
                counter.display(),
                body_dir.display(),
                body_dir.display()
            ),
        )
        .expect("fake nvault sequence");
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
        fake_nvault(&bin, &rendered, None, 0, None);
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
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
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
        fake_nvault(&bin, &rendered, None, 0, None);
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
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
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
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
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
        fake_nvault(&bin, &rendered, None, 0, None);
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
        let timestamp = "2020-01-01T00:00:00Z";
        let unicode = "héllo\nline";
        let rendered = render_env(
            &[
                export("FAKE_SECRET", &payload),
                export("STAMP", timestamp),
                export("UNICODE", unicode),
                export("SECOND_KEY", "second"),
            ],
            EnvShell::JsonBase64,
        )
        .expect("env");
        fake_nvault(&bin, &rendered, None, 0, None);

        let payload_file = base.join("payload.txt");
        std::fs::write(&payload_file, payload.as_bytes()).expect("payload file");
        let stamp_file = base.join("stamp.txt");
        std::fs::write(&stamp_file, timestamp.as_bytes()).expect("stamp file");
        let unicode_file = base.join("unicode.txt");
        std::fs::write(&unicode_file, unicode.as_bytes()).expect("unicode file");
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
if ($env:STAMP -ne [IO.File]::ReadAllText('__STAMP__')) { exit 27 }
if ($env:UNICODE -ne [IO.File]::ReadAllText('__UNICODE__')) { exit 28 }
if ($env:NVAULT_LOADED_KEYS -ne 'FAKE_SECRET STAMP UNICODE SECOND_KEY') { exit 21 }
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
            .replace("__STAMP__", &stamp_file.display().to_string())
            .replace("__UNICODE__", &unicode_file.display().to_string())
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

        let rendered =
            render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::JsonBase64).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
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
        fake_nvault(&bin, &rendered, None, 0, None);

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
        fake_nvault(&bin, &rendered, None, 0, None);
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
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
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

    #[cfg(unix)]
    #[test]
    fn bash_hook_cleans_exports_when_the_probe_fails() {
        let base = temp_base("bash-probe-fail");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let dir_fails = base.join("dir-fails");
        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Bash).expect("env");
        fake_nvault(&bin, &rendered, None, 0, Some(&dir_fails));
        let hook_file = write_hook(&base, HookShell::Bash, "hook.bash");
        let script = base.join("test.bash");
        std::fs::write(
            &script,
            format!(
                r#"export PATH="{}:$PATH"
export FAKE_NVAULT_DIR="{}"
export NVAULT_AUTOLOAD=1
source "{}"
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 20
: > "{}"
cd "{}"
_nvault_hook
[ -z "${{FAKE_SECRET+x}}" ] || exit 21
[ -z "${{NVAULT_LOADED_KEYS+x}}" ] || exit 22
[ -z "${{NVAULT_DIR+x}}" ] || exit 23
[ -z "${{NVAULT_LAST_DIR+x}}" ] || exit 24
rm -f "{}"
_nvault_hook
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 25
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                dir_fails.display(),
                other.display(),
                dir_fails.display(),
            ),
        )
        .expect("test script");

        let output = run("bash", "--noprofile", &script, &base);
        assert_ok(&output, "bash probe failure");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn zsh_hook_cleans_exports_when_the_probe_fails() {
        let Some(zsh) = shell_binary("zsh") else {
            return;
        };
        let base = temp_base("zsh-probe-fail");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let dir_fails = base.join("dir-fails");
        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Zsh).expect("env");
        fake_nvault(&bin, &rendered, None, 0, Some(&dir_fails));
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
: > "{}"
cd "{}"
[ -z "${{FAKE_SECRET+x}}" ] || exit 21
[ -z "${{NVAULT_LOADED_KEYS+x}}" ] || exit 22
[ -z "${{NVAULT_DIR+x}}" ] || exit 23
[ -z "${{NVAULT_LAST_DIR+x}}" ] || exit 24
rm -f "{}"
_nvault_hook
[ "${{FAKE_SECRET:-}}" = "loaded" ] || exit 25
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                dir_fails.display(),
                other.display(),
                dir_fails.display(),
            ),
        )
        .expect("test script");

        let output = run(&zsh, "-f", &script, &base);
        assert_ok(&output, "zsh probe failure");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn fish_hook_cleans_exports_when_the_probe_fails() {
        let Some(fish) = shell_binary("fish") else {
            return;
        };
        let base = temp_base("fish-probe-fail");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let dir_fails = base.join("dir-fails");
        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Fish).expect("env");
        fake_nvault(&bin, &rendered, None, 0, Some(&dir_fails));
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
touch "{}"
cd "{}"
not set -q FAKE_SECRET; or exit 21
not set -q NVAULT_LOADED_KEYS; or exit 22
not set -q NVAULT_DIR; or exit 23
not set -q NVAULT_LAST_DIR; or exit 24
rm -f "{}"
_nvault_hook
test "$FAKE_SECRET" = "loaded"; or exit 25
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                dir_fails.display(),
                other.display(),
                dir_fails.display(),
            ),
        )
        .expect("test script");

        let output = run(&fish, "--no-config", &script, &base);
        assert_ok(&output, "fish probe failure");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_cleans_exports_when_the_probe_fails() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-probe-fail");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let dir_fails = base.join("dir-fails");
        let rendered =
            render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::JsonBase64).expect("env");
        fake_nvault(&bin, &rendered, None, 0, Some(&dir_fails));
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
if ($env:FAKE_SECRET -ne 'loaded') { exit 20 }
New-Item -ItemType File -Path '__DIR_FAILS__' -Force | Out-Null
Set-Location -LiteralPath '__OTHER__'
_nvault_hook
if (Test-Path Env:\FAKE_SECRET) { exit 21 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 22 }
if (Test-Path Env:\NVAULT_DIR) { exit 23 }
if ($null -ne $global:_nvault_last_dir) { exit 24 }
Remove-Item -LiteralPath '__DIR_FAILS__'
_nvault_hook
if ($env:FAKE_SECRET -ne 'loaded') { exit 25 }
"#
            .replace("__BIN__", &bin.display().to_string())
            .replace("__ROOT__", &root.display().to_string())
            .replace("__OTHER__", &other.display().to_string())
            .replace("__HOOK__", &hook_file.display().to_string())
            .replace("__DIR_FAILS__", &dir_fails.display().to_string()),
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
        assert_ok(&output, "pwsh probe failure");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_cleans_exports_when_the_probe_fails() {
        let Some(nu) = shell_binary("nu") else {
            return;
        };
        let base = temp_base("nu-probe-fail");
        let bin = base.join("bin");
        let root = base.join("root");
        let other = base.join("other");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&other).expect("other");

        let dir_fails = base.join("dir-fails");
        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Json).expect("env");
        fake_nvault(&bin, &rendered, None, 0, Some(&dir_fails));
        let hook_file = write_hook(&base, HookShell::Nu, "hook.nu");
        let script = base.join("test.nu");
        std::fs::write(
            &script,
            format!(
                r#"$env.PATH = ($env.PATH | prepend '{}')
$env.FAKE_NVAULT_DIR = '{}'
$env.NVAULT_AUTOLOAD = '1'
source "{}"
if (($env.FAKE_SECRET? | default '') != 'loaded') {{ exit 20 }}
touch '{}'
cd '{}'
_nvault_hook
if (($env.FAKE_SECRET? | default '') | is-not-empty) {{ exit 21 }}
if (($env.NVAULT_LOADED_KEYS? | default '') | is-not-empty) {{ exit 22 }}
if (($env.NVAULT_DIR? | default '') | is-not-empty) {{ exit 23 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 24 }}
rm '{}'
_nvault_hook
if (($env.FAKE_SECRET? | default '') != 'loaded') {{ exit 25 }}
"#,
                bin.display(),
                root.display(),
                hook_file.display(),
                dir_fails.display(),
                other.display(),
                dir_fails.display(),
            ),
        )
        .expect("test script");

        let output = std::process::Command::new(&nu)
            .arg("--no-config-file")
            .arg(&script)
            .current_dir(&base)
            .output()
            .expect("run nu");
        assert_ok(&output, "nu probe failure");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn zsh_hook_retries_from_the_next_prompt_and_keeps_existing_precmd_hooks() {
        let (Some(zsh), Some(_script)) = (shell_binary("zsh"), shell_binary("script")) else {
            return;
        };
        let base = temp_base("zsh-precmd");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let rendered = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Zsh).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 1, None);
        let hook_file = write_hook(&base, HookShell::Zsh, "hook.zsh");
        let result = base.join("result.txt");
        let counts = base.join("counts.txt");
        let mine = base.join("mine.txt");

        let input = format!(
            r#"my_precmd() {{ print -r -- mine >> '{}' }}
precmd_functions=(my_precmd)
source '{}'
print -r -- "$#chpwd_functions $#precmd_functions" > '{}'
print -r -- "$FAKE_SECRET" > '{}'
exit
"#,
            mine.display(),
            hook_file.display(),
            counts.display(),
            result.display(),
        );

        let mut child = std::process::Command::new("script")
            .arg("-qec")
            .arg(format!("{zsh} -f -i"))
            .arg("/dev/null")
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("FAKE_NVAULT_DIR", root.display().to_string())
            .env("NVAULT_AUTOLOAD", "1")
            .current_dir(&base)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn interactive zsh");
        std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), input.as_bytes())
            .expect("write commands");
        drop(child.stdin.take());
        let output = child.wait_with_output().expect("wait for zsh");

        assert_ok(&output, "zsh prompt retry");
        assert_eq!(
            std::fs::read_to_string(&result).expect("result").trim(),
            "loaded",
            "the prompt did not retry the failed load"
        );
        assert_eq!(
            std::fs::read_to_string(&counts).expect("counts").trim(),
            "1 2",
            "an existing precmd hook was not preserved, or ours was duplicated"
        );
        assert!(
            std::fs::read_to_string(&mine)
                .expect("mine")
                .contains("mine"),
            "the user's precmd hook did not run"
        );
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "2");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_retries_malformed_and_wrong_shaped_json() {
        let Some(nu) = shell_binary("nu") else {
            return;
        };
        let base = temp_base("nu-malformed");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let valid = render_env(&[export("FAKE_SECRET", "loaded")], EnvShell::Json).expect("env");
        let counter = base.join("count");
        fake_nvault_sequence(&bin, &counter, &["{oops\n", "[1,2]\n", valid.as_str()]);
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
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 32 }}
if (($env.FAKE_SECRET? | default '') | is-not-empty) {{ exit 33 }}
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
        assert_ok(&output, "nu malformed json retry");
        assert_eq!(std::fs::read_to_string(&counter).expect("counter"), "3");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.matches("will retry").count() >= 2,
            "expected a diagnostic per failure: {stderr}"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_rejects_untrusted_json_before_mutation() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-validate");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let counter = base.join("count");
        fake_nvault_sequence(
            &bin,
            &counter,
            &[
                r#"{"A":1,"NVAULT_LOADED_KEYS":"QQ=="}
"#,
                r#"{"A":"eA=="}
"#,
                r#"{"A":"eA==","NVAULT_LOADED_KEYS":"QSBC"}
"#,
                r#"{"A":"","NVAULT_LOADED_KEYS":"QQ=="}
"#,
                r#"{"A-B":"eA==","NVAULT_LOADED_KEYS":"QS1C"}
"#,
                r#"{"A":"eA==","B":"eQ==","NVAULT_LOADED_KEYS":"QSBC"}
"#,
            ],
        );
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
if (Test-Path Env:\A) { exit 21 }
if ($null -ne $global:_nvault_last_dir) { exit 22 }
_nvault_hook
if (Test-Path Env:\A) { exit 23 }
if ($null -ne $global:_nvault_last_dir) { exit 24 }
_nvault_hook
if (Test-Path Env:\A) { exit 25 }
if ($null -ne $global:_nvault_last_dir) { exit 26 }
_nvault_hook
if (Test-Path Env:\A) { exit 27 }
if ($null -ne $global:_nvault_last_dir) { exit 28 }
_nvault_hook
if (Test-Path Env:\A) { exit 29 }
if ($null -ne $global:_nvault_last_dir) { exit 31 }
_nvault_hook
if ($env:A -ne 'x') { exit 20 }
if ($env:B -ne 'y') { exit 34 }
if ($env:NVAULT_LOADED_KEYS -ne 'A B') { exit 35 }
if ($global:_nvault_last_dir -ne $PWD.Path) { exit 36 }
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
        assert_ok(&output, "pwsh validation");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.matches("will retry").count() >= 5,
            "expected a diagnostic per rejected body: {stderr}"
        );
        assert!(
            !stderr.contains("eA==") && !stderr.contains("QSBC") && !stderr.contains("A B"),
            "a payload or value reached stderr: {stderr}"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_rolls_back_partial_assignments() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-rollback");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let body = r#"{"A":"eA==","B":"eQ==","NVAULT_LOADED_KEYS":"QSBC"}
"#;
        fake_nvault(&bin, body, None, 0, None);
        let hook_file = write_hook(&base, HookShell::Pwsh, "hook.ps1");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
$ErrorActionPreference = 'Stop'
function global:Set-Item {
    param($LiteralPath, $Value, $ErrorAction)
    if ($LiteralPath -eq 'Env:\B' -and $Value -eq 'y') { throw 'mock assignment failure' }
    Microsoft.PowerShell.Management\Set-Item -LiteralPath $LiteralPath -Value $Value -ErrorAction $ErrorAction
}
$env:PATH = '__BIN__' + [IO.Path]::PathSeparator + $env:PATH
$env:FAKE_NVAULT_DIR = '__ROOT__'
$env:NVAULT_AUTOLOAD = '1'
$env:A = 'user-value'
$env:B = 'keep-me'
. '__HOOK__'
if ($env:A -ne 'user-value') { exit 21 }
if ($env:B -ne 'keep-me') { exit 22 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 23 }
if ($null -ne $global:_nvault_last_dir) { exit 24 }
Remove-Item -Path Function:\Set-Item -Force
function global:Set-Item {
    param($LiteralPath, $Value, $ErrorAction)
    if ($LiteralPath -eq 'Env:\NVAULT_LOADED_KEYS') { throw 'mock tracking failure' }
    Microsoft.PowerShell.Management\Set-Item -LiteralPath $LiteralPath -Value $Value -ErrorAction $ErrorAction
}
_nvault_hook
if ($env:A -ne 'user-value') { exit 31 }
if ($env:B -ne 'keep-me') { exit 32 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 33 }
if ($null -ne $global:_nvault_last_dir) { exit 34 }
Remove-Item -Path Function:\Set-Item -Force
_nvault_hook
if ($env:A -ne 'x') { exit 25 }
if ($env:B -ne 'y') { exit 26 }
if ($env:NVAULT_LOADED_KEYS -ne 'A B') { exit 27 }
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
        assert_ok(&output, "pwsh rollback");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_accepts_an_empty_tracking_value_with_no_exports() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-empty-tracking");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        fake_nvault(
            &bin,
            r#"{"NVAULT_LOADED_KEYS":""}
"#,
            None,
            0,
            None,
        );
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
if ($global:_nvault_last_dir -ne $PWD.Path) { exit 21 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 22 }
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
        assert_ok(&output, "pwsh empty tracking");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "an empty export set was treated as a failure"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn nu_hook_rejects_untrusted_json_before_mutation() {
        let Some(nu) = shell_binary("nu") else {
            return;
        };
        let base = temp_base("nu-validate");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let counter = base.join("count");
        fake_nvault_sequence(
            &bin,
            &counter,
            &[
                r#"{"A":1,"NVAULT_LOADED_KEYS":"A"}
"#,
                r#"{"A":"x"}
"#,
                r#"{"A":"x","NVAULT_LOADED_KEYS":"A B"}
"#,
                r#"{"A-B":"x","NVAULT_LOADED_KEYS":"A-B"}
"#,
                r#"{"A":"x","B":"","NVAULT_LOADED_KEYS":"A B"}
"#,
            ],
        );
        let hook_file = write_hook(&base, HookShell::Nu, "hook.nu");
        let script = base.join("test.nu");
        std::fs::write(
            &script,
            format!(
                r#"$env.PATH = ($env.PATH | prepend '{}')
$env.FAKE_NVAULT_DIR = '{}'
$env.NVAULT_AUTOLOAD = '1'
source "{}"
if (($env.A? | default '') | is-not-empty) {{ exit 21 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 22 }}
_nvault_hook
if (($env.A? | default '') | is-not-empty) {{ exit 23 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 24 }}
_nvault_hook
if (($env.A? | default '') | is-not-empty) {{ exit 25 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 26 }}
_nvault_hook
if (($env.A? | default '') | is-not-empty) {{ exit 27 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-not-empty) {{ exit 28 }}
_nvault_hook
if (($env.A?) != 'x') {{ exit 20 }}
if (($env.B?) != '') {{ exit 34 }}
if (($env.NVAULT_LOADED_KEYS?) != 'A B') {{ exit 35 }}
if (($env.NVAULT_LAST_DIR? | default '') | is-empty) {{ exit 36 }}
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
        assert_ok(&output, "nu validation");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.matches("will retry").count() >= 4,
            "expected a diagnostic per rejected body: {stderr}"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_rejects_case_mismatched_tracking() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-case");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let counter = base.join("count");
        fake_nvault_sequence(
            &bin,
            &counter,
            &[
                r#"{"TOKEN":"eA==","NVAULT_LOADED_KEYS":"dG9rZW4="}
"#,
                r#"{"TOKEN":"eA==","NVAULT_LOADED_KEYS":"VE9LRU4="}
"#,
            ],
        );
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
if (Test-Path Env:\TOKEN) { exit 21 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 22 }
if ($null -ne $global:_nvault_last_dir) { exit 23 }
_nvault_hook
if ($env:TOKEN -ne 'x') { exit 20 }
if ($env:NVAULT_LOADED_KEYS -ne 'TOKEN') { exit 24 }
if ($global:_nvault_last_dir -ne $PWD.Path) { exit 25 }
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
        assert_ok(&output, "pwsh case-sensitive tracking");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("will retry"),
            "no retry diagnostic: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_rejects_invalid_base64_and_utf8() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-bytes");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let counter = base.join("count");
        fake_nvault_sequence(
            &bin,
            &counter,
            &[
                r#"{"A":"!!!","NVAULT_LOADED_KEYS":"QQ=="}
"#,
                r#"{"A":"//8=","NVAULT_LOADED_KEYS":"QQ=="}
"#,
                r#"{"A":"eA==","NVAULT_LOADED_KEYS":"QQ=="}
"#,
            ],
        );
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
if (Test-Path Env:\A) { exit 21 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 22 }
if ($null -ne $global:_nvault_last_dir) { exit 23 }
_nvault_hook
if (Test-Path Env:\A) { exit 24 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 25 }
if ($null -ne $global:_nvault_last_dir) { exit 26 }
_nvault_hook
if ($env:A -ne 'x') { exit 20 }
if ($env:NVAULT_LOADED_KEYS -ne 'A') { exit 27 }
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
        assert_ok(&output, "pwsh byte validation");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.matches("will retry").count() >= 2,
            "expected a diagnostic per rejected body: {stderr}"
        );
        assert!(
            !stderr.contains("//8=") && !stderr.contains("!!!") && !stderr.contains("eA=="),
            "payload text reached stderr: {stderr}"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[test]
    fn powershell_hook_carries_strict_validation_and_cleanup_markers() {
        for edition in [HookShell::PowerShell, HookShell::Pwsh] {
            let script = hook(edition);
            for needle in [
                "-ErrorAction Stop",
                "$applied += $name",
                "$previous[$name] =",
                "PSCustomObject",
                "'empty value'",
                "-cne",
                "-ceq 'NVAULT_LOADED_KEYS'",
                "$strict.GetString",
                "$global:_nvault_pending_cleanup = @($names + @('NVAULT_LOADED_KEYS'))",
                "could not clean up a failed load",
                "if ($global:_nvault_last_dir -ceq $here)",
            ] {
                assert!(script.contains(needle), "{edition:?} lacks {needle:?}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_keeps_pending_cleanup_when_restore_and_removal_fail() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-pending");
        let bin = base.join("bin");
        let root = base.join("root");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");

        let body = concat!(
            r#"{"A":"eA==","B":"eQ==","NVAULT_LOADED_KEYS":"QSBC"}"#,
            "\n"
        );
        fake_nvault(&bin, body, None, 0, None);
        let hook_file = write_hook(&base, HookShell::Pwsh, "hook.ps1");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
$ErrorActionPreference = 'Stop'
function global:Set-Item {
    param($LiteralPath, $Value, $ErrorAction)
    if ($LiteralPath -eq 'Env:\B' -and $Value -eq 'y') { throw 'mock assignment failure' }
    if ($LiteralPath -eq 'Env:\A' -and $Value -eq 'user-value') { throw 'mock restore failure' }
    Microsoft.PowerShell.Management\Set-Item -LiteralPath $LiteralPath -Value $Value -ErrorAction $ErrorAction
}
$env:PATH = '__BIN__' + [IO.Path]::PathSeparator + $env:PATH
$env:FAKE_NVAULT_DIR = '__ROOT__'
$env:A = 'user-value'
$env:B = 'keep-me'
$env:NVAULT_AUTOLOAD = '1'
. '__HOOK__'
if ($env:A -ne 'x') { exit 21 }
if ($env:B -ne 'keep-me') { exit 22 }
if (Test-Path Env:\NVAULT_LOADED_KEYS) { exit 23 }
if ($null -ne $global:_nvault_last_dir) { exit 24 }
if (-not (@($global:_nvault_pending_cleanup) -contains 'A')) { exit 25 }
Microsoft.PowerShell.Management\Remove-Item -Path Function:\Set-Item -Force
function global:Remove-Item {
    param($LiteralPath, $ErrorAction)
    if ($LiteralPath -eq 'Env:\A' -and -not $global:_remove_failed) {
        $global:_remove_failed = $true
        throw 'mock removal failure'
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -ErrorAction $ErrorAction
}
_nvault_hook
if ($env:A -ne 'x') { exit 31 }
if (-not (@($global:_nvault_pending_cleanup) -contains 'A')) { exit 32 }
if ($null -ne $global:_nvault_last_dir) { exit 33 }
Microsoft.PowerShell.Management\Remove-Item -Path Function:\Remove-Item -Force
_nvault_hook
if ($env:A -ne 'x') { exit 41 }
if ($env:B -ne 'y') { exit 42 }
if ($env:NVAULT_LOADED_KEYS -ne 'A B') { exit 43 }
if (@($global:_nvault_pending_cleanup).Count -ne 0) { exit 44 }
if ($global:_nvault_last_dir -cne $PWD.Path) { exit 45 }
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
        assert_ok(&output, "pwsh pending cleanup");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.matches("could not clean up a failed load").count() >= 2,
            "expected a rollback diagnostic per failed restore/removal: {stderr}"
        );
        assert!(
            stderr.contains("could not load this directory"),
            "the load failure was not reported: {stderr}"
        );
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }

    #[cfg(unix)]
    #[test]
    fn pwsh_hook_reloads_for_a_directory_that_differs_only_in_case() {
        let Some(pwsh) = shell_binary("pwsh") else {
            return;
        };
        let base = temp_base("pwsh-case-dir");
        let bin = base.join("bin");
        let root = base.join("root");
        let lower = base.join("a");
        let upper = base.join("A");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&lower).expect("lower");
        std::fs::create_dir_all(&upper).expect("upper");

        let rendered = render_env(&[export("A", "x")], EnvShell::JsonBase64).expect("env");
        let counter = base.join("count");
        fake_nvault(&bin, &rendered, Some(&counter), 0, None);
        let hook_file = write_hook(&base, HookShell::Pwsh, "hook.ps1");
        let script = base.join("test.ps1");
        std::fs::write(
            &script,
            r#"
$ErrorActionPreference = 'Stop'
$env:PATH = '__BIN__' + [IO.Path]::PathSeparator + $env:PATH
$env:FAKE_NVAULT_DIR = '__ROOT__'
$env:NVAULT_AUTOLOAD = '1'
Set-Location -LiteralPath '__LOWER__'
. '__HOOK__'
if ([IO.File]::ReadAllText('__COUNTER__').Trim() -ne '1') { exit 21 }
Set-Location -LiteralPath '__UPPER__'
_nvault_hook
if ([IO.File]::ReadAllText('__COUNTER__').Trim() -ne '2') { exit 22 }
if ($env:A -ne 'x') { exit 23 }
if ($global:_nvault_last_dir -cne $PWD.Path) { exit 24 }
"#
            .replace("__BIN__", &bin.display().to_string())
            .replace("__ROOT__", &root.display().to_string())
            .replace("__LOWER__", &lower.display().to_string())
            .replace("__UPPER__", &upper.display().to_string())
            .replace("__HOOK__", &hook_file.display().to_string())
            .replace("__COUNTER__", &counter.display().to_string()),
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
        assert_ok(&output, "pwsh case-distinct directories");
        std::fs::remove_dir_all(base).expect("remove temp hook dir");
    }
}
