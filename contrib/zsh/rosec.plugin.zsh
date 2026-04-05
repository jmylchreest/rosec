# rosec.plugin.zsh — rosec secret -> environment variable helper
#
# Provides shell functions for fetching secrets from rosec and
# exporting them as environment variables. Designed for use with
# antidote (or any zsh plugin manager).
#
# Add to ~/.zsh_plugins.txt:
#   jmylchreest/rosec path:contrib/zsh kind:defer
#
# Configuration (optional, via zstyle):
#   zstyle ':rosec:env' aliases-file "$HOME/.config/rosec-env/aliases"
#   zstyle ':rosec:env' autoload-file "$HOME/.config/rosec-env/autoload"
#
# Usage:
#   get-key KAGI_API_KEY          # prints the secret value (cached, fast)
#   get-key kagi                  # resolves alias from aliases file, prints value
#   get-key --sync kagi           # sync providers first, then fetch (slower)
#   rosec-env KAGI_API_KEY        # exports KAGI_API_KEY=<secret> into current shell
#   rosec-env kagi                # resolves alias, then exports
#   rosec-env --sync kagi         # sync providers first, then export
#   rosec-env kagi CUSTOM_VAR    # resolves alias, exports as CUSTOM_VAR instead
#
# Aliases file format (~/.config/rosec-env/aliases):
#   kagi=KAGI_API_KEY
#   openai=OPENAI_API_KEY
#
# Autoload file format (~/.config/rosec-env/autoload):
#   kagi
#   openai

# Bail early if rosec is not installed
(( $+commands[rosec] )) || return 0

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Resolve a short alias or input to a rosec item name.
#
# Rules:
#   1. If input is UPPER_SNAKE_CASE, treat it as a direct item name
#   2. Look it up in the aliases file
#   3. Fall back: uppercase the input and append _API_KEY
__rosec_env_resolve() {
  local input="$1"
  local aliases_file
  zstyle -s ':rosec:env' aliases-file aliases_file \
    || aliases_file="${XDG_CONFIG_HOME:-$HOME/.config}/rosec-env/aliases"

  # Already UPPER_SNAKE_CASE — use directly
  if [[ "$input" =~ ^[A-Z][A-Z0-9_]+$ ]]; then
    echo "$input"
    return 0
  fi

  # Look up in aliases file
  if [[ -f "$aliases_file" ]]; then
    local match
    match=$(command grep -m1 "^${input}=" "$aliases_file" 2>/dev/null)
    if [[ -n "$match" ]]; then
      echo "${match#*=}"
      return 0
    fi
  fi

  # Fall back: uppercase + _API_KEY suffix
  echo "${(U)input}_API_KEY"
  return 0
}

# Check whether any rosec provider is unlocked.
# Returns 0 if at least one provider is unlocked, 1 otherwise.
__rosec_env_any_unlocked() {
  rosec provider list 2>/dev/null | command grep -q 'unlocked'
}

# Ensure at least one provider is unlocked, prompting if needed.
__rosec_env_ensure_unlocked() {
  __rosec_env_any_unlocked && return 0

  if ! (( $+commands[rosec] )); then
    echo "rosec is not installed." >&2
    return 1
  fi

  echo "rosec: all providers locked, unlocking..." >&2
  rosec unlock 2>&1 || return $?
  return 0
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

# Fetch a secret value from rosec and print it to stdout.
#
# Usage: get-key [--sync] <name|alias>
get-key() {
  local do_sync=0
  if [[ "$1" == --sync ]]; then
    do_sync=1
    shift
  fi

  if [[ -z "$1" ]]; then
    echo "Usage: get-key [--sync] <name|alias>" >&2
    return 1
  fi

  __rosec_env_ensure_unlocked || return 1

  local item_name
  item_name=$(__rosec_env_resolve "$1")

  local value
  if (( do_sync )); then
    value=$(rosec get --sync "name=${item_name}" 2>&1)
  else
    value=$(rosec get "name=${item_name}" 2>&1)
  fi
  local rc=$?
  if [[ $rc -ne 0 || -z "$value" ]]; then
    echo "Error: could not fetch '${item_name}' from rosec" >&2
    echo "  Ensure an item named '${item_name}' exists in one of your rosec providers." >&2
    return 1
  fi

  echo "$value"
}

# Fetch a secret and export it as an environment variable.
#
# Usage: rosec-env [--sync] <name|alias> [VAR_NAME]
rosec-env() {
  local sync_flag=()
  if [[ "$1" == --sync ]]; then
    sync_flag=(--sync)
    shift
  fi

  if [[ -z "$1" ]]; then
    echo "Usage: rosec-env [--sync] <name|alias> [VAR_NAME]" >&2
    echo "  Fetches a secret from rosec and exports it as an environment variable." >&2
    return 1
  fi

  local item_name var_name value
  item_name=$(__rosec_env_resolve "$1")
  var_name="${2:-$item_name}"

  value=$(get-key $sync_flag "$item_name")
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  export "$var_name=$value"
  echo "Exported $var_name"
}

# ---------------------------------------------------------------------------
# Deferred autoload
# ---------------------------------------------------------------------------
# After the prompt renders, silently export keys listed in the autoload file.
# Only runs if at least one provider is already unlocked (no pinentry popup).

if (( $+functions[zsh-defer] )); then
  zsh-defer -c '
    local _rosec_autoload
    zstyle -s ":rosec:env" autoload-file _rosec_autoload \
      || _rosec_autoload="${XDG_CONFIG_HOME:-$HOME/.config}/rosec-env/autoload"

    if [[ -f "$_rosec_autoload" ]] && command grep -qv "^\s*#\|^\s*$" "$_rosec_autoload" 2>/dev/null; then
      __rosec_env_any_unlocked || return 0
      while IFS= read -r _rosec_key || [[ -n "$_rosec_key" ]]; do
        [[ -z "$_rosec_key" || "$_rosec_key" == \#* ]] && continue
        rosec-env "$_rosec_key" >/dev/null 2>&1
      done < "$_rosec_autoload"
    fi
  '
fi
