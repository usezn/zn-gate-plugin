#!/bin/sh
# Starts scripts/zn-launch.js of the zn-gate plugin with a Node.js found only in absolute PATH entries outside the project.
#
# Why: a hook command that starts `node` by name uses the first `node` on the PATH of the agent. A relative
# entry (".", an empty entry, "bin") points into the folder the session runs in, which is the project, and on Windows
# the current folder can be searched too. An absolute entry can point into the project as well (its bin/ or
# node_modules/.bin). A node placed there would run with the user's rights, without zn's checks.
#
# Usage: zn-node.sh <Event> <zn-launch.js arguments...>
#   e.g. zn-node.sh PreToolUse hook claude-code, zn-node.sh PreToolUse hook codex
# The event JSON arrives on stdin and is passed to zn-launch.js. <Event> and the agent (the last argument) are only used
# to choose how to refuse when zn-launch.js cannot be started: the events that can stop a call are blocked (exit 2);
# the others only warn. (Cursor does not use this script: it runs plugin hooks from the plugin folder, see check-plugins.js.)
#
# What zn-launch.js prints and the exit code it ends with (0, 2 or anything else) pass through unchanged: it checks the Node.js
# version itself (and refuses when it is too old), and Claude Code's onFailure "block" handles a hook that ends with another code.
# This script adds one thing zn-launch.js cannot do for itself: a start deadline (DEADLINE seconds, under the timeout of the
# hooks: 13 of 15 in Claude Code, 26 of 30 in Codex). A Node.js that has not finished by then is stopped and the hook refuses
# like it does when Node.js is missing. Without a `sleep` program there is no deadline, and the other refusals still apply.

# Functions exported in the environment (bash running as sh) could replace the commands below.
unset -f [ test wait kill command printf cd pwd ls sort sleep 2>/dev/null

# Variables that make Node.js or the dynamic loader load code of the caller's choosing (NODE_OPTIONS=--require, LD_PRELOAD and the
# like) are removed before anything is started: a project can set the environment of the agent. NODE_EXTRA_CA_CERTS and the proxy settings stay.
unset GCONV_PATH GLIBC_TUNABLES LOCPATH NLSPATH HOSTALIASES RES_OPTIONS OPENSSL_CONF NODE_OPTIONS NODE_PATH NODE_REPL_EXTERNAL_MODULE NODE_V8_COVERAGE PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONUSERBASE PERL5OPT PERL5LIB PERLLIB RUBYOPT RUBYLIB JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS BASH_ENV ENV
set -f; IFS='
'; for ZN_V in $(export -p); do ZN_V=${ZN_V#export }; ZN_V=${ZN_V#declare -x }; ZN_V=${ZN_V%%=*}; case $ZN_V in ""|*[!A-Za-z0-9_]*) ;; [Ll][Dd]_*|[Dd][Yy][Ll][Dd]_*|[Gg][Cc][Oo][Nn][Vv]_[Pp][Aa][Tt][Hh]|[Gg][Ll][Ii][Bb][Cc]_[Tt][Uu][Nn][Aa][Bb][Ll][Ee][Ss]|[Ll][Oo][Cc][Pp][Aa][Tt][Hh]|[Nn][Ll][Ss][Pp][Aa][Tt][Hh]|[Hh][Oo][Ss][Tt][Aa][Ll][Ii][Aa][Ss][Ee][Ss]|[Rr][Ee][Ss]_[Oo][Pp][Tt][Ii][Oo][Nn][Ss]|[Oo][Pp][Ee][Nn][Ss][Ss][Ll]_[Cc][Oo][Nn][Ff]|[Nn][Oo][Dd][Ee]_[Oo][Pp][Tt][Ii][Oo][Nn][Ss]|[Nn][Oo][Dd][Ee]_[Pp][Aa][Tt][Hh]|[Nn][Oo][Dd][Ee]_[Rr][Ee][Pp][Ll]_[Ee][Xx][Tt][Ee][Rr][Nn][Aa][Ll]_[Mm][Oo][Dd][Uu][Ll][Ee]|[Nn][Oo][Dd][Ee]_[Vv]8_[Cc][Oo][Vv][Ee][Rr][Aa][Gg][Ee]|[Pp][Yy][Tt][Hh][Oo][Nn][Pp][Aa][Tt][Hh]|[Pp][Yy][Tt][Hh][Oo][Nn][Hh][Oo][Mm][Ee]|[Pp][Yy][Tt][Hh][Oo][Nn][Ss][Tt][Aa][Rr][Tt][Uu][Pp]|[Pp][Yy][Tt][Hh][Oo][Nn][Ii][Nn][Ss][Pp][Ee][Cc][Tt]|[Pp][Yy][Tt][Hh][Oo][Nn][Uu][Ss][Ee][Rr][Bb][Aa][Ss][Ee]|[Pp][Ee][Rr][Ll]5[Oo][Pp][Tt]|[Pp][Ee][Rr][Ll]5[Ll][Ii][Bb]|[Pp][Ee][Rr][Ll][Ll][Ii][Bb]|[Rr][Uu][Bb][Yy][Oo][Pp][Tt]|[Rr][Uu][Bb][Yy][Ll][Ii][Bb]|[Jj][Aa][Vv][Aa]_[Tt][Oo][Oo][Ll]_[Oo][Pp][Tt][Ii][Oo][Nn][Ss]|_[Jj][Aa][Vv][Aa]_[Oo][Pp][Tt][Ii][Oo][Nn][Ss]|[Jj][Dd][Kk]_[Jj][Aa][Vv][Aa]_[Oo][Pp][Tt][Ii][Oo][Nn][Ss]|[Bb][Aa][Ss][Hh]_[Ee][Nn][Vv]|[Ee][Nn][Vv]) unset "$ZN_V" ;; esac; done; unset IFS ZN_V; set +f

EVENT="${1:-}"
[ "$#" -gt 0 ] && shift
AGENT=
for a in "$@"; do AGENT=$a; done

# Absolute script path only: the folder of this script is where zn-launch.js is; any other form would depend on the
# folder the session runs in (the project), so the launcher is then treated as missing. A Windows path (C:\... or C:/...,
# Git Bash) counts as absolute too; the folder is whatever precedes the last / or \.
# shellcheck disable=SC1003 # one backslash, not an escaped single quote
BS='\'
HERE_DIR=
case "$0" in
  /* | [A-Za-z]:*)
    A=${0%/*}
    B=${0%"$BS"*}
    if [ "$A" = "$0" ]; then HERE_DIR=$B; elif [ "$B" = "$0" ]; then HERE_DIR=$A; elif [ "${#A}" -ge "${#B}" ]; then HERE_DIR=$A; else HERE_DIR=$B; fi
    [ "$HERE_DIR" != "$0" ] || HERE_DIR=
    ;;
esac
HERE=$([ -n "$HERE_DIR" ] && CDPATH='' cd -- "$HERE_DIR" 2>/dev/null && pwd -P) || HERE=""

# Folders the agent works in are not trusted for programs: the folder the hook runs in, the project folder the host names
# (CLAUDE_PROJECT_DIR, CURSOR_PROJECT_DIR) and the git work tree around the hook's folder, compared by their real paths,
# and any node_modules folder. An absolute PATH entry there (a bin/ of the project, node_modules/.bin, a folder added by
# direnv) could hold a node or a sleep of the project's own. Your home folder and / never count as the project: everything
# would be untrusted there. A link is followed to its target, and the target's folder must be trusted too.
NL='
'
# The real path of a folder, in PHYS. Without a process per folder (a subshell is slow in Git Bash on Windows): cd -P into
# the folder and back to the hook's folder in this shell. Only when the hook's folder cannot be read is a subshell used.
CDPATH=
CWD_P=$(pwd -P 2>/dev/null) || CWD_P=""
phys() {
  PHYS=""
  _pf=$1
  [ -n "$_pf" ] || return 1
  # cd prints the folder and goes back to the previous one for "-": a folder named "-" is ./-, and nothing reaches the
  # hook's output (the agent reads it as the hook's answer).
  [ "$_pf" != - ] || _pf=./-
  if [ -z "$CWD_P" ]; then
    PHYS=$(cd -P -- "$_pf" >/dev/null 2>&1 && pwd -P) || return 1
    return 0
  fi
  cd -P -- "$_pf" >/dev/null 2>&1 || return 1
  PHYS=$PWD
  # Back to the hook's folder; if it is gone, no folder is trusted (the hook then finds no Node.js and refuses).
  cd -P -- "$CWD_P" >/dev/null 2>&1 || { PHYS=""; return 1; }
  [ -n "$PHYS" ]
}
dir_of() {
  DIR_OF=${1%/*}
  [ -n "$DIR_OF" ] || DIR_OF=/
}
HOME_P=""
if phys "${HOME:-/nonexistent}"; then HOME_P=$PHYS; fi
ROOTS=""
add_root() {
  phys "$1" || return 0
  case "$PHYS" in / | "$HOME_P") return 0 ;; esac
  ROOTS="$ROOTS$NL$PHYS"
}
add_root "$CWD_P"
add_root "${CLAUDE_PROJECT_DIR:-}"
add_root "${CURSOR_PROJECT_DIR:-}"
_d=$CWD_P
while [ -n "$_d" ] && [ "$_d" != / ]; do
  if [ -e "$_d/.git" ]; then
    add_root "$_d"
    break
  fi
  _d=${_d%/*}
done
trusted_dir() {
  phys "$1" || return 1
  _p=$PHYS
  case "$_p/" in */node_modules/*) return 1 ;; esac
  _o=$IFS
  IFS=$NL
  set -f
  _ok=0
  for _r in $ROOTS; do
    case "$_p/" in "$_r"/*) _ok=1; break ;; esac
  done
  set +f
  IFS=$_o
  return "$_ok"
}
READLINK=""
for c in /usr/bin/readlink /bin/readlink; do
  if [ -x "$c" ]; then READLINK=$c; break; fi
done
trusted_prog() {
  _f=$1
  _i=0
  dir_of "$_f"
  trusted_dir "$DIR_OF" || return 1
  while [ -L "$_f" ]; do
    [ -n "$READLINK" ] && [ "$_i" -lt 40 ] || return 1
    _t=$("$READLINK" -- "$_f") || return 1
    dir_of "$_f"
    case "$_t" in /*) _f=$_t ;; *) _f=$DIR_OF/$_t ;; esac
    dir_of "$_f"
    trusted_dir "$DIR_OF" || return 1
    _i=$((_i + 1))
  done
  return 0
}

# Only absolute, trusted PATH entries, for this script and everything it starts.
OLDIFS=$IFS
IFS=:
set -f
SAFE_PATH=
for d in $PATH; do
  case "$d" in /*) trusted_dir "$d" && SAFE_PATH="${SAFE_PATH:+$SAFE_PATH:}$d" ;; esac
done
set +f
IFS=$OLDIFS
[ -n "$SAFE_PATH" ] || SAFE_PATH=/usr/bin:/bin
PATH=$SAFE_PATH
export PATH

# Refusal: exit 2 and the reason on stderr where that blocks; elsewhere exit 0 with a message for the user.
refuse() {
  case "$AGENT" in
    codex) OFF='turn off the zn-gate plugin in Codex (/plugins)' ;;
    *) OFF='turn off the zn-gate plugin (claude plugin disable zn-gate@usezn)' ;;
  esac
  MSG="zn: $1 This call was blocked because zn could not check it. Fix it, or $OFF."
  case "$EVENT" in
    PreToolUse | PermissionRequest | UserPromptSubmit | UserPromptExpansion)
      printf '%s\n' "$MSG" >&2
      exit 2
      ;;
    *)
      printf '{"systemMessage":"zn is NOT protecting this session: %s"}\n' "$1"
      exit 0
      ;;
  esac
}

LAUNCH="$HERE/zn-launch.js"
[ -n "$HERE" ] && [ -f "$LAUNCH" ] || refuse "the plugin launcher (scripts/zn-launch.js) is missing."

# Under each host's hook timeout: Claude Code 15 s, Codex 30 s (the timeout the plugin sets).
DEADLINE=13
[ "$AGENT" != codex ] || DEADLINE=26
exec 3<&0
CUR=""
WD=""
# shellcheck disable=SC2329 # called by trap
stop_watchdog() {
  [ -z "$WD" ] || kill "$WD" 2>/dev/null
}
# shellcheck disable=SC2329 # called by trap
on_deadline() {
  trap '' USR1
  [ -z "$CUR" ] || kill "$CUR" 2>/dev/null
  refuse "the hook did not finish starting within $DEADLINE seconds."
}
# The system's sleep, by its full path (never one found on the PATH).
SLEEP=""
for c in /bin/sleep /usr/bin/sleep; do
  if [ -x "$c" ]; then SLEEP=$c; break; fi
done
if [ -n "$SLEEP" ]; then
  MAIN=$$
  trap on_deadline USR1
  trap stop_watchdog EXIT
  (
    exec >/dev/null 2>&1 </dev/null
    "$SLEEP" "$DEADLINE" &
    s=$!
    trap 'kill "$s" 2>/dev/null; exit 0' TERM
    wait "$s" && kill -USR1 "$MAIN"
  ) &
  WD=$!
fi

NODE=""
OLDIFS=$IFS
IFS=:
set -f
for d in $PATH; do
  case "$d" in /*) ;; *) continue ;; esac
  for n in node node.exe; do
    if [ -f "$d/$n" ] && [ -x "$d/$n" ] && trusted_prog "$d/$n"; then NODE="$d/$n"; break; fi
  done
  [ -z "$NODE" ] || break
done
set +f
IFS=$OLDIFS

# The usual install folders (an app often starts with a short PATH).
if [ -z "$NODE" ]; then
  for c in /usr/local/bin/node /opt/homebrew/bin/node /usr/bin/node "/c/Program Files/nodejs/node.exe" "${HOME:-/nonexistent}/.volta/bin/node" "${HOME:-/nonexistent}/.local/share/fnm/aliases/default/bin/node"; do
    if [ -f "$c" ] && [ -x "$c" ] && trusted_prog "$c"; then NODE="$c"; break; fi
  done
fi
LS=""
SORT=""
for c in /bin/ls /usr/bin/ls; do
  if [ -x "$c" ]; then LS=$c; break; fi
done
for c in /usr/bin/sort /bin/sort; do
  if [ -x "$c" ]; then SORT=$c; break; fi
done
if [ -z "$NODE" ] && [ -n "${HOME:-}" ] && [ -d "$HOME/.nvm/versions/node" ] && [ -n "$LS" ] && [ -n "$SORT" ]; then
  # shellcheck disable=SC2012 # a plain list of folders, newest version first (version order: v22 before v9)
  for c in $("$LS" -1d "$HOME"/.nvm/versions/node/*/bin/node 2>/dev/null | "$SORT" -r -V); do
    if [ -f "$c" ] && [ -x "$c" ] && trusted_prog "$c"; then NODE="$c"; break; fi
  done
fi

[ -n "$NODE" ] || refuse "no Node.js was found for the hook (looked in the absolute PATH entries outside the project and the usual install folders)."

"$NODE" "$LAUNCH" "$@" <&3 &
CUR=$!
wait "$CUR"
rc=$?
CUR=""
exit "$rc"
