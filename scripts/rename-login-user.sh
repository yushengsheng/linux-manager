#!/usr/bin/env bash
# Rename an existing Linux login in place.  It does not create a replacement
# account: the UID, supplemental groups, sudo access, home contents, and SSH
# authorized_keys remain attached to the same account.
#
# Run as root on the target host, preferably from the provider console:
#   sudo bash rename-login-user.sh
#
# This script deliberately prompts for the existing password before it changes
# anything. Passwords are never printed, stored in command-line arguments, or
# saved in the backup directory.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly BACKUP_ROOT=/root/account-rename-backups
readonly PLAN_ROOT=/run/account-rename

old_user=''
new_user=''
old_password=''
new_password=''
stdin_secrets=0
dry_run=0
execute_plan=''

usage() {
  cat <<'EOF'
Usage: sudo bash rename-login-user.sh [--old-user USER] [--new-user USER] [--stdin-secrets] [--dry-run]

Renames an existing login in place and prompts for its current password and
the new password. The destination username may also be provided interactively.

The target is not a new account: its UID, group memberships, home directory,
SSH authorized keys, and sudo access are retained. The script makes a
root-only backup of account and relevant SSH/cloud-init configuration first.

--stdin-secrets is for the local GUI launcher. It reads the current password,
new password, repeated new password, and final RENAME confirmation from stdin
instead of the terminal. Do not use it manually.

--dry-run validates credentials, account prerequisites, sudoers and sshd
configuration without changing users, passwords, files, or services.

The actual rename is automatically executed by a temporary root systemd unit.
That unit disconnects the old account before running usermod, which is required
on Linux when the account currently owns an SSH session.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

on_error() {
  local exit_code=$?
  printf 'ERROR: account rename did not complete. Do not close the current session. ' >&2
  printf 'A root-only backup was written under %s. Exit code: %s\n' "$BACKUP_ROOT" "$exit_code" >&2
  exit "$exit_code"
}

trap on_error ERR
trap 'unset old_password new_password' EXIT

require_root() {
  [[ ${EUID} -eq 0 ]] || die 'run this script through sudo or as root'
}

valid_username() {
  [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

prompt_value() {
  local prompt=$1
  local value=''
  read -r -p "$prompt" value
  printf '%s' "$value"
}

prompt_secret() {
  local prompt=$1
  local value=''
  if (( stdin_secrets )); then
    read -r value
  else
    read -r -s -p "$prompt" value
    printf '\n' >&2
  fi
  printf '%s' "$value"
}

verify_password() {
  local user=$1
  local password=$2
  local shadow_hash=''

  shadow_hash=$(getent shadow "$user" | awk -F: '{print $2}')
  [[ -n $shadow_hash && $shadow_hash != '!' && $shadow_hash != '*' ]] || return 1

  # Pass the candidate password through stdin so it is not present in argv or
  # the process environment. Python's crypt implementation supports the hash
  # formats used by Ubuntu's /etc/shadow file.
  printf '%s' "$password" | python3 -c '
import crypt
import sys

encoded = sys.argv[1]
candidate = sys.stdin.read()
result = crypt.crypt(candidate, encoded)
raise SystemExit(0 if result == encoded else 1)
' "$shadow_hash"
}

backup_configuration() {
  local timestamp backup_dir file
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  backup_dir="$BACKUP_ROOT/$timestamp-$old_user-to-$new_user"
  install -d -m 700 "$backup_dir"

  cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow "$backup_dir/"

  for file in /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/cloud/cloud.cfg; do
    [[ -f $file ]] || continue
    cp -a --parents "$file" "$backup_dir/"
  done

  printf 'Root-only rollback material: %s\n' "$backup_dir"
}

replace_login_reference() {
  local file=$1
  [[ -f $file ]] || return 0

  # Replace standalone account names only. The validated names contain only
  # characters that are safe inside this extended regular expression.
  sed -i -E "s/(^|[[:space:],])${old_user}([[:space:],]|$)/\\1${new_user}\\2/g" "$file"
}

update_cloud_init_default_user() {
  local cloud_cfg=/etc/cloud/cloud.cfg
  [[ -f $cloud_cfg ]] || return 0

  python3 - "$cloud_cfg" "$old_user" "$new_user" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

in_default_user = False
default_indent = None
replaced = False
out = []

for line in lines:
    match = re.match(r"^(\s*)default_user:\s*(?:#.*)?$", line)
    if match:
        in_default_user = True
        default_indent = len(match.group(1))
        out.append(line)
        continue

    if in_default_user and line.strip() and not line.lstrip().startswith("#"):
        indent = len(line) - len(line.lstrip())
        if indent <= default_indent:
            in_default_user = False

    if in_default_user:
        name_match = re.match(
            rf"^(\s*name:\s*){re.escape(old)}(\s*(?:#.*)?(?:\r?\n)?)$", line
        )
        if name_match:
            out.append(f"{name_match.group(1)}{new}{name_match.group(2)}")
            replaced = True
            continue

    out.append(line)

if replaced:
    path.write_text("".join(out), encoding="utf-8")
PY
}

validate_post_change() {
  getent passwd "$new_user" >/dev/null || die "new account $new_user is missing"
  id "$new_user" >/dev/null

  visudo -c >/dev/null
  sshd -t
  systemctl reload ssh

  printf '\nRename completed. New login: %s\n' "$new_user"
  printf 'SSH public keys were retained at: %s/.ssh/authorized_keys\n' "$new_home"
  printf 'Existing sessions under %s may remain open until they disconnect.\n' "$old_user"
  printf 'Confirm a new SSH login as %s before closing this session.\n' "$new_user"
}

remove_plan() {
  local plan_dir=$1
  rm -f -- "$plan_dir/old_user" "$plan_dir/new_user" "$plan_dir/new_password" "$plan_dir/unit"
  rmdir "$plan_dir" 2>/dev/null || true
}

create_plan() {
  local plan_dir unit_name
  install -d -m 700 "$PLAN_ROOT"
  plan_dir=$(mktemp -d "$PLAN_ROOT/rename.XXXXXXXX")
  unit_name="account-rename-${new_user}-$(date +%s)"

  printf '%s' "$old_user" > "$plan_dir/old_user"
  printf '%s' "$new_user" > "$plan_dir/new_user"
  printf '%s' "$new_password" > "$plan_dir/new_password"
  printf '%s' "$unit_name" > "$plan_dir/unit"
  chmod 600 "$plan_dir/old_user" "$plan_dir/new_user" "$plan_dir/new_password" "$plan_dir/unit"

  printf '%s\n' "$plan_dir"
}

load_plan() {
  local plan_dir=$1
  [[ $plan_dir == "$PLAN_ROOT"/* && -d $plan_dir ]] || die 'invalid scheduled rename plan'
  [[ $(stat -c '%U:%G' "$plan_dir") == root:root ]] || die 'rename plan ownership is unsafe'
  [[ $(stat -c '%a' "$plan_dir") == 700 ]] || die 'rename plan permissions are unsafe'

  old_user=$(<"$plan_dir/old_user")
  new_user=$(<"$plan_dir/new_user")
  new_password=$(<"$plan_dir/new_password")
  valid_username "$old_user" || die 'scheduled old username is invalid'
  valid_username "$new_user" || die 'scheduled new username is invalid'
  [[ -n $new_password && ${#new_password} -ge 16 ]] || die 'scheduled new password is invalid'
}

terminate_old_user_processes() {
  local user=$1
  local attempt

  # Give the GUI enough time to receive the scheduling acknowledgement before
  # its SSH session is terminated. The root systemd unit is unaffected.
  sleep 8
  pkill -TERM -u "$user" 2>/dev/null || true
  for attempt in {1..8}; do
    pgrep -u "$user" >/dev/null || return 0
    sleep 1
  done
  pkill -KILL -u "$user" 2>/dev/null || true
  for attempt in {1..3}; do
    pgrep -u "$user" >/dev/null || return 0
    sleep 1
  done
  die "could not terminate active processes for $user"
}

apply_rename() {
  old_home=$(getent passwd "$old_user" | awk -F: '{print $6}')
  old_group=$(id -gn "$old_user")
  new_home="$(dirname "$old_home")/$new_user"
  [[ ! -e $new_home ]] || die "target home directory already exists: $new_home"

  backup_configuration
  usermod -l "$new_user" "$old_user"
  if [[ $old_group == "$old_user" ]]; then
    groupmod -n "$new_user" "$old_group"
  fi
  usermod -d "$new_home" -m "$new_user"
  printf '%s:%s\n' "$new_user" "$new_password" | chpasswd
  unset new_password

  for file in /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
    replace_login_reference "$file"
  done
  update_cloud_init_default_user
  validate_post_change
}

execute_scheduled_rename() {
  local plan_dir=$1
  load_plan "$plan_dir"
  getent passwd "$old_user" >/dev/null || die "scheduled account does not exist: $old_user"
  ! getent passwd "$new_user" >/dev/null || die "scheduled new username already exists: $new_user"
  terminate_old_user_processes "$old_user"
  apply_rename
  remove_plan "$plan_dir"
  printf 'Scheduled account rename completed successfully.\n'
}

schedule_rename() {
  local plan_dir unit_name
  plan_dir=$(create_plan)
  unit_name=$(<"$plan_dir/unit")
  systemd-run --unit="$unit_name" --collect /usr/local/sbin/rename-login-user --execute-plan "$plan_dir"
  printf 'Rename scheduled: %s. The old SSH session will close in about 8 seconds.\n' "$unit_name"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --old-user)
      [[ $# -ge 2 ]] || die '--old-user requires a value'
      old_user=$2
      shift 2
      ;;
    --new-user)
      [[ $# -ge 2 ]] || die '--new-user requires a value'
      new_user=$2
      shift 2
      ;;
    --stdin-secrets)
      stdin_secrets=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --execute-plan)
      [[ $# -ge 2 ]] || die '--execute-plan requires a plan path'
      execute_plan=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

require_root

if [[ -n $execute_plan ]]; then
  execute_scheduled_rename "$execute_plan"
  exit 0
fi

[[ -n $old_user ]] || old_user=$(prompt_value 'Current username: ')
valid_username "$old_user" || die 'current username is not valid'
getent passwd "$old_user" >/dev/null || die "account does not exist: $old_user"
[[ $old_user != root ]] || die 'renaming root is intentionally not supported'

[[ -n $new_user ]] || new_user=$(prompt_value 'New username: ')
valid_username "$new_user" || die 'new username must use lowercase letters, digits, _ or - and be at most 32 characters'
[[ $new_user != root ]] || die 'root cannot be used as the new username'
[[ $new_user != "$old_user" ]] || die 'the new username must differ from the current username'
getent passwd "$new_user" >/dev/null && die "new username already exists: $new_user"
getent group "$new_user" >/dev/null && die "a group named $new_user already exists"

old_password=$(prompt_secret "Current password for $old_user: ")
verify_password "$old_user" "$old_password" || die 'current password did not match'

new_password=$(prompt_secret "New password for $new_user: ")
[[ ${#new_password} -ge 16 ]] || die 'new password must be at least 16 characters'
local_confirmation=$(prompt_secret 'Repeat the new password: ')
[[ $new_password == "$local_confirmation" ]] || die 'new passwords did not match'
unset local_confirmation

old_home=$(getent passwd "$old_user" | awk -F: '{print $6}')
new_home="$(dirname "$old_home")/$new_user"
[[ ! -e $new_home ]] || die "target home directory already exists: $new_home"

printf '\nAbout to rename %s -> %s and move %s -> %s.\n' "$old_user" "$new_user" "$old_home" "$new_home"
confirmation=$(prompt_value 'Type RENAME to continue: ')
[[ $confirmation == RENAME ]] || die 'cancelled'
unset confirmation

if (( dry_run )); then
  visudo -c >/dev/null
  sshd -t
  printf 'Dry-run completed: credentials and rename prerequisites are valid; no changes were made.\n'
  exit 0
fi

# The GUI is logged in as the account being renamed. Run the destructive part
# in a detached root systemd unit so the old user can be cleanly terminated
# before usermod checks for active processes.
schedule_rename
unset old_password new_password
