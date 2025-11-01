#!/bin/sh
#
# Minimum init for headless servers. Assumes ~fresh Debian 12+ (for now) / not run over ssh. POSIX
# - Adds GitHub SSH keys
# - Harden sshd:
#   - Disable password / root login
#   - Changes SSH port
# - Sets up UFW and Fail2ban
#   - '--http' to allow HTTP/S ports in UFW
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/Data-Corruption/tool/main/i.sh | sudo sh -s -- -g Data-Corruption -p 22 --http

set -eu
umask 077

TARGET_USER=""
GITHUB_USER=""
SSH_PORT=22
ALLOW_HTTP=0
cat <<'EOF'
 _____     ______     ______   ______    
/\  __-.  /\  __ \   /\__  _\ /\  __ \   
\ \ \/\ \ \ \  __ \  \/_/\ \/ \ \  __ \  
 \ \____-  \ \_\ \_\    \ \_\  \ \_\ \_\ 
  \/____/   \/_/\/_/     \/_/   \/_/\/_/ 
                                         
EOF

# w/og code: `some_cmd || { rc=$?; dief 'some_cmd failed (rc=%d)' "$rc"; }`
dief() {
  fmt=$1; shift; printf "$fmt\n" "$@" >&2; exit 1
}

# Arguments -------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    -u) TARGET_USER="$2"; shift 2 ;;
    -g) GITHUB_USER="$2"; shift 2 ;;
    -p) SSH_PORT="$2"; shift 2 ;;
    --http) ALLOW_HTTP=1; shift ;;
    *) dief "Unknown arg: %s" "$1" ;;
  esac
done

TARGET_USER=${TARGET_USER:-${SUDO_USER-}}

# Sanity Checks ---------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || dief "Please run with sudo."
[ -n "$TARGET_USER" ] || dief "Error determining user."
[ -n "$GITHUB_USER" ] || dief "Missing -g <github_user>"
[ -f /etc/debian_version ] || dief "This script only runs on Debian."
[ -n "${SSH_CONNECTION-}" ] && dief "Refusing to run over SSH (console only)."
id "$TARGET_USER" >/dev/null 2>&1 || dief "Error: user '%s' does not exist." "$TARGET_USER"

case "$SSH_PORT" in
  ''|*[!0-9]* ) dief "Invalid port: %s" "$SSH_PORT" ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  dief "Invalid port range: %s" "$SSH_PORT"
fi

home_dir=$(getent passwd "$TARGET_USER" | awk -F: '{print $6}')
[ -n "$home_dir" ] && [ -d "$home_dir" ] || dief "Home directory for %s not found" "$TARGET_USER"

ssh_dir="$home_dir/.ssh"

# ensure ~/.ssh exists and is private
if [ ! -d "$ssh_dir" ]; then
  mkdir -p "$ssh_dir" || dief "Failed to create %s" "$ssh_dir"
  chown "$TARGET_USER:$TARGET_USER" "$ssh_dir"
  chmod 700 "$ssh_dir"
fi

# Temp files ------------------------------------------------------------------

tmp_keys=$(mktemp)
git_sorted=$(mktemp)
current_block=$(mktemp)
tmp_out=$(mktemp "$ssh_dir/.authorized_keys.tmp.XXXXXX")

cleanup_tmp() {
  rm -f "$tmp_keys" "${tmp_keys}.filtered" "$git_sorted" "$current_block" "$tmp_out" 2>/dev/null || true
}
trap cleanup_tmp EXIT

# Main ------------------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
apt-get update || dief "apt-get update failed"
apt-get install -y curl openssh-server ufw fail2ban ca-certificates || dief "apt-get install failed"

# ---- Install GitHub SSH keys

auth_keys="$ssh_dir/authorized_keys"
begin="# >>> managed-by-data-init >>>"
end="# <<< managed-by-data-init <<<"

# download GitHub keys
if ! curl -fsSL --connect-timeout 10 --max-time 20 --proto '=https' --proto-redir '=https' "https://github.com/${GITHUB_USER}.keys" >"$tmp_keys"; then
  dief "Failed to download GitHub keys for %s" "$GITHUB_USER"
fi

# keep non-empty lines only
awk 'NF' "$tmp_keys" > "${tmp_keys}.filtered"
[ -s "${tmp_keys}.filtered" ] || dief "No public keys returned for %s" "$GITHUB_USER"

# prepare a sorted unique list of GitHub keys
sort -u "${tmp_keys}.filtered" >"$git_sorted"

# extract managed block if present and sort it for comm
awk -v b="$begin" -v e="$end" '
  inblk && $0==e { inblk=0; next }
  $0==b { inblk=1; next }
  inblk { print }
' "$auth_keys" 2>/dev/null | sort -u >"$current_block"

total_git_keys=$(wc -l <"$git_sorted")
if [ -s "$current_block" ]; then
  dup_key_count=$(comm -12 "$git_sorted" "$current_block" | wc -l | awk '{print $1}')
else
  dup_key_count=0
fi
added_key_count=$(( total_git_keys - dup_key_count ))

# write merged output
{
  # preserve non-managed content (if any)
  if [ -f "$auth_keys" ]; then
    awk -v b="$begin" -v e="$end" '
      $0==b { inblk=1; next }
      $0==e { inblk=0; next }
      !inblk { print }
    ' "$auth_keys"
  fi

  # fresh managed block
  printf '%s\n' "$begin"
  cat "$git_sorted"
  printf '%s\n' "$end"
} >"$tmp_out"

# move into place
chown "$TARGET_USER:$TARGET_USER" "$tmp_out" 2>/dev/null || true
chmod 600 "$tmp_out" || true
sync; mv -f "$tmp_out" "$auth_keys"

# ---- Harden sshd

sshd_main="/etc/ssh/sshd_config"
sshd_dir="/etc/ssh/sshd_config.d"
sshd_dropin="${sshd_dir}/99-bootstrap.conf"

install -d -m 755 "$sshd_dir"

cat >"$sshd_dropin" <<EOF
Port ${SSH_PORT}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
chmod 644 "$sshd_dropin"

if ! sshd -t -f "$sshd_main"; then
  dief "sshd configuration test failed"
fi

systemctl enable ssh || { rc=$?; dief "Failed to enable ssh (rc=%d)" "$rc"; }
systemctl restart ssh || { rc=$?; dief "Failed to restart ssh (rc=%d)" "$rc"; }

# ---- UFW setup

ufw --force reset || { rc=$?; dief "ufw reset failed (rc=%d)" "$rc"; }
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment 'SSH'
if [ "$ALLOW_HTTP" -eq 1 ]; then
    ufw allow http
    ufw allow https
fi
ufw --force enable || { rc=$?; dief "ufw enable failed (rc=%d)" "$rc"; }

# ---- Fail2ban minimal jail

fail2ban_dropin="/etc/fail2ban/jail.d/sshd.local"

install -d -m 755 /etc/fail2ban/jail.d
cat >"$fail2ban_dropin" <<EOF
[sshd]
enabled  = true
backend  = systemd
port     = ${SSH_PORT}
maxretry = 5
bantime  = 1h
findtime = 10m
EOF
chmod 644 "$fail2ban_dropin"

systemctl enable fail2ban || { rc=$?; dief "Failed to enable fail2ban (rc=%d)" "$rc"; }
systemctl restart fail2ban || { rc=$?; dief "Failed to restart fail2ban (rc=%d)" "$rc"; }
sleep 0.5
fail2ban-client ping >/dev/null 2>&1 || dief "Fail2ban not responding"

# ---- Summary

printf '\nInit complete.\n'
printf '  - GitHub keys: total=%s, added=%s, duplicates=%s\n' \
  "$total_git_keys" "$added_key_count" "$dup_key_count"
printf '  - SSH ready: ssh -p %s %s@<server-ip>\n' "$SSH_PORT" "$TARGET_USER"
if [ "$ALLOW_HTTP" -eq 1 ]; then
  printf '  - UFW active: allowing HTTP/HTTPS.\n'
else
  printf '  - UFW active.\n'
fi
printf '  - Fail2ban sshd jail active.\n'
