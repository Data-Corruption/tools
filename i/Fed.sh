#!/bin/sh
#
# Minimum init for headless Fedora Server 43+. Not run over ssh. ~POSIX
# - Adds GitHub SSH keys
# - Harden sshd:
#   - Disable password / root login
#   - Changes SSH port (with SELinux labeling)
# - Sets up firewalld and Fail2ban
#   - '--http' to allow HTTP/S ports in firewalld
#   - '--shell' to install basic QoL tools
#   - '--cockpit' to allow Cockpit web console (port 9090). Skip this for security critical stuff.
# - Enables user lingering for systemd user services
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/Data-Corruption/tools/main/i/Fed.sh | sudo sh -s -- -g Data-Corruption -p 22 --http --shell --cockpit

set -eu
umask 077

TARGET_USER=""
GITHUB_USER=""
SSH_PORT=22
ALLOW_HTTP=0
ALLOW_COCKPIT=0
SHELL_QOL=0
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
    --shell) SHELL_QOL=1; shift ;;
    --cockpit) ALLOW_COCKPIT=1; shift ;;
    *) dief "Unknown arg: %s" "$1" ;;
  esac
done

TARGET_USER=${TARGET_USER:-${SUDO_USER-}}

# Sanity Checks ---------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || dief "Please run with sudo."
[ -n "$TARGET_USER" ] || dief "Error determining user."
[ -n "$GITHUB_USER" ] || dief "Missing -g <github_user>"
[ -f /etc/fedora-release ] || dief "This script only runs on Fedora."
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

dnf install -y curl openssh-server firewalld fail2ban ca-certificates policycoreutils-python-utils || dief "dnf install failed"
dnf -y makecache || dief "dnf makecache failed"

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

# ---- SELinux port labeling for custom SSH port

if command -v semanage >/dev/null 2>&1 && [ "$SSH_PORT" -ne 22 ]; then
  semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || \
  semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || {
    rc=$?
    dief "Failed to label SSH port %d for SELinux (rc=%d). sshd will not start." "$SSH_PORT" "$rc"
  }
fi

sshd -t || dief "sshd configuration test failed"
sshd -T | grep -q "^port $SSH_PORT$" || dief "sshd not using port %s" "$SSH_PORT"

systemctl enable sshd || { rc=$?; dief "Failed to enable sshd (rc=%d)" "$rc"; }
systemctl restart sshd || { rc=$?; dief "Failed to restart sshd (rc=%d)" "$rc"; }

# ---- firewalld setup

systemctl enable firewalld || { rc=$?; dief "Failed to enable firewalld (rc=%d)" "$rc"; }
systemctl start firewalld || { rc=$?; dief "Failed to start firewalld (rc=%d)" "$rc"; }

# Allow SSH (custom port or default service)
if [ "$SSH_PORT" -ne 22 ]; then
  # Remove default ssh service and add custom port
  firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" || { rc=$?; dief "firewalld add ssh port failed (rc=%d)" "$rc"; }
else
  firewall-cmd --permanent --add-service=ssh || { rc=$?; dief "firewalld add ssh failed (rc=%d)" "$rc"; }
fi

if [ "$ALLOW_HTTP" -eq 1 ]; then
  firewall-cmd --permanent --add-service=http || { rc=$?; dief "firewalld add http failed (rc=%d)" "$rc"; }
  firewall-cmd --permanent --add-service=https || { rc=$?; dief "firewalld add https failed (rc=%d)" "$rc"; }
fi

if [ "$ALLOW_COCKPIT" -eq 1 ]; then
  firewall-cmd --permanent --add-service=cockpit || { rc=$?; dief "firewalld add cockpit failed (rc=%d)" "$rc"; }
fi

firewall-cmd --reload || { rc=$?; dief "firewalld reload failed (rc=%d)" "$rc"; }

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
banaction = firewallcmd-rich-rules
EOF
chmod 644 "$fail2ban_dropin"

systemctl enable fail2ban || { rc=$?; dief "Failed to enable fail2ban (rc=%d)" "$rc"; }
systemctl restart fail2ban || { rc=$?; dief "Failed to restart fail2ban (rc=%d)" "$rc"; }
sleep 0.5
fail2ban-client ping >/dev/null 2>&1 || dief "Fail2ban not responding"

# ---- Enable user lingering (for systemd user services without login)

linger_file="/var/lib/systemd/linger/$TARGET_USER"
if [ ! -f "$linger_file" ]; then
  loginctl enable-linger "$TARGET_USER" || {
    printf 'Warning: Failed to enable lingering for %s. User services may not start on boot.\n' "$TARGET_USER" >&2
  }
fi

# ---- Shell QOL (optional)

if [ "${SHELL_QOL:-0}" -eq 1 ]; then
  dnf install -y \
    bash-completion \
    tmux \
    ncdu \
    ripgrep \
    tealdeer \
    btop \
    nvtop \
    || dief "dnf install (shell-min) failed"

  profile_dropin="/etc/profile.d/99-shell-min.sh"
  cat >"$profile_dropin" <<'EOF'
# managed-by-data-init: minimal interactive shell defaults
# Applies to interactive shells only.
case $- in *i*) ;; *) return ;; esac

# History: bigger + timestamped + less duplication
export HISTSIZE=50000
export HISTFILESIZE=100000
export HISTTIMEFORMAT='%F %T '
export HISTCONTROL=ignoreboth:erasedups

# Editor default (do not override user choice)
: "${EDITOR:=nano}"

# Safe convenience aliases
alias ll='ls -alF'
alias la='ls -A'
alias ..='cd ..'

# Optional: lightly colorize user@host in purple for bash, only if prompt isn't already customized.
# Tries hard not to stomp on existing fancy prompts.
if [ -n "${BASH_VERSION-}" ]; then
  # If PS1 already contains ANSI escapes or bracketed escapes, assume it's customized.
  case "${PS1-}" in
    *$'\033['*|*'\'\['*|*'\\['*|*'\e['*) : ;;
    *)
      # Only do this when terminal likely supports color
      if command -v tput >/dev/null 2>&1; then
        cols=$(tput colors 2>/dev/null || echo 0)
      else
        cols=0
      fi
      if [ "${cols:-0}" -ge 8 ]; then
        # Purple user@host, rest default-ish
        PS1='\[\033[35m\]\u@\h\[\033[0m\]:\w\$ '
        export PS1
      fi
    ;;
  esac
fi
EOF
  chmod 644 "$profile_dropin" || true
fi


# ---- Summary

printf '\nInit complete.\n'
printf '  - GitHub keys: total=%s, added=%s, duplicates=%s\n' \
  "$total_git_keys" "$added_key_count" "$dup_key_count"
printf '  - SSH ready: ssh -p %s %s@<server-ip>\n' "$SSH_PORT" "$TARGET_USER"
if [ "$SSH_PORT" -ne 22 ]; then
  printf '  - SELinux: port %d labeled as ssh_port_t.\n' "$SSH_PORT"
fi
printf '  - firewalld active'
if [ "$ALLOW_HTTP" -eq 1 ] && [ "$ALLOW_COCKPIT" -eq 1 ]; then
  printf ': allowing HTTP/HTTPS, Cockpit.\n'
elif [ "$ALLOW_HTTP" -eq 1 ]; then
  printf ': allowing HTTP/HTTPS.\n'
elif [ "$ALLOW_COCKPIT" -eq 1 ]; then
  printf ': allowing Cockpit.\n'
else
  printf '.\n'
fi
printf '  - Fail2ban sshd jail active.\n'
if [ -f "$linger_file" ]; then
  printf '  - User lingering enabled for %s.\n' "$TARGET_USER"
else
  printf '  - Warning: User lingering not enabled.\n'
fi
if [ "${SHELL_QOL:-0}" -eq 1 ]; then
  printf '  - Shell (minimal QoL): enabled\n'
  printf '    - Packages: tmux ncdu bash-completion ripgrep tealdeer btop nvtop\n'
  printf '    - Defaults: extended history, EDITOR=nano (if unset), basic aliases\n'
  printf '    - Prompt: subtle user@host color (only if no existing customization)\n'
fi
