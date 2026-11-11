#!/usr/bin/env bash
set -euo pipefail

# The approved fallback applies only to the audited amd64 noble mirror layout.
if [ "$(uname -m)" = x86_64 ] &&
   [ "$(dpkg --print-architecture)" = amd64 ] &&
   (. /etc/os-release; [ "${VERSION_CODENAME:-}" = noble ]) &&
   [ -f /etc/apt/apt-mirrors.txt ] &&
   [ -f /etc/apt/sources.list.d/ubuntu.sources ] &&
   [ -s /usr/share/keyrings/ubuntu-archive-keyring.gpg ] &&
   grep -qE '^URIs:[[:space:]]+mirror\+file:/etc/apt/apt-mirrors\.txt[[:space:]]*$' /etc/apt/sources.list.d/ubuntu.sources &&
   grep -qE '^Signed-By:[[:space:]]+/usr/share/keyrings/ubuntu-archive-keyring\.gpg[[:space:]]*$' /etc/apt/sources.list.d/ubuntu.sources; then
  sudo sed -i '\|^[[:space:]]*https\?://azure\.archive\.ubuntu\.com/|d' /etc/apt/apt-mirrors.txt
  apt_mirror=$'https://mirror.us.leaseweb.net/ubuntu/\tpriority:0'
  if ! grep -Fxq "$apt_mirror" /etc/apt/apt-mirrors.txt; then
    printf '%s\n' "$apt_mirror" | sudo tee -a /etc/apt/apt-mirrors.txt >/dev/null
  fi
fi

sudo apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 "$@"
