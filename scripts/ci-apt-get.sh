#!/usr/bin/env bash
set -euo pipefail

# The approved fallback applies only to the audited amd64 noble mirror layout.
if [ "$(uname -m)" = x86_64 ] &&
   [ "$(dpkg --print-architecture)" = amd64 ] &&
   (. /etc/os-release; [ "${VERSION_CODENAME:-}" = noble ]) &&
   [ -f /etc/apt/apt-mirrors.txt ] &&
   [ -f /etc/apt/sources.list.d/ubuntu.sources ] &&
   [ -s /usr/share/keyrings/ubuntu-archive-keyring.gpg ] &&
   awk '
     BEGIN { RS = "\n[ \t\r]*\n"; FS = "\n" }
     {
       uri = key = disabled = 0
       for (i = 1; i <= NF; i++) {
         if ($i ~ /^URIs:[[:space:]]+mirror\+file:\/etc\/apt\/apt-mirrors\.txt[[:space:]]*$/) uri = 1
         if ($i ~ /^Signed-By:[[:space:]]+\/usr\/share\/keyrings\/ubuntu-archive-keyring\.gpg[[:space:]]*$/) key = 1
         if (tolower($i) ~ /^enabled:[[:space:]]*no[[:space:]]*$/) disabled = 1
       }
       if (uri && key && !disabled) found = 1
     }
     END { exit !found }
   ' /etc/apt/sources.list.d/ubuntu.sources; then
  sudo sed -i '\|^[[:space:]]*https\?://azure\.archive\.ubuntu\.com/|d' /etc/apt/apt-mirrors.txt
  apt_mirror=$'https://mirror.us.leaseweb.net/ubuntu/\tpriority:0'
  if ! grep -Fxq "$apt_mirror" /etc/apt/apt-mirrors.txt; then
    printf '%s\n' "$apt_mirror" | sudo tee -a /etc/apt/apt-mirrors.txt >/dev/null
  fi
fi

sudo apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 "$@"
