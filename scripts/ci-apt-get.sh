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
elif [ "$(uname -m)" = aarch64 ] &&
     [ "$(dpkg --print-architecture)" = arm64 ] &&
     (. /etc/os-release; [ "${VERSION_CODENAME:-}" = noble ]) &&
     [ -f /etc/apt/sources.list.d/ubuntu.sources ] &&
     [ -s /usr/share/keyrings/ubuntu-archive-keyring.gpg ]; then
  # ARM64 uses direct ports sources, not the amd64 mirror list.
  ports_updates=$(awk '
    function finish() {
      if (uri && key && !disabled && !unsupported && uris == 1 && keys == 1 && suites == 1)
        print uri "s|http://ports[.]ubuntu[.]com/ubuntu-ports/*|https://mirror.us.leaseweb.net/ubuntu-ports/|"
      uri = key = disabled = unsupported = uris = keys = suites = 0
      field = ""
    }
    /^[[:space:]]*$/ { finish(); next }
    /^[^#[:space:]][^:]*:/ {
      field = tolower(substr($0, 1, index($0, ":") - 1))
      if (field == "uris") uris++
      if (field == "signed-by") keys++
      if (field == "suites") suites++
    }
    /^[[:space:]]/ {
      if (field == "uris" || field == "signed-by" || field == "enabled" || field == "suites") unsupported = 1
    }
    /^URIs:/ {
      if ($0 ~ /^URIs:[[:space:]]+http:\/\/ports\.ubuntu\.com\/ubuntu-ports\/?[[:space:]]*$/) uri = NR
    }
    /^Signed-By:/ {
      if ($0 ~ /^Signed-By:[[:space:]]+\/usr\/share\/keyrings\/ubuntu-archive-keyring\.gpg[[:space:]]*$/) key = 1
    }
    /^Suites:/ {
      if ($0 !~ /^Suites:[[:space:]]+noble(-updates|-backports|-security)?([[:space:]]+noble(-updates|-backports|-security)?)*[[:space:]]*$/) unsupported = 1
    }
    tolower($0) ~ /^enabled:/ {
      if (tolower($0) !~ /^enabled:[[:space:]]+yes[[:space:]]*$/) disabled = 1
    }
    END { finish() }
  ' /etc/apt/sources.list.d/ubuntu.sources)
  if [ -n "$ports_updates" ]; then
    printf '%s\n' "$ports_updates" | sudo sed -i -f - /etc/apt/sources.list.d/ubuntu.sources
  else
    printf '%s\n' 'ARM64 ports fallback skipped: no matching active Ubuntu source stanza' >&2
  fi
fi

sudo apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 "$@"
