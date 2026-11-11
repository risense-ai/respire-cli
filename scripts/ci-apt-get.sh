#!/usr/bin/env bash
set -euo pipefail

# Hosted runner mirror lists repeatedly failed DNS for the Azure archive.
if [ -f /etc/apt/apt-mirrors.txt ]; then
  sudo sed -i '\|^[[:space:]]*https\?://azure\.archive\.ubuntu\.com/|d' /etc/apt/apt-mirrors.txt
fi

sudo apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 "$@"
