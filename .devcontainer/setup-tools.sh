#!/usr/bin/env bash
set -euo pipefail

CODEX_CLI_PACKAGE="${CODEX_CLI_PACKAGE:-@openai/codex@0.142.5}"
CODEGRAPH_PACKAGE="${CODEGRAPH_PACKAGE:-@colbymchenry/codegraph@1.2.0}"

echo "Installing global Node CLIs: ${CODEX_CLI_PACKAGE}, ${CODEGRAPH_PACKAGE}"
sudo env "PATH=${PATH}" npm install -g "${CODEX_CLI_PACKAGE}" "${CODEGRAPH_PACKAGE}"

if command -v corepack >/dev/null 2>&1; then
  sudo env "PATH=${PATH}" corepack enable
fi

mkdir -p "${HOME}/.ssh"

if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "${SSH_AUTH_SOCK:-}" ]; then
  echo "Using forwarded SSH agent at ${SSH_AUTH_SOCK}"
elif [ -d /tmp/host-ssh ]; then
  cp -a /tmp/host-ssh/. "${HOME}/.ssh/" 2>/dev/null || true
  echo "Copied host SSH config from /tmp/host-ssh"
fi

chmod 700 "${HOME}/.ssh" || true
find "${HOME}/.ssh" -type f -name "id_*" ! -name "*.pub" -exec chmod 600 {} \; 2>/dev/null || true
find "${HOME}/.ssh" -type f -name "*.pub" -exec chmod 644 {} \; 2>/dev/null || true
touch "${HOME}/.ssh/known_hosts"
chmod 644 "${HOME}/.ssh/known_hosts" || true

if ! ssh-keygen -F github.com >/dev/null 2>&1; then
  ssh-keyscan github.com >> "${HOME}/.ssh/known_hosts" 2>/dev/null || true
fi

if [ -z "${SSH_AUTH_SOCK:-}" ] && ! find "${HOME}/.ssh" -maxdepth 1 -type f -name "id_*" ! -name "*.pub" | grep -q .; then
  cat >&2 <<'EOF'
No SSH agent or private key was found in the devcontainer.
If your host keys are outside ~/.ssh, mount that directory to /tmp/host-ssh and rerun this script.
EOF
fi

git config --global --add safe.directory "$(pwd)" || true
git config --global core.autocrlf true
git config --global core.filemode false

echo "Toolchain versions:"
node --version
npm --version
rustc --version
cargo --version
java --version

if command -v gradle >/dev/null 2>&1; then
  gradle --version | head -n 3
elif [ -x ./gradlew ]; then
  echo "Gradle wrapper available: ./gradlew"
fi

command -v codex
codex --version || true

command -v codegraph
codegraph --version || true
