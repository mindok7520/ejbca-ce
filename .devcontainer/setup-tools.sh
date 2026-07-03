#!/usr/bin/env bash
set -euo pipefail

CODEX_CLI_PACKAGE="${CODEX_CLI_PACKAGE:-@openai/codex@0.142.5}"
CODEGRAPH_PACKAGE="${CODEGRAPH_PACKAGE:-@colbymchenry/codegraph@1.2.0}"

echo "Installing global Node CLIs: ${CODEX_CLI_PACKAGE}, ${CODEGRAPH_PACKAGE}"
sudo env "PATH=${PATH}" npm install -g "${CODEX_CLI_PACKAGE}" "${CODEGRAPH_PACKAGE}"

if command -v corepack >/dev/null 2>&1; then
  sudo env "PATH=${PATH}" corepack enable
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
