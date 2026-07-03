# Dev Container

This container is intended for extracting the needed EJBCA behavior into a new
Rust backend and React frontend while keeping the original Java/Gradle source
available for reference.

Included toolchains:

- Rust stable with `rustfmt` and `clippy`
- Node.js 22 for React/Vite development
- OpenJDK 21 for inspecting or building the existing EJBCA project with `./gradlew`
- Codex CLI, installed from `@openai/codex`
- CodeGraph CLI, installed from `@colbymchenry/codegraph`

Suggested ports:

- `5173` for a React/Vite frontend
- `3000` for a Rust API server
- `8080` and `8443` for HTTP/HTTPS service experiments

The global CLI package versions are pinned in `setup-tools.sh` for repeatable
container creation. Override `CODEX_CLI_PACKAGE` or `CODEGRAPH_PACKAGE` before
running the script if you need a different version.
