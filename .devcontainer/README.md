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

## SSH keys for GitHub

The dev container first uses SSH agent forwarding when VS Code provides it. If
there is no forwarded agent, it falls back to a read-only mount of the host
`%USERPROFILE%\.ssh` directory at `/tmp/host-ssh` and copies those files into
the container user's `~/.ssh` with Linux SSH permissions.

On Windows, you can still prefer agent forwarding by starting the OpenSSH
Authentication Agent on the host and adding your key before reopening the
container:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
ssh-add -l
```

After reopening the container, verify forwarding inside the container:
After reopening the container, verify GitHub SSH access inside the container:

```bash
ssh -T git@github.com
git ls-remote origin HEAD
```
