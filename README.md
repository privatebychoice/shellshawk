# shellshawk

A self-hosted, privacy-first BBS with an SSH TUI, SFTP, and an optional web
interface. See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

> **Status:** stage 1 (skeleton): configuration, SQLite with migrations,
> structured logging, and a `/version` endpoint. SSH, TUI and the rest
> follow the build order in the design doc.

## Build

Requires Go 1.27+. No C toolchain is needed (`CGO_ENABLED=0`).

```bash
make build         # bin/shellshawk for this machine
make build-linux   # bin/shellshawk-linux-{amd64,arm64}
make check         # gofmt, vet, tests, govulncheck
make bump          # increment the build number in VERSION before a deploy
```

## Configure

All configuration comes from environment variables. Addresses and paths have
no built-in defaults.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHELLSHAWK_DB_PATH` | yes | — | SQLite database file (created if missing) |
| `SHELLSHAWK_HTTP_ADDR` | no | disabled | `host:port` for the web interface; unset = web disabled |
| `SHELLSHAWK_LOG_LEVEL` | no | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `SHELLSHAWK_LOG_FORMAT` | no | `text` | `text` or `json` |

Example (values are examples only):

```bash
SHELLSHAWK_DB_PATH="$HOME/shellshawk/bbs.db" \
SHELLSHAWK_HTTP_ADDR="127.0.0.1:8080" \
./bin/shellshawk
```

## Endpoints

| Path | Description |
|------|-------------|
| `GET /version` | `{"version","commit","buildDate"}`. Use it to confirm a deploy is running the expected build |

## Privacy

Logs never contain client IP addresses, user agents, cookies or query strings.
shellshawk makes no outbound network requests.
