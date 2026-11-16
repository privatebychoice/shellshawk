# shellshawk

A self-hosted, privacy-first BBS with an SSH TUI, SFTP, and an optional web
interface. See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

> **Status:** stage 4: SSH server, accounts, and the TUI core — full-screen
> and screen-reader (line) interfaces, themes, terminal profiles, standard
> form controls, registration, add-key, display settings, SSH key
> management, a terminal test, and basic administration (approvals and
> invites). Conferences, messages, chat and the other plugins come later.

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
| `SHELLSHAWK_SSH_ADDR` | no | disabled | `host:port` for the SSH server; unset = SSH disabled |
| `SHELLSHAWK_SSH_HOST_KEY` | with SSH | — | Ed25519 host key file; generated (mode `0600`) if missing. Refused if group/world accessible |
| `SHELLSHAWK_SSH_MAX_CONNS` | no | `100` | Maximum concurrent SSH connections |
| `SHELLSHAWK_INVITE_USER` | no | `new` | SSH login name for registering with an invite code |
| `SHELLSHAWK_AUDIT_RETENTION_DAYS` | no | `365` | Audit log entries older than this are purged daily |
| `SHELLSHAWK_HTTP_ADDR` | no | disabled | `host:port` for the web interface; unset = web disabled |
| `SHELLSHAWK_LOG_LEVEL` | no | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `SHELLSHAWK_LOG_FORMAT` | no | `text` | `text` or `json` |

Example (values are examples only):

```bash
SHELLSHAWK_DB_PATH="$HOME/shellshawk/bbs.db" \
SHELLSHAWK_SSH_ADDR="127.0.0.1:2222" \
SHELLSHAWK_SSH_HOST_KEY="$HOME/shellshawk/ssh_host_ed25519_key" \
SHELLSHAWK_HTTP_ADDR="127.0.0.1:8080" \
./bin/shellshawk
```

## First administrator

With the same environment variables set, run:

```bash
./bin/shellshawk bootstrap-invite
```

It prints a single-use invite code (valid 24 hours) that registers an
administrator without approval. It only works while no active administrator
exists, and running it again revokes the previous unused code.

## Accounts and logins

| Login | How | Result |
|-------|-----|--------|
| Public key | Any of the account's keys (max 3) | Full BBS (active) or a status screen (pending approval) |
| Invite | User `new` (configurable), invite code as password | Registration wizard only |
| Password | Username + account password | Add-a-key screen only — a password never grants BBS access |

Passwords must be 15–256 characters (NIST SP 800-63B-4, single-factor),
hashed with argon2id. Password attempts are rate-limited: 5 failures per
account and 10 per IP address in 15 minutes. Invite codes are 128-bit,
stored only as SHA-256 hashes, and shown once.

Built-in groups: `admin` (`core.admin`, implies everything), `moderator`
(approve accounts, create invites) and `member` (default). Nobody can grant a
permission, assign a group, or attach a group to an invite unless they hold
every permission involved, and the last active administrator cannot be
removed or locked.

## Using the TUI

- **Full screen** (default): Tab / Shift-Tab move between fields, Ctrl-S
  submits a form, Esc goes back. Menus accept arrow keys or the item number.
- **Screen reader mode**: no colours, no screen drawing — every screen starts
  with `Screen: <name>`, fields are asked one at a time, and long pages pause
  every N lines. Choose it at registration (type `s`), or later under
  *Display settings → Terminal type*. Clients that do not request a terminal
  (e.g. `ssh -T`) always get this mode.
- **Terminal types**: Modern (24-bit colour), PuTTY (256 colours, italic as a
  colour), Basic (16 colours, ASCII), Screen reader. Bold and italic can each
  be shown as real bold/italic, a highlight colour, underline, or not at all —
  use *Terminal test* to see what your terminal supports.
- **Themes**: Classic BBS, Amber Terminal, Green Phosphor, Dark, Light and
  High Contrast. Text colours meet WCAG AA contrast (AAA for High Contrast),
  enforced by tests.

All user-supplied text is stripped of control characters and escape
sequences before it is written to anyone's terminal.

## Endpoints

| Path | Description |
|------|-------------|
| `GET /version` | `{"version","commit","buildDate"}`. Use it to confirm a deploy is running the expected build |

## SSH security policy

| Area | Allowed |
|------|---------|
| Key exchange | `mlkem768x25519-sha256` (post-quantum hybrid, preferred), `curve25519-sha256` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` |
| Host key | Ed25519 |
| User keys | Ed25519, ECDSA P-256, FIDO (`sk-*`), RSA ≥ 3072 bits with SHA-2 signatures |
| Channels | `session` only — no port forwarding, X11, agent forwarding |
| Session requests | `pty-req`, `window-change`, `shell`, `env` (`LANG`, `LC_ALL`, `LC_CTYPE`, `COLORTERM`). No `exec`; `sftp` arrives in stage 7 |

shellshawk never starts OS processes; a test fails the build if `os/exec`
is imported anywhere.

## Privacy

Logs never contain client IP addresses, user agents, cookies, query strings,
or attempted SSH user names. Client IP addresses are held in memory only, for
rate limiting.
shellshawk makes no outbound network requests.
