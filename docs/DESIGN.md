# shellshawk — Design Document

> Status: **v0.2** — all open decisions resolved (see §13).

shellshawk is a self-hosted BBS with three front doors, all served by **one Go
binary** and **one SQLite database**:

| Front door | Transport | Purpose |
|------------|-----------|---------|
| TUI | SSH (`session` channel, PTY) | Primary interface, full features |
| SFTP | SSH (`sftp` subsystem) | Uploads, downloads, data sync over a virtual file system |
| Web | HTTPS (`net/http`) | Optional, limited parity, markdown-first output |

---

## 1. Decisions already made

| Topic | Decision |
|-------|----------|
| Language | Go **1.27.x** |
| SSH | `golang.org/x/crypto/ssh` (server side) |
| TUI | In-house widget/render layer (no Charm stack) |
| SQLite | `modernc.org/sqlite` (pure Go, no cgo → clean macOS→Linux cross-compile) |
| Plugins | Compiled-in registry (Go packages implementing a `Plugin` interface) |
| Link grading | `go.privatebychoice.com/pbc-classification`, loaded with `WithDataFile(<path from config>)` |
| Module path | `go.privatebychoice.com/shellshawk` |
| Markdown parser | `github.com/yuin/goldmark` (raw HTML disabled), custom renderers |
| SFTP | `github.com/pkg/sftp` — `RequestServer` API only |

---

## 2. Hard security boundaries

These are invariants, enforced in code and covered by tests:

1. **No OS access, ever.** The SSH server only accepts `session` channels with
   `pty-req`, `window-change`, `shell` (→ BBS TUI), and `subsystem sftp` (→
   virtual FS). Rejected: `exec`, `env` (except `LANG`, `LC_ALL`,
   `LC_CTYPE`, `COLORTERM`; the terminal type arrives via `pty-req`), `x11-req`, `auth-agent-req@openssh.com`, `direct-tcpip`,
   `tcpip-forward`, and every other channel/request type. No call to
   `os/exec` anywhere in the codebase (enforced by a lint/test that greps the
   module).
2. **SFTP is fully virtual.** SFTP paths map to plugin-registered handlers that
   read/write SQLite rows. There is no mapping to the host file system.
3. **Crypto policy (modern only, PQ preferred).**
   - KEX: `mlkem768x25519-sha256` (post-quantum hybrid, preferred),
     `curve25519-sha256`, `curve25519-sha256@libssh.org`. Nothing else.
     x/crypto implements the ML-KEM hybrid but at last check it may not be in
     the *default* list, so shellshawk sets `KeyExchanges` explicitly.
   - Ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
     `aes128-gcm@openssh.com`.
   - MACs: only relevant for non-AEAD ciphers → none needed; if required,
     `hmac-sha2-256-etm@openssh.com` / `hmac-sha2-512-etm@openssh.com`.
   - Host key: Ed25519 (generated on first run, path from config, `0600`).
   - User keys accepted: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
     `ecdsa-sha2-nistp256`, `sk-ecdsa-sha2-nistp256@openssh.com`,
     `rsa-sha2-256/512` with ≥3072-bit modulus (`ssh-rsa`/SHA-1 rejected).
4. **Authentication.**
   - Public key is the only way into an existing account.
   - Password auth exists **only** for: (a) the invite/registration flow and
     (b) a logged-in user adding a public key. A password login never grants
     the main menu. *(See §6 for the flow.)*
   - Max **3** public keys per user.
   - Rate limiting and lockout on failed attempts per IP and per account, kept
     in memory plus an audit row.
5. **Input sanitisation.** All user content is stored as markdown source and
   rendered through one renderer (§8) with raw HTML disabled. Terminal output
   strips all C0/C1 control characters and escape sequences from user content
   before the theme adds its own, so users cannot inject ANSI/OSC sequences
   (title changes, clipboard writes, hyperlinks) into other users' terminals.

---

## 3. Architecture

```
cmd/shellshawk/          main: config, migrations, start servers
internal/config/         env + config file loading (no hardcoded paths/ports)
internal/store/          SQLite access, migrations, transactions
internal/auth/           users, keys, passwords (argon2id), sessions
internal/perm/           groups, permissions, checks
internal/invite/         invite codes, approval queue
internal/privacy/        visibility rules, friends graph queries, erasure
internal/sshd/           x/crypto/ssh server, channel/request filtering
internal/sftpd/          virtual FS router → plugin SFTP handlers
internal/web/            net/http server, templates, GPC, CSP
internal/tui/            terminal, screen, input loop, layout
internal/tui/widgets/    standard controls (§7)
internal/form/           control + validation definitions shared by TUI & Web
internal/markdown/       parser → AST → renderers (web, tui-modern, tui-putty, tui-accessible)
internal/theme/          themes, terminal profiles
internal/linkgrade/      wrapper around pbc-classification
internal/plugin/         Plugin interface, registry, host API
plugins/conferences/ polls/ contacts/ messages/ userlist/ chat/
themes/                  built-in theme files (embedded)
docs/
```

### 3.1 Plugin interface (sketch)

```go
type Plugin interface {
    Manifest() Manifest                 // id, name, version, permissions it defines, settings schema
    Migrations() []store.Migration      // plugin-owned tables, prefixed by plugin id
    Init(h Host) error                  // Host = store, perm, privacy, events, logger, settings
    MenuItems() []tui.MenuItem          // optional
    WebRoutes() []web.Route             // optional
    SFTPRoutes() []sftpd.Route          // optional, read/write declared per route
}
```

- Plugins **never** get the raw `*sql.DB` of other plugins; they get a scoped
  store handle plus the core APIs (users, groups, contacts, privacy check).
- Every route/menu item declares the permission it needs; the host checks it
  before calling the plugin (deny by default).
- **Settings**: the manifest declares settings using the standard form controls
  (§7), so the admin TUI can render a settings screen for any plugin without
  plugin-specific UI code.
- Plugins publish/subscribe to an in-process event bus (e.g.
  `user.erased`, `user.renamed`, `group.changed`) — this is how Right to Forget
  reaches plugin data (§5).

Implementation notes (stage 6): `plugin.Manifest` carries the ID,
permissions (each with optional default groups, granted once and never
re-granted after an admin revokes them), settings (`form.Field` + default),
migrations and menu items; `Init(ctx, *Host)` receives the shared DB,
permission and account services, the event bus and the plugin's own
settings. Migrations may only create, alter or drop `<id>_` objects and may
only attach indexes/triggers to them (checked at load). This is a
convention check, not a security boundary: plugins are trusted, compiled-in
code. Web routes and SFTP routes are added to the manifest in stages 10
and 7.

### 3.2 Configurable menu system

Menus are stored in SQLite (editable from the admin menu: rename, move,
extra permission, submenus, reset) as a tree of entries. New menu items
(core or plugin) are added at the end of the main menu the first time they
are seen; removed items are not re-added. *Administration* cannot be
deleted. Logging out is not an entry but `q` (or Esc) in the main menu;
core migration 7 removed the earlier *Log out* entry. Entries whose item no longer exists are hidden from members and
flagged in the editor. Previously sketched as:
`{key, label, target(plugin:item | submenu), required_permission, order}`. A
default menu is seeded on first run. Users only see entries they are permitted
to use.

---

## 4. Users, groups, permissions, invites

- **Permissions** are strings namespaced by owner: `core.admin`,
  `core.invite.create`, `conferences.post`, `chat.channel.create`, …
- **Groups** hold permissions; users hold groups. Effective permissions = union.
- Built-in groups: `admin`, `moderator`, `member`. Accounts awaiting approval
  have status `pending` (rather than a `pending` group) and hold no
  permissions until approved; status `locked` blocks all logins.
- Escalation rules: an actor can only grant permissions, assign groups, or
  attach groups to invites if they hold every permission involved, and can
  only approve/reject/lock accounts whose permissions they fully hold. The
  last active administrator cannot be removed or locked.
- Locking an account publishes `user.locked`; `sessions.Service` ends every
  open SSH connection of the account (`presence.Conns.EndUser`) with a
  `*presence.Disconnect` cause, so the member is told why. Web sessions
  and live streams already re-check that the account is active.
- Recovery: `shellshawk unlock USERNAME` (operator CLI) unlocks a locked
  account without a login, audited as the system actor. Whoever can run it
  can already edit the database, so it grants nothing new.
- First administrator: `shellshawk bootstrap-invite` (operator CLI) prints a
  single-use admin invite, only while no active administrator exists.
- Resource-level checks (e.g. "conference X requires group Y") are stored on the
  resource by the plugin that owns it and checked against the member's groups
  (`perm.Service.UserGroupIDs`).
- **Invites**: codes are random 128-bit Crockford base32 in dash-separated
  groups, stored as SHA-256 hashes, with optional expiry, max uses, the inviting user,
  and default groups to assign.
- **Approval**: configurable per invite or globally — new accounts land in
  `pending` until an admin/moderator approves.

### 4.1 Connection limits and ending connections

- `presence.Conns` records every authenticated SSH connection in memory
  (account, login mode, terminal/SFTP sessions open, start, last input).
  No address is recorded. `sshd` registers each connection after
  authentication and enforces the per-account limit there, atomically
  (`presence.ErrTooMany`). Accounts registering with an invite (user 0) are
  not limited. A refused connection has its terminal and shell requests
  granted, so the client prints the reason (stderr) and exits with status
  1 instead of reporting a failed request.
- Limits live in `system_settings` (`ssh.idle_timeout_minutes`, default
  30, 0 or 2–1440; `ssh.max_connections_per_user`, default 3, 0–20) and are
  read through `sshd.Config.Limits` on every check, so changes need no
  restart.
- Idle: reading from any channel of the connection counts as activity;
  keepalives, window changes and output do not. A watcher per connection
  checks at most every 10 seconds (more often for short timeouts). It
  sends interactive sessions a warning (`Session.IdleWarning`) before the
  timeout, a minute or a quarter of the timeout, and never ends a
  connection that has not had its full warning period (WCAG 2.2.1 Timing
  Adjustable: warn and let the member extend with one keystroke).
  `term.Terminal.Notify` shows the warning without involving the screen in
  progress: its own line in line mode; in full screen a reverse-video
  bottom line drawn with save/restore cursor, followed by a forced redraw
  (a `KeyResize` event) before the next key.
- Ending a connection on purpose (idle, or by staff) cancels the
  connection's context with a `*presence.Disconnect` cause. Sessions get
  5 seconds to finish: the BBS closes its UI (restoring the terminal from
  the alternate screen) and then writes the cause's message.
- `sessions.Service` (permission `core.sessions.manage`, not granted to
  moderators by default) lists connections with usernames and ends one.
  Ending uses `perm.RequireOutranks`, so the actor must hold every
  permission the target account holds; it is audited as
  `connection.ended`. A staff member cannot end their own current
  connection from the list; `q` in the main menu does that.

---

## 5. Privacy

### 5.1 Profile visibility

Each field has a visibility setting: **Public**, **Friends Only**, **No One**.

| Field | Default |
|-------|-------------------------|
| Full name | No One |
| Email | No One |
| Phone | No One |
| Status | Friends Only |
| Last login timestamp | No One |
| Direct messages (who may DM me) | Friends Only |

Defaults are privacy-first; users opt *in* to sharing.

**Friend = mutual contact** (both users have each other in their contacts).
One-sided adds never grant Friends Only visibility.

**Admins** can see a user's **email only** (for recovery/contact), regardless of
its visibility setting; every such view is audit-logged. All other No One
fields are hidden from admins too.

### 5.1.1 Implementation notes (stage 9)

Visibility is stored per member and field (only changed fields have rows);
"Online now" uses the same rules (default Friends only). Messages honour the
recipient's "who can send you private messages" setting and name who
refused. The admin email view requires `core.users.manage` and writes an
`admin.viewed.email` audit entry.

### 5.2 Right to forget

Two user-facing actions, both in Profile → Privacy, both available in TUI and Web:

**A. Export my data** — creates a markdown/JSON bundle readable over SFTP at
`/me/export/` (profile, posts, messages sent/received, contacts, votes, chat
lines). Supports GDPR-style access and portability, and lets users keep a copy
before erasing.

**B. Erase my account** — a two-step process:

1. **Request** → requires re-authentication by public key (a fresh SSH login)
   and typing the username. The account is locked immediately (cannot log in,
   hidden from listings).
2. **Grace period** (configurable, default **14 days**) → the user can cancel by
   contacting an admin. The user also picks content handling now:
   **(a)** delete posts and chat lines, or **(b)** keep them under the tombstone.
3. **Erasure** → a core job publishes `user.erased`; each plugin handles its data
   per the table below; core then deletes the user row.

| Data | Proposed handling |
|------|-------------------|
| Profile, keys, password hash, settings, theme | Hard delete |
| Conference posts | Per the user's choice: **(a)** delete, or **(b)** keep, reattributed to the tombstone ("former member #a1b2") |
| Replies by others to their posts | Kept; parent shows "[removed by author]" if (a) |
| Messages they sent | Removed from their mailbox; in recipients' mailboxes the body is kept and the sender becomes the tombstone |
| Messages they received | Hard delete |
| Contacts they own | Hard delete; also removed from other users' contact lists |
| Poll votes | Aggregate totals kept; link to the user deleted (votes become anonymous) |
| Chat log lines | Reattributed to the tombstone, or deleted, following the same (a)/(b) choice |
| Invites they issued | Kept for audit, inviter replaced by the tombstone |
| Audit log | Keep event type and timestamp, replace user id with the tombstone. All audit rows purged after **1 year** (configurable) |
| Backups | Document in the privacy policy that erased data ages out of backups after N days |

Tombstone IDs are random per erased user (not derived from the username), so
erased users cannot be re-identified across the system.

Implementation notes (stage 9): rather than deleting the user row and
rewriting every reference, erasure turns the row into the tombstone — a
random `former-xxxxxxxx` username (a reserved prefix), no password, keys,
email, profile, preferences or groups — so everything kept stays attributed
to the same anonymous name, including audit entries. Plugins handle
`user.erased` first; if any fails, the erasure is retried on the next hourly
run. While a request is pending only "Cancel the erasure request" (admin)
reactivates the account; a plain unlock is refused. The only active
administrator cannot request erasure. "Fresh login" is implemented as a key
login less than 15 minutes old. With *delete content*, conference posts are
blanked to "[removed by author]" (and thread titles replaced) rather than
removed, so others' replies keep their place; chat lines are deleted.

---

## 6. SSH TUI

### 6.1 Login & registration flow

```
ssh bbs.example            (example host)
 ├─ public key matches a user → BBS main menu
 └─ no matching key
     ├─ username "new" (configurable) + password = invite code
     │     → registration wizard: username, password (15+ chars), email (optional), first public key
     │     → account enters `pending` if approval is on
     (later key logins to a pending account get a status screen only)
     └─ username + password (existing user)
           → "Add key" screen ONLY (paste a public key, max 3) → disconnect
```

### 6.2 Terminal profiles (user setting)

| Profile | Bold | Italic | Colour | Box-drawing | Screen mode |
|---------|------|--------|--------|-------------|-------------|
| Modern | SGR 1 | SGR 3 | 24-bit / 256 | Unicode | Full screen |
| PuTTY | Theme colour substitute **or** SGR 1 (user toggle) | Theme colour substitute or underline | 256 | Unicode | Full screen |
| Basic | Theme colour substitute | Theme colour substitute | 16 | ASCII | Full screen |
| Accessible | none | none | none (optional) | none | **Line mode** (see §6.3) |

**PuTTY verification:** PuTTY does render bold, but how depends on its config.
"Indicate bolded text by changing: the colour / the font / both" — the default
changed from colour to font in 0.63. Whether PuTTY renders **italic (SGR 3)**
could not be confirmed from its documentation. Proposal: ship a
**"Terminal test"** screen showing bold, italic, underline, 256-colour and
truecolour samples, and let users pick what actually rendered. This is more
reliable than detection, because PuTTY reports `TERM=xterm` like many other
clients.

### 6.3 Accessibility mode

Screen readers used with SSH clients (NVDA/JAWS with PuTTY or Windows Terminal,
VoiceOver with Terminal.app) read text as it is written out and handle
full-screen redraws poorly. Accessible mode therefore changes more than colours:

- **Line mode**: no alternate screen, no cursor positioning, no redraws. Output
  is appended like a chat log; menus are numbered lists with a prompt
  (`Enter a number from 1 to 6 or an action letter, or q to go back:`).
- No colour-only meaning, no box-drawing, no spinners/animation, ASCII only
  (optional).
- Every screen starts with a one-line title: `Screen: Conferences > General`.
- Menus longer than the screen: full screen, PgUp/PgDn move a screenful
  (Home/End to the first/last item) and the help bar starts with the
  visible range and whether there is more above or below; line mode pauses
  every page like long pages, and accepts a choice number at the pause.
- Menus separate the list from its fixed actions. Only the list is
  numbered; actions (start a thread, create a group, find a channel,
  delete this conference, next page, ...) have a lowercase letter and are
  shown, and read out, before the list: `Actions: n Start a thread; d
  Delete this conference; q Back.` `q` (and Esc in full screen) always
  goes back, so there is no Back item; the main menu labels it *Log out*.
  Menus made only of actions (the thread or message menus) stay numbered.
  `tui.Menu` rejects a reused letter, `q`, or anything but a-z.
- Spoken-friendly markers instead of decoration (see §8).
- Separately toggleable: **high contrast theme**, **reduce motion**,
  **ASCII only**, **verbose markers**, **page size** (lines before `--More--`).

### 6.3.1 Implementation notes (stage 4)

- Screens are written once against a `tui.UI` interface with two
  implementations: full-screen (`tui.Screen`) and line mode (`tui.Lines`).
- Line mode never uses colour, even for non-screen-reader clients without a
  PTY, because it cannot know the client's background colour.
- Registration asks "screen reader mode?" in plain text before any screen
  drawing, and saves the answer to the new account's preferences.
- Forms show each field's rules in words (e.g. "3 to 32 characters,
  required") so nothing is conveyed by colour or position alone; focus is
  marked with a `▶`/`>` marker as well as colour.
- 16-colour output maps theme colours by hue, not nearest RGB, so e.g. error
  red stays red.

### 6.4 Text editor

*Built in stage 8 (`tui.UI.Edit`). Line mode uses dot-commands on their own line: `.` finish, `.preview`, `.clear`, `.cancel`, `.keep`. Tab inserts four spaces.* nano-like: `^O` save, `^X` exit, `^K` cut line, `^U` paste, `^W` find, `^G`
help, arrow/Home/End/PgUp/PgDn, a help bar on the bottom two lines (hidden in
accessible mode; `^G` prints the help instead). Markdown-aware syntax colouring
in Modern/PuTTY profiles. `^P` toggles preview through the TUI renderer.

---

## 7. Standardised input controls

One definition, two renderers (TUI widget + HTML form element), one validator.

```go
type Field struct {
    Name, Label, Help string
    Kind     Kind      // SingleLine, MultiLine, Option, Boolean
    Subtype  Subtype   // Text, Int, Float, Email, Phone, Password, Markdown, PublicKey
    Required bool
    MinLen, MaxLen int
    Min, Max *float64
    Options  []Option  // for Option; Multi bool for multi-select (voting)
}
```

| Kind | Subtypes | TUI | Web |
|------|----------|-----|-----|
| Single line | text, int, float, email, phone, password | input line, masked for password | `<input type=…>` with server-side validation |
| Multi line | text, markdown, public key | editor (§6.4) / paste box for keys | `<textarea>` |
| Option | single / multi | arrow-key list; numbered in accessible mode | radio / checkbox group in `<fieldset>` |
| Boolean | — | `[x] Label` toggled with space; `Label: yes/no` in accessible mode | `<input type=checkbox>` with `<label>` |

Validation runs **server-side for both interfaces** (web HTML validation is
only a convenience). Validators: email (net/mail parse + length), phone (E.164:
accept spaces/dashes/brackets on input, store `+<digits>`, 8–15 digits), int, float, length, markdown
(length + parse succeeds), public key (`ssh.ParseAuthorizedKey` + allowed
algorithms + RSA size).

---

## 8. Markdown parity

One parser — `github.com/yuin/goldmark` (CommonMark, no dependencies of its
own) — producing an AST rendered by four custom renderers. Raw HTML and images
are disabled everywhere.

Authors get three heading levels (`#`–`###`; deeper ones are shown as
`###`). A member's headings never compete with the page they appear on:
they are moved down so `#` sits one level below the nearest heading the
page itself shows. On the web `#` is `<h2>` under the page's `<h1>`, and
`<h3>` in a conference post (under its "Post N" `<h2>`) or in the message
of the day panel. Over SSH the screen title counts as level 1 in the same
way. Levels never go past 6. Plugins choose the level with
`Session.MarkdownAt` / `WebSession.MarkdownAt`; `Markdown` means level 2.

TUI heading markers follow markdown convention, show the level after the
move, and are padded so text aligns, e.g. under a screen title:
`##   H2`, `###  H3`, `#### H4`.

| Element | Web | TUI Modern / PuTTY | TUI Accessible |
|---------|-----|--------------------|-------------------------------|
| Bold | `<strong>` | SGR 1 / colour substitute | plain text (optional `*word*`) |
| Italic | `<em>` | SGR 3 / colour substitute | plain text (optional `_word_`) |
| `#`–`###` | `<h2>`–`<h4>` under a page title (one level deeper per heading in between) | `##   HEADING` / `###  HEADING` / `#### HEADING` on a full-width background bar | `Heading level 2: Text` |
| Blockquote | `<blockquote>` | indented, `>` in quote-marker colour, text in quote-text colour, nesting repeats `>` | `Quote:` … `End quote.` with nesting as `Quote level 2:` |
| Ordered list | `<ol>` | number colour + `.` colour + text | `List, 3 items:` then `1. text` (nested: `Sub-list of item 2, 2 items:`) |
| Unordered list | `<ul>` | `-` in bullet colour + text colour | `List, 4 items:` then `- text` |
| Horizontal rule | `<hr>` | full-width bar | `Section break.` (shorter and clearer when read aloud than "RULE LINE") |
| Code block | `<pre><code>` (escaped) | indented, code theme colours | `Code block start, language go, 12 lines:` … `Code block end.`. No indentation-only meaning; tabs expanded |
| Inline code | `<code>` | code colour | `` `text` `` kept as is |
| Link | `<a rel="nofollow noopener noreferrer">` with grade badge | `Link {LETTER} {GRADE NAME}: {LINK TEXT} -> {URL}` in grade colour | `Link, grade B Considerate: {LINK TEXT}, {URL}` |
| Image | not rendered | not rendered | not rendered (alt text shown as plain text) |

Resolved for stage 5: in addition to the elements above, inline code,
bare-URL autolinks (http/https, `www.` → https) and strikethrough are
supported; tables are not. Unsupported syntax renders as plain text. In
screen-reader mode lists end with "End of list.", quotes with "End quote.",
and nested lists are announced ("Sub-list, 2 items:") instead of indented.

### 8.1 Links and pbc-classification

The library returns `Grade` (`Letter()`, `Name()`, `Icon()`), `Trust`
(`Marker()`), `Reasons`, `Stale`.

- **Format:** `Link B Considerate: Project docs -> https://example.org/docs`
  *(example values)*.
- **Colours:** defined by shellshawk themes as `grade.A … grade.F,
  grade.unknown` tokens, so they adapt to light and high-contrast themes.
  pbc-classification is not changed.
- Links to the BBS's own hosts are marked first-party through
  `WithFirstParty(...)`, set from config (never hardcoded).
- Classification runs at render time and is cached per domain in memory.

---

## 9. Themes

Theme = named set of semantic colour tokens (not raw element colours):
`fg, bg, accent, muted, error, warn, ok, heading.bg, heading.fg, quote.marker,
quote.text, list.bullet, list.number, list.dot, code.fg, code.bg, rule,
grade.A…grade.F, grade.unknown, bold.substitute, italic.substitute, …`

Each token defines truecolour, 256 and 16-colour fallbacks. Web uses the same
tokens as CSS custom properties. Built-in themes: *Classic BBS*
(blue/cyan), *Amber Terminal*, *Green Phosphor*, *Solarized-like Dark*, *Light*,
*High Contrast* (WCAG AAA contrast checked by a unit test). Themes are embedded
TOML/JSON files; admins can add more.

---

## 10. SFTP virtual file system

```
/me/                       profile.md, export/ (right-to-access bundle)
/conferences/{AREA}/{CONF}/{YYYYMMDD-POST-SLUG}.md     read-only thread export
/chat/{CHANNEL}/{YYYYMMDD}.log                         read-only, permission-checked
/messages/inbox/ …                                     (if the plugin opts in)
```

- Routes are registered by plugins with a path pattern, a permission, and
  read/write mode. Unknown paths → `ENOENT`; no route lists another route's tree.
- Upload size is set in config (`SHELLSHAWK_SFTP_MAX_UPLOAD_BYTES`, default
  1 MiB, max 64 MiB). Uploads are buffered in memory and committed only after
  a complete transfer. Per-user quotas are left to the plugins that store
  uploads.
- Implemented (stage 7): mounts are `sftpd.Mount{Name, AnyOf, FS}`; plugins
  declare them in `Manifest.SFTP` (name = plugin ID or `<id>-…`). Hidden
  mounts report "no such file". Only key logins to active accounts get the
  `sftp` subsystem. `/me/export/` arrives with the privacy work (stage 9).
- **SFTP library:** `github.com/pkg/sftp`, `RequestServer` API only (virtual
  handlers; the OS-backed `Server` type is never used — enforced by a test).

---

## 11. Web interface

- `net/http` + `html/template`, all assets embedded and self-hosted, no CDNs.
- Optional (disabled unless configured). Explains how to connect over SSH,
  including the host key fingerprint.
- **Web login:** a one-time code generated in the TUI (`Profile → Web login
  code`): single use, short-lived (configurable, default 5 minutes), stored
  hashed, rate-limited. Web never uses passwords.
- GPC: `Sec-GPC` header detection middleware, `navigator.globalPrivacyControl`
  noted client-side, `/.well-known/gpc.json`, privacy policy page.
- Strict CSP without breaking Privacy Badger (`default-src 'none'` with
  `'self'` for scripts, styles, images and `connect-src`, no
  `style-src 'none'`), `Referrer-Policy: same-origin` (`no-referrer` would make browsers send `Origin: null` on the site's own form posts), HSTS, fingerprinted
  asset names, `/version` endpoint, build number `1.0.x` in footer.
- No analytics, no third-party requests. Session cookie: `HttpOnly; Secure;
  SameSite=Strict`, no other cookies.

---

Implementation notes (stage 10): read-only in this version — conferences
(areas, conferences, threads) and messages (inbox, read) via plugin web
routes (`Manifest.Web`, served under `/p/<id>/`, GET only, built with
html/template). Login codes are 8 Crockford characters (40 bits), single
use, 5 minutes, replaced by any newer code, rate-limited; sessions are
stored hashed with a per-session CSRF token. Login rate limits key on the
connecting IP: behind a reverse proxy that is the proxy's address, so the
per-username limit is the effective one.

Live thread chat (after stage 10): plugin web routes may also be POST
actions (`Method: "POST"`; the core checks the session, CSRF token and
Origin, and only follows redirects to local paths) or streams (`Stream`;
the core lifts the read and whole-response write timeouts, sets a write
deadline per write, ends the stream when the session expires or is logged
out, re-checked every 30 seconds, and on shutdown, and allows 4 open streams
per member). The chat plugin serves `/p/chat/c/{id}/events` (server-sent
events; a web member is in the channel and listed by `/who` while it is
open; access is re-checked every 25 seconds) and `/p/chat/c/{id}/send`, and
`WebPanel` embeds a panel in other plugins' pages. Messages from the web go
through the same `Say` as the TUI (one printable line, at most 500
characters, flood control, logging); slash commands stay SSH-only.
`static/live.js` progressively enhances the panel; the CSP gains
`connect-src 'self'`. Thread chats are named `<conference>-<title words>`
(falling back to adding the thread ID), the chat list shows a thread
chat's title, and a thread forgets a chat that was closed from the Chat
menu so it can be enabled again.

Web messages (after stage 10): the inbox page gained Sent and Deleted
folders (folder links with `aria-current`), and each message page offers
what SSH offers from that folder: Reply, Delete (to Deleted), Move back
to the inbox, Delete permanently, Remove from Sent; the Deleted folder can
be emptied. Which copy an action applies to follows the folder the
message was opened from (`?folder=`, sent back as a form field), as a
message sent to oneself is in both Inbox and Sent; a wrong folder fails
as not found. Irreversible actions need a ticked confirmation box (Remove
from Sent too, which SSH does without asking). `/new` writes or replies
(`?reply=id` fills in the recipient, "Re:" subject and quoted text through
the same `replyDraft` as SSH); sending goes through `Send` with its
recipient, rate, length and privacy checks, and a refused message comes
back with what was typed and the error at its field (status 422).

Web chat pages (after stage 10): `/p/chat/` lists every channel the member
may enter, grouped as channels, private chats and thread chats, with a
GET search (`/find?q=`; the access log records paths only, so the query
is not logged). `/p/chat/c/{id}` is the channel's page around `WebPanel`.
Private chats add POST forms at `/c/{id}/invite`, `/topic`, `/remove` and
`/close` (close needs a ticked confirmation box), and `/new` starts one;
they use the same checks as the SSH commands, and topic changes and
removals are announced in the chat by the same helpers. These forms are
refused (not found) on other channel kinds: moderator topic/kick in
public channels and channel management stay on SSH. A refused form is
shown again with the member's input and an error next to the field (a
POST handler may return a page instead of a redirect; the core sends it
with status 422). Confirmations after a redirect use fixed codes
(`?done=invite`), never text the member typed.

## 12. Core plugins — notable design points

| Plugin | Notes |
|--------|-------|
| **Conferences** | Areas → conferences → threads → posts. Each conference is open to all readers or limited to one or more groups. Optional polls (uses the Polls API). Optional per-thread chat channel created through the Chat API, enabled by an admin/moderator. SFTP thread export. |
| | *Implemented (stage 8):* SFTP file names include the thread ID (`YYYYMMDD-<id>-<slug>.md`) so names stay unique; deleting a post, thread or conference also deletes its polls and thread chat; a restricted conference is open to members of any of its groups and to administrators, and stays closed if all its groups are deleted; a thread chat admits exactly the members who can read its thread (`chat.SetThreadAccess`); schema version 2 converted the original single per-conference permission to the groups holding it; authors can edit/delete their posts until a thread is locked; deleting the first post deletes the thread. |
| **Polls** | Single/multi choice, open/close dates, **anonymous by default** (creator may make a poll named; voters are told before voting), pinned polls, results view (bar rendering in TUI, a table in accessible mode and as the web fallback). |
| | *Web (added after stage 10):* `/p/polls/` lists Polls-menu polls (context `''`) and shows one with a vote form (`<fieldset>` of radios or checkboxes; the anonymity notice beside the button) and results under `CanSeeResults` (counts and percentages in text; a `<meter>` hidden from screen readers is only decoration). Attached polls are never served there: `polls.WebPanel` and `polls.WebVote` are called by the owning plugin after its own access check. Conferences show each post's polls in the thread (question `<h3>` under the post's `<h2>`) and accept votes at `/t/{id}/poll/{poll}` only for a poll on a post of that thread. Creating, closing, pinning and deleting stay on SSH. |
| **Contacts** | Personal lists and user-defined contact groups. Exposes `IsContact`, `IsMutual` (→ "friend"), `ListGroup` to other plugins. |
| **Messages** | Subject + markdown body, threaded replies, per-user unread/read/deleted counters (computed, with a restorable Deleted folder; copies there are removed permanently after an admin-set period, default 30 days, checked hourly, or sooner by the member — one message or the whole folder; a message's text is deleted once no recipient copy and no Sent copy remain, including after the sender's erasure), recipients by username or contact group, admin-set limits (recipients, per hour, length), read-only SFTP `/messages/{inbox,sent}`. Honouring the recipient's DM privacy setting arrives with the privacy settings (stage 9). |
| **User list** | All users (respecting privacy), my contacts, contact groups, online now. Stage 8: shows usernames and join dates only; online status (in-memory presence of open BBS sessions) only between friends until the privacy settings define it. |
| **Message of the day** | Added after stage 10. One markdown message (`motd_message`, versioned) set by `motd.edit` (moderators by default). Shown once after SSH login via the plugin `OnLogin` hook until the member has seen the current version (`motd_seen`); clearing it bumps the version so a later message is shown again. Readable from the menu; shown on the web home page via the `WebHome` hook. Erasure forgets what a member saw and their name on the message. |
| **Wall** | Added after stage 10. One line per member (`wall_entries`, keyed by user), at most 200 characters, emphasis only: `**bold**`, `*italic*`/`_italic_` (own parser: unmatched markers shown as typed, `_` only at word boundaries, backslash escapes, everything else plain text; HTML is escaped with only `<strong>`/`<em>` added). Expires an admin-set time after its last edit (default 168 hours), filtered on read and deleted at startup and hourly. `wall.write` for members, `wall.moderate` for moderators by default; administrators pick the groups for each from the Wall menu, which grants and revokes those permissions through the audited group permissions (the admin group is not offered: administrators can always do both). Username prefix search for finding lines and for moderators' removal. Read-only web page. |
| **Chat** | Channel types shown as a tag: `[P]` persistent, `[T]` thread (conference), `[A]` ad hoc, `[D]` direct. Commands `/who /channels /join /part /topic /kick /invite /createchat /destroychat`. Logging on by default, stored in SQLite, downloadable over SFTP by permitted users. Retention **90 days** default, overridable per channel (0 = logging off). Web uses SSE (no third-party websocket libraries). |

Each channel's join banner states whether it is logged and for how long. A
persistent channel is open to everyone who can chat or limited to one or
more groups (members of any of them, plus administrators; it stays closed
if all its groups are deleted); chat schema version 2 converted the
original single per-channel permission to the groups holding it. Implemented (stage 8): channel kinds persistent/adhoc/thread; ad hoc
chats are invite-only (creator, invitees, chat moderators); kick removes
the member now and, in ad hoc chats, withdraws the invitation; join/leave
events are broadcast but not logged (only messages and topic changes are);
retention 0 = not logged at all; a direct-message chat is an ad hoc chat
with one invitee (no separate [D] type); live delivery is in-process.

---

## 13. Resolved decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | User key types | Ed25519, ECDSA P-256, FIDO (sk-*), RSA ≥3072 (rsa-sha2-256/512 only) |
| 2 | Friend | Mutual contact |
| 3 | Admin view of private fields | Email only, audit-logged |
| 4 | Erasure | 14-day grace (configurable); sent message bodies kept + anonymised; audit retention 1 year (configurable); user chooses delete vs. anonymise for posts/chat |
| 5 | Phone | E.164 normalised |
| 6 | Markdown | goldmark |
| 7 | Headings | `#`–`###`, moved below the page's own headings (`#` = level 2 under a title) |
| 8 | Links | `Link B Considerate: {text} -> {url}`; grade colours in themes |
| 9 | SFTP | pkg/sftp RequestServer |
| 10 | Web login | One-time code from TUI |
| 11 | Polls / chat | Anonymous by default; chat logs 90 days, per-channel override |
| 12 | Module path | `go.privatebychoice.com/shellshawk` |
| 13 | Branding | See §15 |
| 14 | Markdown extras | Inline code, bare-URL autolinks, strikethrough; no tables |
| 15 | BBS name | Admin setting (`branding.name` in `system_settings`), perm `core.settings.manage` |
| 16 | pbc data | Optional `SHELLSHAWK_PBC_DATA_FILE` merged over built-in data; optional `SHELLSHAWK_FIRST_PARTY_DOMAINS` |

---

## 14. Proposed build order

1. Skeleton: config, SQLite + migrations, logging, `/version`.
2. SSH server with locked-down channel handling + crypto policy + tests.
3. Users, keys, groups, permissions, invites, approvals.
4. TUI core: terminal profiles, themes, line mode, widgets, form system.
5. Markdown parser + 4 renderers + pbc-classification links.
6. Plugin registry + menu system + admin menu.
7. SFTP virtual FS.
8. Core plugins: contacts → messages → userlist → polls → conferences → chat.
9. Privacy: visibility enforcement, export, erasure.
10. Web interface.

---

## 15. Branding

All branding is admin-configurable — nothing hardcoded.

- **BBS name:** shown in the TUI title line, web `<title>`/header, and SSH
  banner.
- **Login banner:** admin-editable ANSI/ASCII art shown at connect, with a
  required plain-text alternative used in accessible mode (and for clients
  that cannot render it). Banner content is sanitised to a safe SGR-only
  subset.
- **Web logo + footer:** self-hosted logo (uploaded via admin; SVG sanitised or
  raster only), footer text, and the build number `1.0.x`.
- **"Powered by shellshawk":** shown in the footer and on the About screen;
  admins can turn it off.
