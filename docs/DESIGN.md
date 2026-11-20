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
   `tcpip-forward`, and every other channel/request type. Refused global
   requests are logged, except keepalives (`keepalive@openssh.com`, and
   `keepalive@jcraft.com` from JSch-based clients such as many Android
   apps), which a refusal answers just as well. No call to
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
   - Because a password can add a key, members can change it: *SSH keys →
     Change password*, from a key login less than 15 minutes old (the same
     freshness as erasure, so the old password is not needed and a session
     left open cannot be used), audited as `password.changed` with no
     detail.
   - Max **3** public keys per user.
   - Rate limiting and lockout on failed attempts per IP and per account, kept
     in memory, with one `login.blocked` audit row each time an account or
     an address reaches its limit (target `user` with the account ID, or 0
     for a name that is no account; or `address`, never the address
     itself; detail `ssh password`, `ssh invite` or `web code`). Once per
     block rather than per attempt, so guessing cannot fill the audit log. IPv6 clients are counted per /64
     (`auth.IPLimitKey`). A successful password or invite login clears the
     account's count but never the IP's, so one address cannot alternate
     guesses with logins to an account of its own.
5. **Input sanitisation.** All user content is stored as markdown source and
   rendered through one renderer (§8) with raw HTML disabled. Terminal output
   strips all C0/C1 control characters and escape sequences from user content
   before the theme adds its own, so users cannot inject ANSI/OSC sequences
   (title changes, clipboard writes, hyperlinks) into other users' terminals.
   `term.Sanitize` also removes bidirectional overrides and marks and
   invisible characters that can make different text look the same
   (zero-width space, word joiner, U+FEFF, U+180E), keeping the zero-width
   joiner and non-joiner that emoji and some scripts need. Text from
   settings that is placed into markdown (the BBS name in the built-in
   privacy policy) is escaped with `markdown.Escape`.

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
to use. The web navigation follows the same tree (§11).

---

## 4. Users, groups, permissions, invites

- **Permissions** are strings namespaced by owner: `core.admin`,
  `core.invite.create`, `conferences.post`, `chat.channel.create`, …
- **Groups** hold permissions; users hold groups. Effective permissions = union.
- Built-in groups: `admin`, `moderator`, `member`. Accounts awaiting approval
  have status `pending` (rather than a `pending` group) and hold no
  permissions until approved; status `locked` blocks all logins.
- Escalation rules: an actor can only grant permissions they hold, and
  only revoke from or delete a group whose permissions they all hold.
  Group membership is itself a capability (group-only conferences and
  channels), so adding or removing members, and attaching a group to an
  invite, also require being in that group (`perm.MayAssign`);
  administrators always may, and the built-in `member` group (the default
  for new accounts) needs only its permissions. That exception is safe
  because `member` can never restrict content: conferences and channels
  refuse it as a restriction group (`perm.IsEveryoneGroup`), and their
  forms do not offer it; restrictions made before this rule keep working.
  Removing a member also
  needs the rank rule (`RequireOutranks`). An actor can only
  approve/reject/lock accounts whose permissions they fully hold. The last
  active administrator cannot be removed or locked.
- Locking an account publishes `user.locked` (an erasure request, which
  also locks it, publishes `user.erasure_requested`, handled the same way;
  see §5.2), and rejecting a pending one `user.rejected`; on any of them,
  `sessions.Service` ends every open SSH connection of the account
  (`presence.Conns.EndUser`) with a `*presence.Disconnect` cause, so the
  member is told why. On `user.locked` and `user.erasure_requested`,
  `websess.Service` also deletes the account's web sessions
  and login codes (subscribed even while the web interface is off, since
  sessions from an earlier run remain), so an unlock does not revive them.
  Until then, `Lookup` refuses any account that is not active, and live
  streams re-check it.
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
  and default groups to assign. Each time a code is used (the invite login
  and registration, `checkInvite`), it is checked against its creator as
  they are then: active, holding `core.invite.create`, and able to assign
  each of its groups (`perm.MayAssign`). So locking, demoting or erasing a
  member stops their outstanding invites (unlocking them restores them),
  and a permission added to a group later does not reach invitees through
  an invite from someone who lacks it. The bootstrap invite has no creator.
  Staff invite lists show such an invite as *on hold* (`Invite.State`),
  and a refused invite login logs why.
- **Approval**: configurable per invite (there is no global setting; an
  administrator who wants every account approved issues invites that
  require it) — new accounts land in
  `pending` until an admin/moderator approves. Rejecting deletes the
  account row, but its ID is never given to another account: registration
  takes the next ID from `user_id_high` (core migration 11, kept current
  by a trigger and started above every ID in `users` and the audit log),
  so audit entries about a rejected applicant never read as a later
  member's.

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
| Pages (who may page me, §6.6) | Friends Only |

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
refused. The admin email view requires `core.users.manage` and the rank
rule (`RequireOutranks`: not an account holding permissions the viewer
lacks), and writes an `admin.viewed.email` audit entry.

### 5.2 Right to forget

Two user-facing actions, both in Profile → Privacy, both available in TUI and Web:

**A. Export my data** — creates a markdown/JSON bundle readable over SFTP at
`/me/export/` (profile, posts, messages sent/received, contacts, votes, chat
lines). Supports GDPR-style access and portability, and lets users keep a copy
before erasing. Exports are not limited by listing sizes; messages include
those removed from Sent that a recipient still holds; `account.json` also
holds display settings, invites issued (never their codes) and the audit
entries where the member acted or is the target, with the actor given only
as "you", "another account" or "the system" so staff are not identified.

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
| The invite they registered with | Its note (often a real name) is cleared |
| Their name written into stored text | Replaced with the tombstone name: talk chat names and default topics (`talk-alice-bob`, "alice and bob") and logged topic changes ("alice changed the topic to: …") |
| Audit log | Keep event type and timestamp, replace user id with the tombstone; the key fingerprints in their `key.added`/`key.removed` entries are removed (published public keys could re-identify them). All audit rows purged after **1 year** (configurable) |
| Backups | Document in the privacy policy that erased data ages out of backups after N days |

Tombstone IDs are random per erased user (not derived from the username), so
erased users cannot be re-identified across the system.

Implementation notes (stage 9): rather than deleting the user row and
rewriting every reference, erasure turns the row into the tombstone — a
random `former-xxxxxxxx` username (a reserved prefix, chosen before plugins
run and passed to them as `Event.Tombstone`), no password, keys,
email, profile, preferences or groups — so everything kept stays attributed
to the same anonymous name, including audit entries. Plugins handle
`user.erased` first; if any fails, the erasure is retried on the next hourly
run. A request publishes `user.erasure_requested` (with the erasure
time) after it commits; as for `user.locked`, `sessions.Service` ends
every open connection of the account, including the one that asked, with
a message giving the date, and `websess.Service` deletes its web sessions
and login codes, so cancelling does not bring them back. While a request
is pending only "Cancel the erasure request" (admin) reactivates the
account, publishing `user.unlocked`; a plain unlock is refused. The only active
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

### 6.5 Transition screens

Text art shown between the menu and an application, as classic BBSes did.
Package `transition`; tables `transition_profiles`, `transition_files` and
`transition_points` (migration 0009).

- **Profiles** are named (`[a-z0-9][a-z0-9-]{0,39}`, also the SFTP folder
  name) sets of up to 50 files, mode `random` (a random file each time) or
  `single` (one chosen file; if that file is deleted the profile goes back
  to random).
- **Points**: `(target, moment)` where target is a menu item or `*` (the
  default) and moment is `enter` or `exit`. No row = use the default (items)
  or nothing (`*`); a row with a NULL profile = nothing, overriding the
  default. Deleting a profile deletes its rows, so those points fall back
  to the default. Submenus have no transitions.
- **Display**: `bbs.session.openItem` shows the enter screen, runs the
  item, then the exit screen (not if the session ended). Only the
  full-screen UI shows them (`tui.Screen.Splash`: centred, no wrapping, cut
  at the edges, any key continues, a resize redraws). Line mode never does:
  art read out character by character is noise. Members turn them off with
  `user_prefs.transitions` (*Display settings*, default on). ASCII-only
  profiles get `transition.ASCII` (box drawing → `+ - |`, blocks → `#`,
  anything else non-ASCII → `?`). A failure to load a transition is logged
  and skipped, never shown.
- **Text** is cleaned once, on save (`transition.Clean`): input over 64 KiB
  is refused; everything from the first Ctrl-Z (SAUCE) is dropped; invalid
  UTF-8 is decoded as CP437; ANSI escape sequences are stripped (colour is
  not supported yet); tabs expand to 8 columns; control and bidi characters
  are removed; trailing spaces and leading/trailing blank lines are trimmed;
  empty results are refused. The display sanitises again.
- **Editing**: *Administration → Transitions* (`core.transitions.manage`,
  admins only by default) and SFTP `/text/<slug>/<file>`. `sftpd.ManagedFS`
  adds `Remove`, `Mkdir` and `Rmdir` to a writable mount (the only one is
  `/text`); a mount refuses a request it finds invalid with
  `sftpd.ErrRefused`, which the client sees as a plain failure and the log
  records at info level. Uploading to a missing folder creates the profile
  in the same transaction. Every change is audited as `transition.changed`
  (target type `transition`, the profile ID).

### 6.6 Notifications and paging

Short notices for a member about something that happened elsewhere.
Package `notify`; tables `notifications` and `notification_settings`, and
`user_prefs.notifications` (migration 0010).

- **Kinds** are declared by plugins (`plugin.Manifest.Notifications`, named
  `<plugin>:<key>`, with a label, a default and an optional `Open` that
  shows the thing and checks access again). The registry registers them
  with `notify.Service` at load and keeps the openers. Built in:
  `chat:page`, `messages:new` (each recipient but the sender) and
  `conferences:reply` (the thread's author, when someone else replies and
  the author can still read the thread). Plugins send through
  `Host.Notify`; a failure to notify is logged and never fails the action.
- **Stored**: recipient, kind, actor (`ON DELETE SET NULL`, the username
  is looked up when shown, so renames follow), a short description (one
  line, control characters removed, at most 120 characters, e.g. the
  message subject or thread title), a plugin reference (e.g. message ID)
  and `seen_at`. A member keeps at most 100, for 30 days; older ones are
  deleted when a new one arrives and when the list is read.
- **Members choose** per kind whether they receive it (`Add` stores nothing
  for a kind turned off) and whether new ones are listed between screens.
- **Display**: `bbs.session.openItem` shows, after each transition
  screen (opening an item and returning to the menu), the new
  notifications (up to the latest 10; all are marked seen once listed) as a
  menu: choosing one opens it, `q` continues. It works in both modes — line
  mode gets them as a plain numbered list — and is never shown in the
  middle of a screen, nor around the Notifications item itself. The main
  menu's intro and the Notifications entry show the new count. The
  Notifications item lists all, opens or deletes one, marks all seen,
  deletes all, and holds the settings.
- **Paging** (chat): `chat.Page` asks a member to come and talk in a
  channel the pager can enter. A private chat invites them; other
  channels must already admit them. Refused alike (`ErrCannotPage`, "cannot
  be paged right now") when the member is offline (no SSH session in
  presence and not in any chat), does not
  accept pages from the pager (privacy field `pages`, default friends),
  does not let the pager see that they are online (field `online`,
  default friends) or has page notifications off, so a page reveals
  nothing their settings hide. Both privacy fields are checked before
  presence. One page per pair per admin-set interval (chat setting
  `page_minutes`, default 5; in memory). A member who is in any chat gets
  a live line there too, and the notification is then marked seen.
  *Page someone* (Chat menu, needs `chat.create` too) reuses or creates
  the private chat `talk-<a>-<b>` whose creator is one of the pair and
  whose only invitee is the other. Permission `chat.page` (members and
  moderators by default). Opening a page enters the chat if it still
  exists and the member may enter it.
- **Privacy**: erasure deletes the member's notifications, their settings
  and every notification they caused; the data export has
  `notifications/notifications.json` (list and settings).
- **Web**: `GET /notifications` (core, when `web.Config.Notify` is set)
  lists them like the SSH item; the navigation entry and `/home` show the
  new count. A kind's optional `WebPath` (e.g. `notify.RefPath("/m/")`)
  gives the plugin page a notification is about; `GET
  /notifications/{id}/open` marks it seen and redirects to
  `/p/<plugin><path>` (the page checks access again), or back with a
  notice when there is none. It is a GET so the notification can be an
  ordinary link; its only effect is marking one of the member's own
  notifications seen, and the SameSite=Strict cookie means another site
  cannot make a member's browser do even that. Delete one, mark all seen and delete all
  (ticked box) are CSRF-checked POSTs; `/notifications/settings` uses the
  shared form renderer for the same settings as SSH. Paging on the web:
  *Page a member* on each channel page (`POST /p/chat/c/{id}/page`) and
  *Page someone* (`/p/chat/page`, same steps as the Chat menu action).
  A member following a chat on the web counts as online for paging (the
  chat hub knows they are there) and gets a live line without the
  `/join` hint, which only works over SSH.

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

- Text files built from stored content (chat logs, conference threads,
  messages) are passed through `term.Sanitize` (keeping newlines) as they
  are served: input is already checked, but members open these files in
  terminals, so anything a terminal would act on is removed again on the
  way out (defence in depth).
- Routes are registered by plugins with a path pattern, a permission, and
  read/write mode. Unknown paths → `ENOENT`; no route lists another route's tree.
- Upload size is set in config (`SHELLSHAWK_SFTP_MAX_UPLOAD_BYTES`, default
  1 MiB, max 64 MiB). Uploads are buffered in memory and committed only after
  a complete transfer. The uploads in progress in one session share one
  limit's worth of memory (`handler.reserve`), so many files opened at once
  cannot multiply it; a finished or failed upload gives its share back.
  There is no server-wide cap: the worst case is every connection
  (`SHELLSHAWK_SSH_MAX_CONNS`, default 100) with 2 sessions each holding
  the limit, about 200 MiB at the default 1 MiB, so raise the limit with
  the server's memory in mind. Per-user quotas are left to the plugins
  that store uploads.
- Implemented (stage 7): mounts are `sftpd.Mount{Name, AnyOf, FS}`; plugins
  declare them in `Manifest.SFTP` (name = plugin ID or `<id>-…`). Hidden
  mounts report "no such file". Only key logins to active accounts get the
  `sftp` subsystem. `/me/export/` arrives with the privacy work (stage 9).
- `/text/<profile>/<file>` (`core.transitions.manage`) is the one mount that
  also accepts `mkdir`, `rm` and `rmdir` (`sftpd.ManagedFS`, §6.5). Its
  directories are listed as writable (0755).
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
- The Origin check on POSTs compares the host, not the scheme: behind a
  TLS-terminating proxy the server cannot reliably see the scheme the
  browser used, and HSTS (browsers only use https) plus the
  SameSite=Strict cookie already stop a cross-site or downgraded post
  from carrying the session.

---

Implementation notes (stage 10): read-only in this version — conferences
(areas, conferences, threads) and messages (inbox, read) via plugin web
routes (`Manifest.Web`, served under `/p/<id>/`, GET only, built with
html/template). Login codes are 8 Crockford characters (40 bits), single
use, 5 minutes, replaced by any newer code, rate-limited; sessions are
stored hashed with a per-session CSRF token. Login rate limits key on the
client's address (`auth.IPLimitKey`, so IPv6 per /64): the connecting
address, or, when it is listed in `SHELLSHAWK_HTTP_TRUSTED_PROXIES`, the
rightmost `X-Forwarded-For` entry that is not a trusted proxy (entries
further left are client-supplied and ignored). Without the setting, a
proxy's visitors share one count. Each attempt is counted against the
address before the code is checked (`Limiter.Try`, given back by
`Forgive` on success), so parallel requests cannot all get past the
limit; as over SSH, a success never clears the address's earlier
failures. Wrong codes for one username do not block it (anyone could lock
a member out by typing their name): at 5, `websess.VoidCode` deletes that
member's outstanding code and `login.blocked` is audited with detail `web
code voided`; the member gets a new code over SSH. `Redeem` does the same
code lookup whether or not the username is an active account, so the
time taken does not reveal it. The SSH password login also counts with
`Try`/`Forgive`.

Live thread chat (after stage 10): plugin web routes may also be POST
actions (`Method: "POST"`; the core checks the session, CSRF token and
Origin, and only follows redirects to local paths) or streams (`Stream`;
the core lifts the read and whole-response write timeouts, sets a write
deadline per write, ends the stream when the session expires or is logged
out, or the member no longer holds the route's `AnyOf` permission, both
re-checked every 30 seconds, and on shutdown, and allows 4 open streams
per member; plugins may check more, as chat does for the channel). The chat plugin serves `/p/chat/c/{id}/events` (server-sent
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

Web navigation: the links in the page header are the main menu's entries
(labels, order and extra permissions from `menu_entries`), worked out per
page by `nav` in `internal/web/nav.go`; `/home` no longer repeats them.
An item is shown when it can be opened on the web: `core:notifications`
(`/notifications`, with the new count added to its label as over SSH),
`core:admin` (`/admin`, a page of the staff pages the member may use; it
is shown when there is at least one) and plugin items that declare
`MenuItem.WebPath` (a path under `/p/<id>`, validated when the plugin is
loaded; this replaced `WebRoute.Nav`) and that the member may use. Other
core items are SSH-only and left out. A submenu is shown when something
inside it would be, and links to `/menu/{id}`, which lists its entries
with a link back to the menu above. That page answers 404 unless the
submenu and every submenu above it pass their extra permissions and it
has something for the web, so a hidden submenu cannot be opened by
guessing its number. As over SSH, an extra permission on an entry hides
it but does not guard the page it opens; the page checks its own
permissions. Nesting is bounded at 8 levels.

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

Web who is online (after stage 10): the first core staff page, not a
plugin route. `web.Config.Connections` (a `sessions.Service`; nil leaves
the routes out) serves `GET /admin/online` (an accessible table: caption,
column and row headers, an End link per row whose name includes the
account for screen readers), `GET /admin/online/{id}` (confirmation) and
`POST /admin/online/{id}/end` (CSRF token, Origin, ticked box; 422
without it). The navigation shows *Who is online* only to holders of
`core.sessions.manage`; the pages answer 403 to anyone else, and
`sessions.Service` re-checks the permission and rank on every request, so
a moderator cannot end an administrator's connection from the web either.
Descriptions (`Connection.Who`, `Uses`, `Idle`, `Describe`) are shared with
the SSH screen. A connection that has closed meanwhile redirects with
`?done=gone`; notices use fixed codes only.

Web sessions on Who is online: migration 0008 adds `last_seen_at`
(written by `Lookup` at most once a minute) and a random 18-hex-character
`public_id` (backfilled for existing sessions) to `web_sessions`, so staff
pages name a session without its token or a `rowid` that `VACUUM` could
renumber. `sessions.Service.SetWeb` enables `WebSessions` and `EndWeb`
(same permission, rank rule and confirmation as connections; audited as
`web_session.ended`). Routes: `GET /admin/web-sessions/{id}` and `POST
/admin/web-sessions/{id}/end`. The viewer's own session is marked and not
offered; logging out ends it. The privacy policy says last activity is
recorded while logged in. The SSH screen lists web sessions after the
connections in the same menu (values prefixed `web:`), with the same
confirmation and rules.

Web connection limits: `web.Config.Settings` (nil leaves it out) serves
`GET`/`POST /admin/limits` for holders of `core.settings.manage` (linked
in the navigation only for them). Two number fields with their help and
error text tied to the input by `aria-describedby`; a refused value comes
back with status 422, the typed values and `aria-invalid`. Validation uses
the same `settings.CheckIdleMinutes` and `CheckMaxPerUser` as the SSH
form, and `SetConnLimits` re-checks the permission and audits each change.

Web branding: `GET`/`POST /admin/branding` (same `web.Config.Settings`
and permission as the connection limits) edits the BBS name through
`settings.SetBBSName`, which trims, refuses control characters and
escape sequences, and audits. A refused name comes back with status 422
and the error tied to the field. Web pages read the name on every
request; SSH sessions read it when they start.

Web plugin settings: `GET /admin/plugins` lists the plugins that declare
settings, and `GET`/`POST /admin/plugins/{id}` edits one, for holders of
`core.plugins.settings` (routes and the navigation link exist only when a
plugin has settings). `web/formhtml.go` renders any `form.Form` as an
accessible web form, so plugins write no HTML for their settings: every
control has a label and its rules in words (`Field.Constraints`) and help,
tied with `aria-describedby` along with any error; Int and Float become
number inputs with min/max, MultiLine a textarea, Choice a select (or a
fieldset of checkboxes when Multi), Boolean a checkbox (unticked means
false), and Password is never sent back. Input names are prefixed `f-` so
a setting key cannot clash with the form's `csrf` field. `Settings.Save`
validates and re-checks the permission; a refused save comes back with
status 422, the typed values and the errors, worded as over SSH ("<label>
must be at most 50."). The form body limit is 128 KiB.

Web menu editor: `web.Config.Menu` with `MenuItems` (the item catalogue,
implemented by `bbs.Handler`: `MenuDefaults`, `ItemExists`, `ItemLabel`)
serves `GET /admin/menu?parent=` (a table of a menu's entries in order,
the add form, and on the main menu the reset form), `GET`/`POST
/admin/menu/{id}` (label and extra permission, plus delete), and POSTs
`/admin/menu/add`, `/admin/menu/{id}/move` (`direction=up|down`, redirects
to `#entry-<id>`), `/admin/menu/{id}/delete` and `/admin/menu/reset` (both
need a ticked box). Everything goes through `menu.Service`, which checks
`core.menu.manage`, audits, refuses to delete Administration or a
non-empty submenu, and validates labels, targets and permissions; labels
are checked first so their errors appear at the field. Move buttons carry
the entry's label in visually hidden text so each is distinct to screen
readers. Web staff pages share one `requirePerm` helper.

Web audit log: `GET /admin/audit?before=<id>` for holders of
`core.audit.view`, read-only, 100 entries to a page (one extra is read to
know whether an older page exists). `audit.Before` pages by keyset in the
same order as `Recent` (time, then insertion), so entries sharing a
timestamp or recorded out of order are neither skipped nor repeated; an
unknown cursor gives an empty page. Times are shown in UTC inside
`<time datetime>`.

Web approvals: `GET /admin/pending`, `POST /admin/pending/{id}/approve`,
`GET`/`POST /admin/pending/{id}/reject` (reject needs a ticked box), for
holders of `core.users.approve`, through `auth.Service.PendingUsers`,
`Approve` and `Reject`, which check the permission and the rank rule and
audit. Like the SSH screen the page shows only the username and when it
registered, never the email address (viewing one is audited separately).
An account that is no longer waiting redirects with `?done=gone`;
rejecting publishes `user.rejected`, which ends its open connections.

Web invites: `GET /admin/invites` (own invites with `core.invite.create`,
all with `core.invite.manage`), `GET`/`POST /admin/invites/new` (the SSH
form's fields through the generic renderer, `auth.CreateInvite` checks
the permission and that every attached group's permissions are held), and
`GET`/`POST /admin/invites/{id}/revoke` (ticked box; `RevokeInvite`
allows your own or any with manage). The new code is rendered in the POST
response (status 200, `no-store`) rather than after a redirect, so it
never appears in a URL or history entry and is never stored; reloading
would ask to resubmit and create another invite.

Web users: `GET /admin/users?q=` (prefix search through
`auth.ListUsers`; no `q` shows only the form), `GET /admin/users/{id}`, and
POSTs `/lock`, `/unlock`, `/cancel-erasure` (ticked box), `/email` and
`/groups/add|remove` (`group=<id>`), for holders of `core.users.manage` or
`core.groups.manage`, each section shown only with its permission. The
services (`auth.SetLocked`, `privacy.CancelErasure`, `privacy.AdminEmail`,
`perm.AddMember`/`RemoveMember`) check the permission, rank, self and
last-administrator rules and audit; their errors come back on the account's
page (403 forbidden, 409 conflicts). The email address is only shown in
the response to its POST, so viewing it is a deliberate, audited action
that a prefetching browser cannot trigger and that never reaches a URL.
`web.Config.Privacy` (nil leaves erasure and email out) is the same
service as SSH uses.

Web groups: `GET /admin/groups` (table and create form through the
generic renderer), `POST /admin/groups/new`, `GET /admin/groups/{id}`, and
POSTs `/grant`, `/revoke` (`perm=`), `/members/add` (`username=`),
`/members/remove` (`user=<id>`) and `/delete` (ticked box), for holders of
`core.groups.manage`. `perm.Service` enforces escalation (only what the
actor holds; members only of groups the actor is in, see §4), built-in
group protection and the last-administrator guard,
and audits; refusals come back on the group's page. Revoking and removing
are single buttons, as over SSH, since both can be undone. Permissions a
group still holds but no installed plugin provides are listed so they can
be revoked.

Web transitions: `GET /admin/transitions` (profiles, Add a profile, and
one form of selects for every transition point, named
`<moment>/<target>`; `POST /admin/transitions/points` saves only the
points whose value changed and refuses a value not offered, saving
nothing), `POST /admin/transitions/new`, `GET|POST /admin/transitions/{id}`
(name, mode, file through the generic renderer), POSTs `/{id}/upload`
(multipart, `file=` and an optional `name=`, else the file's own base
name), `/{id}/write` (a new file only), `/{id}/delete` (ticked box), and
`GET|POST /admin/transitions/{id}/files/{name}` (preview in a named,
focusable `<pre>` region that scrolls sideways; editing never creates a
file) and `/files/{name}/delete` (ticked box), for holders of
`core.transitions.manage`, only when the transition service and the menu
item catalogue are configured. Requests carrying a file may be up to three
times the 64 KiB file limit plus 8 KiB (URL-encoded text); larger bodies
get 413. `transition.Service` checks the permission, cleans every file and
audits, as for SSH and SFTP.

## 12. Core plugins — notable design points

| Plugin | Notes |
|--------|-------|
| **Conferences** | Areas → conferences → threads → posts. Each conference is open to all readers or limited to one or more groups. Optional polls (uses the Polls API). Optional per-thread chat channel created through the Chat API, enabled by an admin/moderator. SFTP thread export. At most 30 posts (replies and new threads) per member per hour, `max_posts_per_hour`; moderators are exempt. |
| | *Implemented (stage 8):* SFTP file names include the thread ID (`YYYYMMDD-<id>-<slug>.md`) so names stay unique; deleting a post, thread or conference also deletes its polls and thread chat; a restricted conference is open to members of any of its groups and to administrators, and stays closed if all its groups are deleted; a thread chat admits exactly the members who can read its thread (`chat.SetThreadAccess`), and one whose owner has no rule registered (its plugin is not installed) is closed to everyone; schema version 2 converted the original single per-conference permission to the groups holding it; authors can edit/delete their posts until a thread is locked; deleting the first post deletes the thread when a moderator does it or nobody else has replied, and otherwise blanks the post and title to "[removed by author]" (and deletes its poll), keeping the others' replies. |
| **Polls** | Single/multi choice, open/close dates, **anonymous by default** (creator may make a poll named; voters are told before voting), pinned polls, results view (bar rendering in TUI, a table in accessible mode and as the web fallback). At most 5 open polls per creator, `max_open_polls` (closed and expired ones do not count); `polls.manage` holders are exempt. |
| | *Web (added after stage 10):* `/p/polls/` lists Polls-menu polls (context `''`) and shows one with a vote form (`<fieldset>` of radios or checkboxes; the anonymity notice beside the button) and results under `CanSeeResults` (counts and percentages in text; a `<meter>` hidden from screen readers is only decoration). Attached polls are never served there: `polls.WebPanel` and `polls.WebVote` are called by the owning plugin after its own access check. Conferences show each post's polls in the thread (question `<h3>` under the post's `<h2>`) and accept votes at `/t/{id}/poll/{poll}` only for a poll on a post of that thread. Creating, closing, pinning and deleting stay on SSH. |
| **Contacts** | Personal lists and user-defined contact groups. Exposes `IsContact`, `IsMutual` (→ "friend"), `ListGroup` to other plugins. |
| **Messages** | Subject + markdown body, threaded replies, per-user unread/read/deleted counters (computed, with a restorable Deleted folder; copies there are removed permanently after an admin-set period, default 30 days, checked hourly, or sooner by the member — one message or the whole folder; a message's text is deleted once no recipient copy and no Sent copy remain, including after the sender's erasure), recipients by username or contact group, admin-set limits (recipients, per hour, length), read-only SFTP `/messages/{inbox,sent}`. Honouring the recipient's DM privacy setting arrives with the privacy settings (stage 9). Each recipient but the sender gets a `messages:new` notification (§6.6). |
| **User list** | All users (respecting privacy), my contacts, contact groups, online now. Stage 8: shows usernames and join dates only; online status (in-memory presence of open BBS sessions) only between friends until the privacy settings define it. |
| **Message of the day** | Added after stage 10. One markdown message (`motd_message`, versioned) set by `motd.edit` (moderators by default). Shown once after SSH login via the plugin `OnLogin` hook until the member has seen the current version (`motd_seen`); clearing it bumps the version so a later message is shown again. Readable from the menu; shown on the web home page via the `WebHome` hook. Erasure forgets what a member saw and their name on the message. |
| **Wall** | Added after stage 10. One line per member (`wall_entries`, keyed by user), at most 200 characters, emphasis only: `**bold**`, `*italic*`/`_italic_` (own parser: unmatched markers shown as typed, `_` only at word boundaries, backslash escapes, everything else plain text; HTML is escaped with only `<strong>`/`<em>` added). Expires an admin-set time after its last edit (default 168 hours), filtered on read and deleted at startup and hourly. `wall.write` for members, `wall.moderate` for moderators by default; administrators pick the groups for each from the Wall menu, which grants and revokes those permissions through the audited group permissions (the admin group is not offered: administrators can always do both). Username prefix search for finding lines and for moderators' removal. Read-only web page. |
| **Chat** | Channel types shown as a tag: `[C]` channel (persistent), `[T]` thread (conference), `[P]` private (ad hoc), `[D]` direct. Commands `/who /channels /join /part /topic /kick /invite /createchat /destroychat`. Logging on by default, stored in SQLite, downloadable over SFTP by permitted users. Retention **90 days** default, overridable per channel (0 = logging off). Web uses SSE (no third-party websocket libraries). |

Each channel's join banner states whether it is logged and for how long. A
persistent channel is open to everyone who can chat or limited to one or
more groups (members of any of them, plus administrators; it stays closed
if all its groups are deleted); chat schema version 2 converted the
original single per-channel permission to the groups holding it. Implemented (stage 8): channel kinds persistent/adhoc/thread; ad hoc
chats are invite-only (creator, invitees, chat moderators); kick removes
the member now and, in ad hoc chats, withdraws the invitation; join/leave
events are broadcast but not logged (only messages and topic changes are),
and each member's joining (or leaving) one channel at most once a minute
(`hub.announce`), so reconnecting in a loop cannot flood it;
retention 0 = not logged at all; a direct-message chat is an ad hoc chat
with one invitee (no separate [D] type); live delivery is in-process.
While a member is in a channel over SSH, their access is checked again
every 25 seconds (`watchAccess`, the web stream's interval); once they
can no longer enter it (removed from its group or a restricted
conference, uninvited, or without `chat.use`) they are put out of the
room with "You no longer have access to #name.", like a kick.
Only a private chat's creator and chat moderators (`canModerate`, who
may also remove members, change the topic and close it) can invite, so an
invitee cannot bring back someone the creator removed; inviting someone
already in is a no-op, which lets either of a talk chat's pair page the
other into it. The web shows other participants "ask <creator>" instead
of the invite form.
`Invite` (from `/invite`, `/createchat` and the web) needs the invitee to
be active and to accept private messages from the inviter (privacy
field `messages`), so an invitation cannot get round "who can message
me"; `/createchat` checks every invitee before creating the chat. Paging
invites through the same code without that check, since its consent is
`pages`. Chat settings cap the private chats a member has open
(`max_private_chats`, default 20, counting chats they created) and the
invitations per chat (`max_invitees`, default 50).
Paging (`/page`, *Page someone*) is described in §6.6. A thread's author
gets a `conferences:reply` notification when someone else replies.

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
