# shellshawk

A self-hosted, privacy-first BBS with an SSH TUI, SFTP, and an optional web
interface. See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

> **Status:** all ten stages of the design are implemented: SSH server,
> accounts, TUI (full-screen and screen-reader), markdown with graded links,
> plugins and menus, administration, SFTP, the core plugins, privacy and
> erasure, and a web interface for reading, messaging, live chat and voting.

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
| `SHELLSHAWK_SFTP_MAX_UPLOAD_BYTES` | no | `1048576` | Largest file accepted over SFTP (max 64 MiB; uploads are buffered in memory) |
| `SHELLSHAWK_PBC_DATA_FILE` | no | built-in data only | Local pbc-classification JSON dataset, merged over the library's built-in data |
| `SHELLSHAWK_FIRST_PARTY_DOMAINS` | no | — | Comma-separated list of your own domains, graded as first-party |
| `SHELLSHAWK_ERASURE_GRACE_DAYS` | no | `14` | Days between an erasure request and the erasure (0 to 365) |
| `SHELLSHAWK_HTTP_ADDR` | no | disabled | `host:port` for the web interface; unset = web disabled |
| `SHELLSHAWK_PUBLIC_SSH_ADDRESS` | no | — | `host:port` members connect to, shown on the web start page |
| `SHELLSHAWK_PRIVACY_POLICY_FILE` | no | built-in | Markdown file replacing the built-in privacy policy (its `#` headings are shown as `<h2>`, under the page title) |
| `SHELLSHAWK_HTTP_INSECURE_COOKIES` | no | `false` | Drop the `Secure` cookie flag and HSTS — **local testing over plain HTTP only** |
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
- **Menus**: numbers choose from the list itself (threads, channels,
  messages, ...). Fixed actions such as *Start a thread* or *Delete this
  conference* have a letter instead, shown above the list (`n Start a
  thread · d Delete this conference · q Back`), so the numbers never shift
  with what you are allowed to do. `q` goes back in every menu (Esc too in
  full screen); in the main menu it logs out.
- **Screen reader mode**: no colours, no screen drawing — every screen starts
  with `Screen: <name>`, fields are asked one at a time, and long pages pause
  every N lines; so do long menus, where you can also type a number at the
  pause to choose straight away. Where several choices are allowed, type their numbers
  separated by commas; press Enter to keep the current choice, or type
  `none` to choose nothing. Choose it at registration (type `s`), or later under
  *Display settings → Terminal type*. Clients that do not request a terminal
  (e.g. `ssh -T`) always get this mode.
- **Terminal types**: Modern (24-bit colour), PuTTY (256 colours, italic as a
  colour), Basic (16 colours, ASCII), Screen reader. Bold and italic can each
  be shown as real bold/italic, a highlight colour, underline, or not at all —
  use *Terminal test* to see what your terminal supports.
- **Themes**: Classic BBS, Amber Terminal, Green Phosphor, Dark, Light and
  High Contrast. Text colours meet WCAG AA contrast (AAA for High Contrast),
  enforced by tests.

## Markdown

Posts and messages use markdown: bold, italic, ~~strikethrough~~, inline
code, headings (3 levels, placed below the page's own title so screen
reader outlines stay in order), quotes, ordered and bulleted lists, code blocks,
horizontal rules, links and bare URLs. Every link is shown with its
pbc-classification privacy grade, e.g.
`Link B Considerate: docs -> https://example.org/docs`. Only http, https and
mailto links are kept; images are never loaded; HTML is shown as text and
never run. Tables are not supported. Members can read *Markdown guide* in the
main menu and preview their own text. Administrators can change the BBS name
under *Administration → Branding*.

All user-supplied text is stripped of control characters and escape
sequences before it is written to anyone's terminal.

## Administration

Members holding any administrative permission see *Administration* in the
main menu, showing only the sections they may use:

| Section | Permission |
|---------|------------|
| Accounts awaiting approval | `core.users.approve` |
| Users (find, lock/unlock, change groups) | `core.users.manage` or `core.groups.manage` |
| Groups and permissions | `core.groups.manage` |
| Create / view / revoke invites | `core.invite.create`, `core.invite.manage` |
| Who is online (see and end SSH connections) | `core.sessions.manage` |
| Branding (BBS name) | `core.settings.manage` |
| Connection limits (idle timeout, connections per account) | `core.settings.manage` |
| Plugin settings | `core.plugins.settings` (admins and moderators) |
| Menu editor | `core.menu.manage` |
| Audit log | `core.audit.view` |

`admin` has every permission. The member menu can be rearranged, renamed,
split into submenus and restricted by permission; *Administration* can be
moved or renamed but never deleted. There is no Log out entry: `q` (or Esc)
in the main menu logs out.

### Connection limits and who is online

*Administration → Connection limits* sets two limits, which take effect
without a restart:

- **Idle timeout** (default 30 minutes; 0 turns it off, otherwise 2 to
  1440). An SSH connection with no input from the member for this long is
  ended. Members are warned first: a minute before, or a quarter of the
  timeout when that is shorter. The warning is a line of its own in line
  mode and a highlighted bottom line in full screen, both with a bell.
  Pressing an arrow key (or Enter without a terminal) keeps the
  connection. A warning always comes first, even when the timeout is
  lowered below how long someone has already been idle. Lowering or turning
  on the timeout reaches open connections within about 10 seconds.
- **Connections per account** (default 3; 0 means no limit, at most 20).
  Terminal and SFTP connections count together. An extra connection is
  told why and closed. Registrations with an invite are not counted.

*Administration → Who is online* lists every SSH connection: the account,
whether it has a terminal or a file transfer open, how long it has been
idle and when it connected. It never shows addresses. Choosing a connection
ends it after a confirmation; the member is told it was ended by an
administrator or moderator, and the action is audited
(`connection.ended`). It needs `core.sessions.manage`, which administrators
have; give it to moderators by granting it to their group under *Groups
and permissions*. Nobody can end the connection of an account holding
permissions they lack, so a moderator cannot end an administrator's.

## Plugins

Plugins are Go packages compiled into the binary (no runtime loading). Each
declares its permissions (optionally granted to default groups once), its
settings, its own `<id>_`-prefixed tables and its menu items in a manifest.
A plugin error or panic in a menu item is logged and shown as a generic
error; the session continues.

## SFTP

Members logging in with their key can use any SFTP client
(`sftp -P <port> <user>@<host>`, example). The file system is virtual —
nothing maps to the server's files:

| Path | Contents |
|------|----------|
| `/me/profile.md` | Your account details (read-only) |
| `/me/keys.pub` | Your public keys in `authorized_keys` format (read-only) |
| `/<plugin>/…` | Plugin data, e.g. conference threads (later stages) |

Directories you lack permission for do not appear. Uploads are accepted only
where a plugin allows them, up to the configured size, and are stored only
if the transfer completes. `mkdir`, `rm`, `rename` and links are refused.
Password (add-key) logins cannot use SFTP. Permissions are re-checked on
every request, so locking an account takes effect immediately.

## Contacts and messages

- **Conferences**: areas of conferences, each open to every member or
  limited to one or more groups (members of any chosen group, plus
  administrators). Threads of
  markdown posts written in the editor; authors edit (marked *edited*) or
  delete their posts; moderators lock threads, edit or delete anything,
  manage areas and conferences, and can enable a live chat for a thread.
  Posts can carry polls. Each thread downloads as one markdown file over
  SFTP: `/conferences/<area>/<conference>/<YYYYMMDD>-<id>-<title>.md`.
  Permissions: `conferences.read`/`.post` (members and moderators),
  `conferences.moderate` (moderators).
- **Contacts**: your personal list (with private notes) and named contact
  groups. A contact who also has you in their list is shown as a *friend*.
- **Messages**: private mail with a subject and a markdown body, sent to
  usernames and/or your contact groups (including yourself, for a note to
  self); replies quote the original. The mailbox shows unread, read and
  deleted counts. Deleted messages can be restored, deleted permanently one
  by one or all at once ("Empty the Deleted folder"), and are removed
  automatically after 30 days (administrators can change this under the
  Messages settings, 1 to 3650 days). A message's text is deleted as soon
  as nobody holds a copy any more. A message you send
  yourself is in both your inbox and Sent; deleting it from one leaves the
  other. When an account is erased, notes to self are deleted with it. Your mail is also available read-only over SFTP in
  `/messages/inbox` and `/messages/sent`. Sending needs `messages.send`
  (granted to `member` on first start). Administrators can change the
  per-message recipient limit, the hourly sending limit and the maximum
  length under *Plugin settings*.
- **Polls**: single or multiple choice (2–10 options), anonymous unless
  the creator makes them named (voters are told before voting), optional
  automatic closing, changeable votes while open. Results appear after you
  vote or when the poll closes, with counts and percentages written out.
  Pinned polls are listed first. `polls.vote`/`polls.create` go to
  members, `polls.manage` (pin, close, delete any) to moderators. On the
  web you can vote (native radio buttons or checkboxes) and read results;
  polls are created, closed, pinned and deleted over SSH.
- **Members**: browse and search members (username and join date only),
  your contacts and contact groups, and a member's profile with *Add to my
  contacts* and *Send a message*. Until privacy settings exist, online
  status is shown only between friends (mutual contacts).
- **Chat**: live channels. `[P]` persistent channels are run by chat
  moderators (who can limit them to one or more groups — members of any
  chosen group, plus administrators — and set how long the log is kept,
  0 = not logged); `[A]` private chats are invite-only and can be
  started by any member; `[T]` thread chats belong to conference threads.
  *Find a channel* searches the names and topics of the channels you can
  join.
  Commands: `/help`, `/who`, `/channels`, `/join`, `/topic`, `/invite`,
  `/kick`, `/createchat`, `/destroychat`, `/quit`. Logging is on by default
  (90 days) and every channel says so when you join; logs are downloadable
  over SFTP at `/chat/<channel>/<YYYYMMDD>.log` by members who can enter
  the channel. Joins and leaves are shown live but never logged. Flood
  control allows 5 messages per 5 seconds.
- **Message of the day**: a markdown message shown once after you log in,
  and again whenever it changes; read it any time from the main menu.
  Setting or removing it needs `motd.edit` (moderators by default;
  administrators always). It also appears on the web home page.
- **Wall**: one line per member, shown to everyone with its author and
  age. Use `**bold**` and `*italic*` (or `_italic_`); nothing else is
  formatted. Edit or remove your line any time; it disappears 7 days after
  your last edit (administrators can change this under the Wall settings,
  1 hour to 365 days) and is then deleted. *Find a member's line*
  searches by username (or the start of one); moderators use the same
  search to remove a line. `wall.write` goes to members and
  `wall.moderate` (remove anyone's line) to moderators by default;
  administrators choose the groups for each under *Choose who can write
  and moderate* in the Wall menu.
- **Editor**: full screen it works like nano — Ctrl-O save, Ctrl-X exit,
  Ctrl-K cut line, Ctrl-U paste, Ctrl-W find, Ctrl-P preview, Ctrl-G help.
  In screen reader mode, type lines and finish with `.` on its own line
  (`.preview`, `.clear`, `.cancel`, `.keep` are also available).

## Web interface

Optional (`SHELLSHAWK_HTTP_ADDR`); serve it behind a TLS-terminating
reverse proxy. You can read, write, reply to and delete private messages,
chat live in any channel you may join, start and run private chats, and
vote in polls; conference posting, creating polls, channel management,
slash commands and settings stay in the SSH interface.

| Path | Description |
|------|-------------|
| `/` | Start page: how to connect, the SSH host key fingerprint, how to join |
| `/login` | Log in with your username and a one-time code from **Web login code** in the BBS main menu (single use, 5 minutes) |
| `/home` | Your start page once logged in |
| `/p/conferences/` | Areas, conferences and threads you may read; polls on posts can be voted in, and a thread with a chat shows it live, and you can send messages |
| `/p/chat/` | Channels, private chats and thread chats you may join (with who is there and the topic), and a search by name or topic. Each channel has a live page: messages arrive as they are sent and you can send your own. Start a private chat with invitations; inside one, anyone in it can invite, and its creator (or a chat moderator) can change the topic, remove someone or close it |
| `/p/messages/` | Inbox, Sent and Deleted, with unread marks and counts; opening a message marks it read. Write a message (to usernames and your contact groups; markdown) or reply, with the same limits and privacy rules as over SSH. Delete (to Deleted, restorable), move back to the inbox, delete permanently, remove from Sent and empty the Deleted folder; the ones that cannot be undone need a ticked confirmation box |
| `/p/polls/` | Open polls (pinned first) and closed polls; vote or change your vote, and see results under the same rules as over SSH |
| `/p/wall/` | The wall (read-only); the message of the day is on `/home` |
| `/privacy` | Privacy policy (built in, or `SHELLSHAWK_PRIVACY_POLICY_FILE`) |
| `/.well-known/gpc.json` | Global Privacy Control declaration |
| `/version` | `{"version","commit","buildDate"}` to confirm a deploy |

- **No third parties**: every script, stylesheet and font is served by
  shellshawk. There are two small scripts: one shows a notice when the
  browser has GPC turned on; the other streams chat from this server
  (server-sent events) and sends messages without reloading. Without
  JavaScript the chat still works: send with the form, reload to see new
  messages. Assets have content-hashed names and are cached
  as immutable; pages are `no-store`.
- **Global Privacy Control**: detected from the `Sec-GPC` header and
  `navigator.globalPrivacyControl`, acknowledged on every page, declared at
  `/.well-known/gpc.json`, and explained in the privacy policy. Nothing is
  ever sold or shared, so honouring it changes nothing else.
- **Headers**: `Content-Security-Policy: default-src 'none'; script-src
  'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
  form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  `Referrer-Policy: same-origin` (other sites never receive a referrer),
  `X-Frame-Options: DENY`, nosniff, a restrictive `Permissions-Policy`, and
  HSTS. The CSP avoids blanket bans such as `style-src 'none'` so
  Privacy Badger keeps working.
- **Sessions**: one `__Host-session` cookie (HttpOnly, Secure,
  SameSite=Strict, 12 hours), CSRF tokens on forms, Origin checks on every
  POST, login rate limits per IP and per username. Locking or erasing an
  account ends its web sessions at once.
- **Themes**: the web uses the member's colour theme; visitors get Classic
  or Light depending on their system preference.
- The footer shows the build number (`1.0.x`; run `make bump` before each
  deploy) next to "Powered by shellshawk".

## SSH security policy

| Area | Allowed |
|------|---------|
| Key exchange | `mlkem768x25519-sha256` (post-quantum hybrid, preferred), `curve25519-sha256` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` |
| Host key | Ed25519 |
| User keys | Ed25519, ECDSA P-256, FIDO (`sk-*`), RSA ≥ 3072 bits with SHA-2 signatures |
| Channels | `session` only — no port forwarding, X11, agent forwarding |
| Session requests | `pty-req`, `window-change`, `shell`, `subsystem sftp` (key logins to active accounts only), `env` (`LANG`, `LC_ALL`, `LC_CTYPE`, `COLORTERM`). No `exec` |

shellshawk never starts OS processes; a test fails the build if `os/exec`
is imported anywhere.

## Privacy settings, data export and erasure

*Privacy and profile* in the main menu:

- **Profile**: full name, email, phone (E.164) and a status message, all
  optional.
- **Who can see what**: for each of full name, email, phone, status, last
  login time and online status — *Everyone*, *Friends only* (members who
  have each other as contacts) or *No one* — plus who may send you private
  messages. Defaults: *No one*, except status, online status and messages,
  which are *Friends only*. Administrators can view an email address for
  account recovery; each view is recorded in the audit log.
- **Download my data**: over SFTP, `/me/export/account.json` and one folder
  per feature (`messages`, `conferences`, `contacts`, `polls`, `chat`),
  generated when you download them.
- **Erase my account**: needs a key login from the last 15 minutes and your
  username typed to confirm; you choose whether your posts and chat messages
  are deleted or kept anonymously. The account is locked at once and erased
  after the grace period (an administrator can cancel until then). Erasure
  removes keys, password, email, profile, preferences, groups, contacts
  (both ways) and received messages, and unlinks poll votes (totals are
  kept). The account becomes an anonymous `former-xxxxxxxx` name, so
  messages you sent and content you chose to keep are credited to it. Text
  others wrote that mentions you (for example quotes) is not changed.
  Erased data may remain in server backups until they are rotated; operators
  should state their backup retention in their privacy policy.

## Privacy

Logs never contain client IP addresses, user agents, cookies, query strings,
or attempted SSH user names. Client IP addresses are held in memory only, for
rate limiting.
shellshawk makes no outbound network requests.
