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

## Unlocking an account from the server

If an administrator's account is locked (for example by another
administrator), unlock it with the same environment variables set:

```bash
./bin/shellshawk unlock USERNAME
```

It works for any locked account, needs no login, and is recorded in the
audit log as done by the system. It refuses an account waiting to be
erased. It can run while the server is running.

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

Locking an account ends its open SSH connections at once, telling the member
why, and deletes its web sessions and unused web login codes, so unlocking
it later does not bring them back: the member logs in to the web afresh.
Rejecting an account awaiting approval likewise ends its open connections.
Nobody can lock their own account or an account holding permissions they
lack, so a moderator cannot lock an administrator.

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
- **Transition screens**: text art the BBS may show when you open a menu
  item and when you return to the menu; press any key to continue. Turn
  them off under *Display settings → Show transition screens*. They are
  never shown in screen reader mode.
- **Notifications**: a notice when someone pages you, sends you a private
  message or replies to a thread you started. New ones are listed between
  screens — when you open a menu item and when you return to the menu,
  after any transition art, never in the middle of a screen — in both
  full-screen and screen reader mode; choose one to open it, or `q` to
  continue. The main menu says how many are new (*Notifications (2 new)*).
  *Notifications* in the main menu lists them all (kept 30 days, at most
  100), opens or deletes one, marks all as seen or deletes them all. Its
  *Notification settings* (`s`) turn the between-screens list off (they
  then wait under *Notifications*) and choose which kinds you receive.
  The same list and settings are on the web at `/notifications`.
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
under *Administration → Branding* or on the web at `/admin/branding`.

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
| Who is online (see and end SSH connections and web sessions) | `core.sessions.manage` |
| Branding (BBS name) | `core.settings.manage` |
| Connection limits (idle timeout, connections per account) | `core.settings.manage` |
| Plugin settings | `core.plugins.settings` (admins and moderators) |
| Menu editor | `core.menu.manage` |
| Transitions (text art between the menu and applications) | `core.transitions.manage` |
| Audit log | `core.audit.view` |

`admin` has every permission. Staff can never hand out more than they
have:

- **Permissions:** you can only grant a permission you hold, and only
  revoke from a group whose permissions you all hold.
- **Group members and invites:** being in a group can open group-only
  conferences and channels, so to add someone to a group, remove someone
  from it, or create an invite into it, you must hold every permission it
  grants **and** be in the group yourself. Administrators can always; the
  built-in `member` group, which new accounts join, needs only its
  permissions.
- **Accounts:** you cannot act on an account holding permissions you lack,
  and the last active administrator is always kept.

The member menu can be rearranged, renamed,
split into submenus and restricted by permission; *Administration* can be
moved or renamed but never deleted. There is no Log out entry: `q` (or Esc)
in the main menu logs out.

### Connection limits and who is online

*Administration → Connection limits* (or `/admin/limits` on the web) sets
two limits, which take effect without a restart:

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
idle and when it connected, then every logged-in web session with its last
activity. It never shows addresses. Choosing a connection ends it after a
confirmation; the member is told it was ended by an administrator or
moderator, and the action is audited (`connection.ended`). Choosing a web
session logs it out after a confirmation (`web_session.ended`); the
member's next page asks them to log in again. The same list is on the web
at `/admin/online`. It needs `core.sessions.manage`, which administrators
have; give it to moderators by granting it to their group under *Groups
and permissions*. Nobody can end the connection of an account holding
permissions they lack, so a moderator cannot end an administrator's.

### Transition screens

Classic BBSes showed ANSI or ASCII art between screens. *Administration →
Transitions* sets this up; it needs `core.transitions.manage`, which
administrators have; grant it to moderators (or any group) under *Groups
and permissions*.

- A **profile** is a named set of text files. It shows either a random one
  of its files each time or always one chosen file.
- **Where they are shown**: each menu item has two transition points,
  opening it and returning from it to the menu. Each can show a profile,
  nothing, or the default; the default (one profile for opening, one for
  leaving) applies to every item set to it. Nothing is shown until a
  profile is chosen somewhere.
- **Files** can be written in the editor (*Write a new file*, or choose a
  file and *Edit*), managed on the web at `/admin/transitions`, or uploaded
  over SFTP to `/text/<profile>/<file>`.
  Uploading into a folder that does not exist creates the profile; `mkdir`
  creates an empty profile; `rm` deletes a file and `rmdir` an empty
  profile. Profile names use lowercase letters, digits and hyphens; file
  names letters, digits, dots, hyphens and underscores. Up to 50 files of
  64 KiB per profile.
- Files are **stored as plain text**: files that are not UTF-8 are read as
  code page 437 (classic DOS art), a SAUCE record is dropped, ANSI escape
  codes are removed (so colours are not shown), tabs are expanded and other
  control characters removed. Reading a file back over SFTP returns the
  cleaned text.
- Art is centred on screen, cut at the right and bottom edges if it is too
  big, and stays until the member presses a key. Members whose terminal
  is set to ASCII get line and block characters approximated (`+ - | #`).
- Every change is audited as `transition.changed`.

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
| `/text/<profile>/<file>` | Transition screen art, for members with `core.transitions.manage` (see *Transition screens*) |
| `/<plugin>/…` | Plugin data, e.g. conference threads (later stages) |

Directories you lack permission for do not appear. Uploads are accepted only
where a plugin allows them, up to the configured size, and are stored only
if the transfer completes. `rename` and links are refused, and so are
`mkdir`, `rm` and `rmdir` except under `/text`.
Password (add-key) logins cannot use SFTP. Permissions are re-checked on
every request, so locking an account takes effect immediately.

[SFTP.md](SFTP.md) lists every folder, the permission it needs, which
groups hold that permission by default, and what can be done in it.

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
- **Chat**: live channels. `[C]` channels are run by chat
  moderators (who can limit them to one or more groups — members of any
  chosen group, plus administrators — and set how long the log is kept,
  0 = not logged); `[P]` private chats are invite-only and can be
  started by any member; `[T]` thread chats belong to conference threads.
  *Find a channel* searches the names and topics of the channels you can
  join.
  **Paging** asks someone to come and talk: *Page someone* (`a` in the
  Chat menu) opens a private chat `#talk-<you>-<them>` (the same one again
  next time, from either side), invites them, pages them and waits there
  for them; `/page USER` in any chat pages someone into that chat (a
  private chat invites them; other channels must already be open to
  them). The member gets a notification — or, if they are in a chat, a
  line there straight away — that takes them to the chat. Only members
  who are online (over SSH, or following a chat on the web), accept pages
  from you (privacy setting *Who can page
  you*, default *Friends only*) and have page notifications on can be
  paged; the refusal does not say which. You can page the same person
  again after 5 minutes (admin setting in *Plugin settings → Chat*).
  Paging needs `chat.page` (members and moderators by default); the menu
  action also needs `chat.create`.
  Commands: `/help`, `/who`, `/channels`, `/join`, `/topic`, `/invite`,
  `/page`, `/kick`, `/createchat`, `/destroychat`, `/quit`. Logging is on by default
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
chat live in any channel you may join, start and run private chats, page
someone, read and manage your notifications, and vote in polls. Staff can manage users, groups and permissions, create and
revoke invites, approve or reject new accounts, see who is online and end
a connection, set the connection limits, the BBS name and plugin settings,
edit the member menu and the transition screens, and read the audit log.
Conference posting, creating polls, channel management, slash commands and
your own settings (apart from notification settings) stay in the SSH
interface.

The links at the top of every page follow the member menu: the same
entries in the same order, with the labels and extra permissions set in
the menu editor. A submenu opens a page listing its entries, as it does
over SSH, and *Administration* opens a page of the staff pages you may
use. Entries that only work over SSH (display settings, SSH keys and so
on) are left out, and so is a submenu with nothing in it for the web.

| Path | Description |
|------|-------------|
| `/` | Start page: how to connect, the SSH host key fingerprint, how to join |
| `/login` | Log in with your username and a one-time code from **Web login code** in the BBS main menu (single use, 5 minutes) |
| `/home` | Your start page once logged in; says how many notifications are new |
| `/menu/{id}` | A submenu of the member menu: its entries you can open on the web, and a link back to the menu above it |
| `/admin` | *Administration*: the staff pages below that you may use |
| `/notifications` | Your notifications, newest first, with *New* marks (the navigation link shows the count, e.g. *Notifications (2 new)*). A notification links to what it is about (the message, the thread or the chat) and opening it marks it seen; delete one, mark all as seen, or delete all (with a ticked box). *Notification settings* chooses which kinds you receive and whether new ones are listed between screens over SSH |
| `/p/conferences/` | Areas, conferences and threads you may read; polls on posts can be voted in, and a thread with a chat shows it live, and you can send messages |
| `/p/chat/` | Channels, private chats and thread chats you may join (with who is there and the topic), and a search by name or topic. Each channel has a live page: messages arrive as they are sent and you can send your own. Start a private chat with invitations; inside one, anyone in it can invite, and its creator (or a chat moderator) can change the topic, remove someone or close it. With `chat.page`, each channel page has *Page a member* (into that channel), and *Page someone* on the list pages a member into your private chat with them (`#talk-<you>-<them>`, also needs `chat.create`) and opens it. A member paged while following a chat on the web gets a line there pointing to Notifications |
| `/p/messages/` | Inbox, Sent and Deleted, with unread marks and counts; opening a message marks it read. Write a message (to usernames and your contact groups; markdown) or reply, with the same limits and privacy rules as over SSH. Delete (to Deleted, restorable), move back to the inbox, delete permanently, remove from Sent and empty the Deleted folder; the ones that cannot be undone need a ticked confirmation box |
| `/p/polls/` | Open polls (pinned first) and closed polls; vote or change your vote, and see results under the same rules as over SSH |
| `/p/wall/` | The wall (read-only); the message of the day is on `/home` |
| `/admin/users` | Users, for staff with `core.users.manage` or `core.groups.manage` (listed under *Administration* only for them): find accounts by the start of the username, then on an account's page see its status, groups, registration, last login and any erasure request. With `core.users.manage`: lock or unlock it, cancel an erasure request (each with a ticked box), and show its email address (a button; the address appears on the page that answers it and the viewing is audited). With `core.groups.manage`: add it to or remove it from a group. You cannot lock yourself, act on an account holding permissions you lack, or remove the last active administrator |
| `/admin/groups` | Groups and permissions, for staff with `core.groups.manage` (listed under *Administration* only for them): every group with its permission and member counts, and creating a group. A group's page lists its permissions (Revoke) with a Grant select, its members (Remove) with an Add field taking a username, and Delete for groups that are not built in (with a ticked box). The rules above apply: you can only grant what you hold, revoke from groups whose permissions you all hold, and add or remove members of groups you are in; built-in groups and the last active administrator are protected |
| `/admin/invites` | Invites, for staff with `core.invite.create` (their own) or `core.invite.manage` (all, with who created each): state, uses, expiry and note, and Revoke for usable ones (with a ticked confirmation box). **Create an invite** (`core.invite.create`) takes the same options as over SSH (uses, days, approval, groups, note) and shows the new code once, on the page that answers the form: it is never put in a URL and cannot be shown again. You can only attach groups whose permissions you hold and, apart from `member`, that you are in yourself |
| `/admin/pending` | Accounts awaiting approval, for staff with `core.users.approve` (administrators and moderators; linked as *Approvals* only for them): username and registration time, never the email address. Approve with one button; Reject (which deletes the account and its keys, and ends its connections) needs a ticked confirmation box. Nobody can approve or reject an account that would receive permissions they lack |
| `/admin/audit` | Audit log, for staff with `core.audit.view` (listed under *Administration* only for them): administrative actions as a table, newest first, 100 to a page with Older and Newest links; times in UTC. Read-only |
| `/admin/transitions` | Transition screens, for staff with `core.transitions.manage` (listed under *Administration* only for them): the profiles with their file counts and what they show, Add a profile, and a table of every menu item (plus the default) with a select each for opening it and returning to the menu (the default, nothing, or a profile), saved together. A profile's page lists its files, uploads a file (UTF-8 or code page 437, up to 64 KiB, cleaned as over SFTP; a file with the same name is replaced), writes a new one in a monospace text box, sets the name and which file it shows, and deletes the profile (with a ticked box). A file's page shows a preview, edits it and deletes it (with a ticked box). Same rules as *Administration → Transitions* |
| `/admin/menu` | Menu editor, for staff with `core.menu.manage` (listed under *Administration* only for them): the member menu as a table in order, with Move up and Move down, Edit (label and extra permission), Open for submenus, Delete (with a ticked confirmation box; Administration cannot be deleted, and a submenu must be emptied first), Add an entry, and Reset to the default menu. Same rules as *Administration → Menu editor* |
| `/admin/plugins` | Plugin settings, for staff with `core.plugins.settings` (administrators and moderators; listed under *Administration* only for them): each plugin's settings as a form, with each field's rules in words and its help, under the same validation as *Administration → Plugin settings*. A refused value is shown again with the reason next to its field |
| `/admin/branding` | Branding, for staff with `core.settings.manage` (listed under *Administration* only for them): the BBS name, with the same rules as *Administration → Branding* (1 to 40 printable characters) |
| `/admin/limits` | Connection limits, for staff with `core.settings.manage` (listed under *Administration* only for them): the idle timeout and connections per account, with the same rules as *Administration → Connection limits*. A refused value is shown again with the reason next to its field |
| `/admin/online` | Who is online, for staff with `core.sessions.manage` (listed under *Administration* only for them): a table of open SSH connections with account, what is open, idle time and connection time, and a table of logged-in web sessions with account, last activity (to the minute), login and expiry time. Addresses are never shown. **End** opens a confirmation page; ending needs a ticked box, follows the same rank rule as over SSH and is audited (`connection.ended`, `web_session.ended`). A logged-out web member's next page asks them to log in, and their live chat closes within 30 seconds. Your own web session is marked and ended by logging out |
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
  messages and who may page you. Defaults: *No one*, except status, online
  status, messages and pages, which are *Friends only*. Administrators can view an email address for
  account recovery; each view is recorded in the audit log.
- **Download my data**: over SFTP, `/me/export/account.json` and one folder
  per feature (`notifications`, `messages`, `conferences`, `contacts`,
  `polls`, `chat`), generated when you download them.
- **Erase my account**: needs a key login from the last 15 minutes and your
  username typed to confirm; you choose whether your posts and chat messages
  are deleted or kept anonymously. The account is locked at once, like a
  locked account: every open SSH and SFTP connection ends (showing the
  erasure date) and every web session and login code is deleted. It is
  erased after the grace period; an administrator can cancel until then,
  and you then log in afresh. Erasure
  removes keys, password, email, profile, preferences, groups, contacts
  (both ways), received messages and notifications (yours and those you
  caused), and unlinks poll votes (totals are
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
