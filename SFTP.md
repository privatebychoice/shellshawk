# SFTP access

shellshawk serves SFTP from a **virtual file system**. No SFTP path maps to
a file or directory on the host: every listing and every file is produced
from the database when it is requested, and uploads are written to the
database. This document lists each top-level folder, who can see it, and
what they can do in it.

See also docs/DESIGN.md §10 (design) and README.md (connecting).

## Who can use SFTP

| Login | SFTP |
|-------|------|
| Public key, active account | Yes |
| Public key, account awaiting approval | No: the `sftp` subsystem is refused |
| Password (registering with an invite code, or adding a key) | No: the `sftp` subsystem is refused |
| Locked account | No: the key login is refused. An account locked while connected is refused on its next request (clients show "not found" or "permission denied") |

```
sftp -P <port> <username>@<host>
```

## Rules for every folder

- **The root (`/`)** lists only the folders the member may use. A folder the
  member may not use is reported as "no such file", the same as a path that
  does not exist, so its existence is not revealed.
- **Permissions are checked on every request.** The account and its
  permissions are loaded again for each listing, read, upload and command,
  so locking an account or revoking a permission takes effect straight
  away, even in an open session.
- **Only listed files can be read.** A file name that is not in its folder's
  listing for that member is "no such file", so guessed IDs reveal nothing.
- **Read-only unless stated.** Only `/text` accepts uploads, `mkdir`, `rm`
  and `rmdir`. Everywhere else they are refused with "permission denied".
- **Never allowed anywhere:** rename, symbolic or hard links, `readlink`.
  `chmod`, `chown` and setting times (`setstat`) are accepted and ignored, so
  clients that set times after an upload do not fail.
- **Paths:** `..` is resolved within the virtual tree and cannot leave it.
  Names containing `/`, `\`, control characters, `.` or `..` are never listed
  and cannot be uploaded.
- **Uploads** are held in memory and stored only when the transfer finishes
  without error. The size limit is `SHELLSHAWK_SFTP_MAX_UPLOAD_BYTES`
  (default 1 MiB, at most 64 MiB); `/text` also limits each file to 64 KiB.
  Uploads in progress at the same time in one SFTP session share that
  limit, so upload large files one after another.
- **Times:** files show when their content was created or last changed, in
  UTC; generated files (such as `/me`) show the time of the request.

## Folders

| Folder | Permission needed | Held by default | Access |
|--------|-------------------|-----------------|--------|
| `/me` | None: every member | Everyone | Read-only; always your own data |
| `/messages` | None: every member | Everyone | Read-only; your own messages |
| `/conferences` | `conferences.read` | `member`, `moderator` (and `admin`, which holds every permission) | Read-only; conferences you may read |
| `/chat` | `chat.use` | `member`, `moderator` (and `admin`) | Read-only; logged channels you may enter |
| `/text` | `core.transitions.manage` | `admin` only | Read and write: upload, `rm`, `mkdir`, `rmdir` |

Administrators can change which groups hold a permission (*Administration →
Groups and permissions*, or `/admin/groups` on the web); the folders follow
those changes immediately.

### `/me` — your own data

```
/me/profile.md                 your account: status, registration, last login, groups, key count
/me/keys.pub                   your SSH public keys, one per line, with their labels
/me/export/account.json        your account record (right of access)
/me/export/notifications/notifications.json
/me/export/<plugin>/<file>.json
```

- **Who:** every member with SFTP access. Each member only ever sees their
  own files; there is no way to name another member in a path.
- **Export files are complete:** for example `messages.json` holds every
  message in your Inbox, Deleted and Sent folders, not only the 200 most
  recent that `/messages` and the BBS list.
- **Export folders:** one per plugin that stores member data: `chat`
  (`chat.json`), `conferences` (`posts.json`), `contacts`
  (`contacts.json`), `messages` (`messages.json`), `motd` (`motd.json`),
  `polls` (`polls.json`) and `wall` (`wall.json`), plus `notifications`.
- **Write:** none.

### `/messages` — your private messages

```
/messages/inbox/<YYYYMMDD-HHMMSS>-<id>-<subject>.md
/messages/sent/<YYYYMMDD-HHMMSS>-<id>-<subject>.md
```

- **Who:** every member with SFTP access.
- **Shows:** only messages in your own inbox and your own Sent folder, the
  most recent 200 in each, as in the BBS. Messages you have deleted (or
  removed from Sent) are not listed. A message file starts with
  `from`, `to`, `date` and `subject`, then the body.
- **Reading a file does not mark the message as read.**
- **Write:** none.

### `/conferences` — conference threads

```
/conferences/<area>/<conference>/<YYYYMMDD>-<thread id>-<title>.md
```

- **Who:** members holding `conferences.read`.
- **Shows:** only conferences you may read. A restricted conference is
  shown only to members of one of its groups and to administrators. Areas
  with no conference you may read are not listed. Each file is a whole
  thread with all its posts.
- **Write:** none. Posting is done from the BBS.

### `/chat` — chat logs

```
/chat/<channel>/<YYYYMMDD>.log
```

- **Who:** members holding `chat.use`.
- **Shows:** only channels you can enter now **and** that are logged
  (retention above 0 days). One file per day that has messages, in UTC, up
  to 100,000 lines.
  - **Channels:** everyone with `chat.use`; a restricted channel only to
    members of one of its groups and to administrators.
  - **Private chats:** their creator, members invited to them, and chat
    moderators (`chat.moderate`).
  - **Thread chats:** members who may read the thread's conference.
- **The whole retained log is available**, including messages from before
  you joined or were invited.
- Logs older than the channel's retention are deleted and disappear from the
  listing.
- **Write:** none.

### `/text` — transition screen text files

```
/text/<profile>/<file>
```

- **Who:** members holding `core.transitions.manage` (administrators by
  default). The permission is checked again inside every change, and every
  change is audited (`transition.changed`).
- **Read:** list profiles and their files, and download a file. Files are
  returned as they are shown: cleaned of terminal escape sequences and
  converted to UTF-8.
- **Write:**
  - **Upload** a file into `/text/<profile>/`. A profile that does not
    exist yet is created. Files are UTF-8 or code page 437, at most 64 KiB,
    cleaned before they are stored; a file with the same name is replaced.
  - **`mkdir /text/<profile>`** creates an empty profile; **`rmdir`**
    removes an empty one.
  - **`rm /text/<profile>/<file>`** deletes a file.
- **Limits:** at most 200 profiles and 50 files per profile; profile names
  up to 40 characters and file names up to 64.
- **Not allowed:** folders inside a profile, rename, links.
