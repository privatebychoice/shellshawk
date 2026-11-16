This policy describes what {{.Site}} stores and why. The operator of this
server can replace it with their own.

## No tracking, no selling, no sharing

- No analytics, advertising, tracking pixels or fingerprinting.
- No third-party scripts, fonts, stylesheets or images: everything is
  served by this server.
- Personal information is never sold or shared.
- Links in posts are shown with a privacy grade so you can judge a site
  before visiting it. Images in posts are never loaded.

## Global Privacy Control

{{.Site}} honours [Global Privacy Control](https://globalprivacycontrol.org/)
(GPC). When your browser sends the `Sec-GPC: 1` signal, or reports
`navigator.globalPrivacyControl`, it is treated as a valid request to opt
out of the sale or sharing of your personal information, with no further
action needed from you. Because nothing is ever sold or shared, the same
protection applies whether or not you send the signal; not sending it is
never treated as consent. Support is declared at
`/.well-known/gpc.json`.

## What is stored

- **Your account**: username, SSH public keys, a hash of your password
  (only used to add keys), and optionally email, full name, phone and a
  status message. You choose who can see each of these.
- **What you write**: posts, messages, chat messages, poll votes (anonymous
  unless a poll says otherwise) and contacts.
- **Logs**: chat channels say when they are logged and for how long (the
  default is {{.ChatDays}} days). Server logs never contain IP addresses.
  Administrative actions are kept in an audit log for {{.AuditDays}} days.
- **Website**: one cookie, only after you log in, to keep you logged in for
  up to 12 hours. It is never used for anything else.

## Your rights

- **Access**: download everything stored about you over SFTP from
  `/me/export`.
- **Erasure**: choose *Erase my account* under *Privacy and profile*. Your
  account is locked at once and erased after {{.GraceDays}} days. Messages
  you sent stay with their recipients, attributed to an anonymous former
  member; you choose whether your posts and chat messages are deleted or
  kept anonymously.
- Erased data may remain in server backups until they are rotated.
