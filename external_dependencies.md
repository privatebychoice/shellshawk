# External Dependencies

shellshawk is core-first: everything not listed here is the Go standard
library. shellshawk makes **no third-party network calls at runtime**.

Versions are pinned in `go.mod` / `go.sum`; the table records what was vetted.
To list exactly what is linked into a build: `go version -m bin/shellshawk`.

## Direct dependencies

| Name | Version | Project URL | Purpose | Security / privacy notes |
|------|---------|-------------|---------|--------------------------|
| `modernc.org/sqlite` | v1.62.0 | https://gitlab.com/cznic/sqlite | SQLite driver for `database/sql` (bundles SQLite 3.54.1) | Pure Go: SQLite's C code is machine-translated to Go, so no cgo and fully static, cross-compiled binaries. Embedded, file-based database; no network access. Actively maintained. A known trade-off is that the transitive tree is larger than the cgo driver's (listed below). `govulncheck` reported nothing (2026-11-16). |

## Transitive dependencies linked into the binary

All pulled in by `modernc.org/sqlite`. None make network calls.

| Name | Version | Project URL | Purpose / notes |
|------|---------|-------------|-----------------|
| `modernc.org/libc` | v1.80.1 | https://gitlab.com/cznic/libc | C runtime emulation for the translated SQLite code; same maintainer |
| `modernc.org/mathutil` | v1.7.1 | https://gitlab.com/cznic/mathutil | Math helpers; same maintainer |
| `modernc.org/memory` | v1.12.1 | https://gitlab.com/cznic/memory | Memory allocator for libc; same maintainer |
| `golang.org/x/sys` | v0.49.0 | https://pkg.go.dev/golang.org/x/sys | OS syscalls; Go team |
| `github.com/dustin/go-humanize` | v1.1.0 | https://github.com/dustin/go-humanize | Number formatting used by libc; small, stable, rarely updated |
| `github.com/google/uuid` | v1.6.0 | https://github.com/google/uuid | UUIDs used by libc; Google-maintained |
| `github.com/mattn/go-isatty` | v0.0.24 | https://github.com/mattn/go-isatty | Terminal detection used by libc; widely used |
| `github.com/ncruces/go-strftime` | v1.1.0 | https://github.com/ncruces/go-strftime | strftime formatting used by libc; small |
| `github.com/remyoudompheng/bigfft` | 2023-01-29 pseudo-version | https://github.com/remyoudompheng/bigfft | Big-integer FFT multiplication used by mathutil. **Flag:** no tagged releases and no commits since 2023 — small, pure-computation package with no I/O, so the risk is low, but watch it |

`go list -m all` also shows build-tool modules (`modernc.org/cc`, `ccgo`,
`golang.org/x/tools`, …). They are part of the module graph but are **not**
compiled into shellshawk.

## Planned (approved in docs/DESIGN.md, not yet added)

| Name | Stage | Purpose |
|------|-------|---------|
| `golang.org/x/crypto/ssh` | 2 | SSH server |
| `github.com/pkg/sftp` | 7 | SFTP subsystem (`RequestServer` API only) |
| `github.com/yuin/goldmark` | 5 | Markdown parsing |
| `go.privatebychoice.com/pbc-classification` | 5 | Link privacy grading |
