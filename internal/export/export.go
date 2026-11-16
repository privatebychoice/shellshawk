// Package export defines the pieces of a member's data export (the right of
// access, docs/DESIGN.md §5.2). Core and each plugin contribute files; the
// SFTP /me/export directory serves them.
package export

import (
	"context"
	"encoding/json"
)

// File is one file of a member's export.
type File struct {
	Name string // plain file name, e.g. "messages.json"
	Data []byte
}

// Source produces a member's files for one part of the system.
type Source struct {
	Name   string // directory under /me/export ("" for the top level)
	Export func(ctx context.Context, userID int64) ([]File, error)
}

// JSON returns v as an indented JSON file.
func JSON(name string, v any) (File, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return File{}, err
	}
	return File{Name: name, Data: append(b, '\n')}, nil
}
