package ui

import (
	"fmt"

	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

// entryItem wraps pb.VaultEntry to implement bubbles/list.DefaultItem.
// Note that sensitive fields inside entry remain encrypted while in the list.
type entryItem struct {
	entry *pb.VaultEntry
}

func (i entryItem) Title() string {
	if i.entry.Title == "" {
		return "(Без назви)"
	}
	return i.entry.Title
}

func (i entryItem) Description() string {
	user := i.entry.Username
	if user == "" {
		user = "—"
	}
	if i.entry.Url != "" {
		return fmt.Sprintf("%s  •  %s", user, i.entry.Url)
	}
	return user
}

// FilterValue enables fuzzy searching by both title and username in bubbles/list.
func (i entryItem) FilterValue() string {
	return i.entry.Title + " " + i.entry.Username
}

