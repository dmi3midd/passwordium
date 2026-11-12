package clipboard

import (
	"github.com/atotto/clipboard"
)

// Copy writes the given secret string to the system clipboard.
func Copy(secret string) error {
	return clipboard.WriteAll(secret)
}

// Clear overwrites the system clipboard with an empty string.
// If expected is non-empty, it clears the clipboard only if its current contents still match expected,
// avoiding wiping unrelated text copied by the user in the meantime.
func Clear(expected string) error {
	if expected != "" {
		current, err := clipboard.ReadAll()
		if err == nil && current != expected {
			return nil
		}
	}
	return clipboard.WriteAll("")
}
