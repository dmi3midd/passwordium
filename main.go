package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/dmi3midd/passwordium/internal/ui"
	"github.com/dmi3midd/passwordium/internal/vault"
)

func main() {
	vaultPath, err := vault.SystemVaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve vault path: %v\n", err)
		os.Exit(1)
	}

	p := tea.NewProgram(ui.NewModel(vaultPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI runtime error: %v\n", err)
		os.Exit(1)
	}
}
