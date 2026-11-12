package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/dmi3midd/passwordium/internal/ui"
)

func main() {
	defaultPath := os.Getenv("PASSWORDIUM_VAULT")
	if defaultPath == "" {
		defaultPath = "vault.enc"
	}

	vaultPath := flag.String("vault", defaultPath, "Path to the encrypted vault file (Protobuf)")
	flag.Parse()

	p := tea.NewProgram(ui.NewModel(*vaultPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI runtime error: %v\n", err)
		os.Exit(1)
	}
}
