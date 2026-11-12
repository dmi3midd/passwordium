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

	vaultPath := flag.String("vault", defaultPath, "Шлях до зашифрованого файлу сховища (Protobuf)")
	flag.Parse()

	p := tea.NewProgram(ui.NewModel(*vaultPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Помилка роботи TUI: %v\n", err)
		os.Exit(1)
	}
}
