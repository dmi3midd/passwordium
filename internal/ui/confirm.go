package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

func (m *Model) requestDelete(entry *pb.VaultEntry, returnState SessionState) {
	m.deleteEntryID = entry.Id
	m.deleteEntryTitle = entry.Title
	m.deleteReturnState = returnState
	m.state = StateConfirmDelete
}

func (m *Model) clearDeletePrompt() {
	m.deleteEntryID = ""
	m.deleteEntryTitle = ""
	m.deleteReturnState = StateList
}

func (m Model) updateConfirmDelete(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y":
			id := m.deleteEntryID
			title := m.deleteEntryTitle
			m.clearDeletePrompt()
			m.cleanupSensitiveState()

			if err := m.vault.DeleteEntry(id); err != nil {
				m.statusMsg = fmt.Sprintf("Failed to delete entry: %v", err)
				m.statusIsErr = true
				m.state = StateList
				return m, nil
			}

			m.refreshListItems("")
			m.state = StateList
			m.statusMsg = fmt.Sprintf("Entry \"%s\" deleted", title)
			m.statusIsErr = false
			return m, nil

		case "n":
			returnState := m.deleteReturnState
			m.clearDeletePrompt()
			m.state = returnState
			m.statusMsg = "Deletion cancelled"
			m.statusIsErr = false
			return m, nil
		}
	}

	return m, nil
}

func (m Model) viewConfirmDelete() string {
	var b strings.Builder

	b.WriteString(ErrorStyle.Render("Confirm deletion"))
	b.WriteString("\n\n")
	b.WriteString(ValueStyle.Render(fmt.Sprintf("Are you sure you want to delete \"%s\"?", nonEmpty(m.deleteEntryTitle, "(Untitled)"))))
	b.WriteString("\n")
	b.WriteString(MutedStyle.Render("This action cannot be undone."))

	card := CardStyle.
		BorderForeground(colorDanger).
		Width(min(70, max(50, m.width-8))).
		Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("y", "confirm delete"),
		renderKeyHint("n", "cancel"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
}
