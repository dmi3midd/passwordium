package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

func (m *Model) openDetail(entry *pb.VaultEntry) {
	m.cleanupSensitiveState()
	m.selectedEntry = entry
	notes, err := m.vault.DecryptNotes(entry)
	if err == nil {
		m.decryptedNotes = notes
	} else {
		m.decryptedNotes = ""
	}
	m.state = StateDetail
}

func (m *Model) cleanupSensitiveState() {
	m.passwordRevealed = false
	m.revealedPassword = ""
	m.decryptedNotes = ""
	m.selectedEntry = nil
}

func (m Model) updateDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.selectedEntry == nil {
		m.state = StateList
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.cleanupSensitiveState()
			m.state = StateList
			return m, nil

		case "v":
			if m.passwordRevealed {
				m.passwordRevealed = false
				m.revealedPassword = ""
				m.statusMsg = "Password encrypted"
				m.statusIsErr = false
				return m, nil
			}
			pw, err := m.vault.DecryptPassword(m.selectedEntry)
			if err != nil {
				m.statusMsg = fmt.Sprintf("Failed to decrypt password: %v", err)
				m.statusIsErr = true
				return m, nil
			}
			m.revealedPassword = pw
			m.passwordRevealed = true
			m.statusMsg = "Password temporarily decrypted"
			m.statusIsErr = false
			return m, nil

		case "c":
			return m.copyEntryPassword(m.selectedEntry)

		case "u":
			return m.copyEntryUsername(m.selectedEntry)

		case "e":
			entry := m.selectedEntry
			m.cleanupSensitiveState()
			cmd := m.initForm(entry)
			m.state = StateForm
			return m, cmd

		case "d":
			m.requestDelete(m.selectedEntry, StateDetail)
			return m, nil
		}
	}

	return m, nil
}

func (m Model) viewDetail() string {
	if m.selectedEntry == nil {
		return ""
	}
	e := m.selectedEntry

	var b strings.Builder
	b.WriteString(HeaderBadgeStyle.Render("Entry details"))
	b.WriteString("  ")
	b.WriteString(MutedStyle.Render("ID: " + e.Id))
	b.WriteString("\n\n")

	b.WriteString(LabelStyle.Render("Title:"))
	b.WriteString(" ")
	b.WriteString(ValueStyle.Bold(true).Render(nonEmpty(e.Title, "—")))
	b.WriteString("\n")
	b.WriteString(LabelStyle.Render("Username:"))
	b.WriteString(" ")
	b.WriteString(ValueStyle.Render(nonEmpty(e.Username, "—")))
	b.WriteString("\n")

	var pwRender string
	if m.passwordRevealed {
		pwRender = RevealedPasswordStyle.Render(m.revealedPassword)
	} else {
		pwRender = MaskedPasswordStyle.Render("••••••••••••")
	}
	b.WriteString(LabelStyle.Render("Password:"))
	b.WriteString(" ")
	b.WriteString(pwRender)
	b.WriteString("\n")

	b.WriteString(LabelStyle.Render("URL:"))
	b.WriteString(" ")
	b.WriteString(ValueStyle.Render(nonEmpty(e.Url, "—")))
	b.WriteString("\n")
	notesBlock := lipgloss.JoinHorizontal(
		lipgloss.Top,
		LabelStyle.Render("Notes:"),
		" ",
		ValueStyle.Render(nonEmpty(m.decryptedNotes, "—")),
	)
	b.WriteString(notesBlock)
	b.WriteString("\n\n")

	createdStr := formatUnixTime(e.CreatedAt)
	updatedStr := formatUnixTime(e.UpdatedAt)
	b.WriteString(MutedStyle.Render(fmt.Sprintf("Created: %s   |   Updated: %s", createdStr, updatedStr)))

	card := CardStyle.Width(min(84, max(58, m.width-8))).Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("v", "show/hide password"),
		renderKeyHint("c", "copy password (15s)"),
		renderKeyHint("u", "copy username"),
		renderKeyHint("e", "edit"),
		renderKeyHint("d", "delete"),
		renderKeyHint("esc", "back"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
}
