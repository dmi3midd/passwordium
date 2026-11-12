package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dmi3midd/passwordium/internal/vault"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

const (
	formFieldTitle = iota
	formFieldUsername
	formFieldPassword
	formFieldURL
	formFieldNotes
	formFieldCount
)

func (m *Model) initForm(entry *pb.VaultEntry) tea.Cmd {
	inputs := make([]textinput.Model, formFieldCount)

	placeholders := []string{
		"e.g., GitHub, Gmail, AWS...",
		"username or email@example.com",
		"Press Ctrl+G to generate a strong password",
		"https://...",
		"Additional notes, recovery codes, PIN...",
	}

	for i := range formFieldCount {
		ti := textinput.New()
		ti.Placeholder = placeholders[i]
		ti.CharLimit = 512
		ti.Width = 52
		if i == formFieldPassword {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		inputs[i] = ti
	}

	m.formShowPass = false
	m.formErr = ""
	m.formFocusIdx = 0

	if entry != nil {
		m.isEditing = true
		m.editingEntryID = entry.Id
		inputs[formFieldTitle].SetValue(entry.Title)
		inputs[formFieldUsername].SetValue(entry.Username)
		if pw, err := m.vault.DecryptPassword(entry); err == nil {
			inputs[formFieldPassword].SetValue(pw)
		}
		inputs[formFieldURL].SetValue(entry.Url)
		if notes, err := m.vault.DecryptNotes(entry); err == nil {
			inputs[formFieldNotes].SetValue(notes)
		}
	} else {
		m.isEditing = false
		m.editingEntryID = ""
	}

	m.formInputs = inputs
	return m.formInputs[0].Focus()
}

func (m Model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			editingID := m.editingEntryID
			wasEditing := m.isEditing
			m.clearFormInputs()
			if wasEditing {
				if entry, ok := m.vault.GetEntry(editingID); ok {
					m.openDetail(entry)
					return m, nil
				}
			}
			m.state = StateList
			return m, nil

		case "ctrl+g":
			generated, err := vault.GeneratePassword(vault.DefaultGeneratedPasswordLen)
			if err != nil {
				m.formErr = fmt.Sprintf("Failed to generate password: %v", err)
				return m, nil
			}
			m.formInputs[formFieldPassword].SetValue(generated)
			m.formInputs[formFieldPassword].CursorEnd()
			m.statusMsg = "🎲 Generated cryptographically secure password (20 chars)"
			m.statusIsErr = false
			return m, nil

		case "ctrl+r":
			m.formShowPass = !m.formShowPass
			if m.formShowPass {
				m.formInputs[formFieldPassword].EchoMode = textinput.EchoNormal
			} else {
				m.formInputs[formFieldPassword].EchoMode = textinput.EchoPassword
			}
			return m, nil

		case "ctrl+s":
			return m.submitForm()

		case "tab", "shift+tab", "down", "up":
			if msg.String() == "tab" || msg.String() == "down" {
				m.formFocusIdx = (m.formFocusIdx + 1) % formFieldCount
			} else {
				m.formFocusIdx = (m.formFocusIdx - 1 + formFieldCount) % formFieldCount
			}
			cmds := make([]tea.Cmd, formFieldCount)
			for i := range formFieldCount {
				if i == m.formFocusIdx {
					cmds[i] = m.formInputs[i].Focus()
				} else {
					m.formInputs[i].Blur()
				}
			}
			return m, tea.Batch(cmds...)

		case "enter":
			if m.formFocusIdx < formFieldCount-1 {
				m.formInputs[m.formFocusIdx].Blur()
				m.formFocusIdx++
				return m, m.formInputs[m.formFocusIdx].Focus()
			}
			return m.submitForm()
		}
	}

	var cmd tea.Cmd
	m.formInputs[m.formFocusIdx], cmd = m.formInputs[m.formFocusIdx].Update(msg)
	return m, cmd
}

func (m Model) submitForm() (tea.Model, tea.Cmd) {
	title := strings.TrimSpace(m.formInputs[formFieldTitle].Value())
	username := strings.TrimSpace(m.formInputs[formFieldUsername].Value())
	password := m.formInputs[formFieldPassword].Value()
	url := strings.TrimSpace(m.formInputs[formFieldURL].Value())
	notes := m.formInputs[formFieldNotes].Value()

	if title == "" {
		m.formErr = "Field \"Title\" is required"
		m.formInputs[m.formFocusIdx].Blur()
		m.formFocusIdx = formFieldTitle
		return m, m.formInputs[formFieldTitle].Focus()
	}
	if password == "" {
		m.formErr = "Field \"Password\" cannot be empty (press Ctrl+G to generate)"
		m.formInputs[m.formFocusIdx].Blur()
		m.formFocusIdx = formFieldPassword
		return m, m.formInputs[formFieldPassword].Focus()
	}

	if m.isEditing {
		updated, err := m.vault.UpdateEntry(m.editingEntryID, title, username, password, url, notes)
		if err != nil {
			m.formErr = fmt.Sprintf("Failed to save entry: %v", err)
			return m, nil
		}
		m.clearFormInputs()
		m.refreshListItems(updated.Id)
		m.openDetail(updated)
		m.statusMsg = fmt.Sprintf("✅ Entry \"%s\" updated and saved atomically", updated.Title)
		m.statusIsErr = false
		return m, nil
	}

	created, err := m.vault.AddEntry(title, username, password, url, notes)
	if err != nil {
		m.formErr = fmt.Sprintf("Failed to create entry: %v", err)
		return m, nil
	}
	m.clearFormInputs()
	m.refreshListItems(created.Id)
	m.openDetail(created)
	m.statusMsg = fmt.Sprintf("✨ Entry \"%s\" created and encrypted", created.Title)
	m.statusIsErr = false
	return m, nil
}

func (m *Model) clearFormInputs() {
	for i := range m.formInputs {
		m.formInputs[i].SetValue("")
		m.formInputs[i].Blur()
	}
	m.formErr = ""
	m.isEditing = false
	m.editingEntryID = ""
}

func (m Model) viewForm() string {
	var b strings.Builder

	if m.isEditing {
		b.WriteString(HeaderBadgeStyle.Render("✏️ EDIT ENTRY"))
		b.WriteString("\n\n")
	} else {
		b.WriteString(HeaderBadgeStyle.Render("➕ NEW ENTRY"))
		b.WriteString("\n\n")
	}

	labels := []string{
		"Title:",
		"Username:",
		"Password:",
		"URL:",
		"Notes:",
	}

	for i := range formFieldCount {
		lbl := LabelStyle.Render(labels[i])
		if m.formFocusIdx == i {
			lbl = FocusedLabelStyle.Render("▸ " + labels[i])
		}
		b.WriteString(lbl)
		b.WriteString(" ")
		b.WriteString(m.formInputs[i].View())
		if i == formFieldPassword {
			b.WriteString("  ")
			b.WriteString(MutedStyle.Render("[Ctrl+G: generate | Ctrl+R: reveal]"))
		}
		b.WriteString("\n\n")
	}

	if m.formErr != "" {
		b.WriteString(ErrorStyle.Render("⚠️ " + m.formErr))
		b.WriteString("\n")
	}

	card := CardStyle.Width(min(92, max(64, m.width-8))).Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("tab/shift+tab", "navigate"),
		renderKeyHint("ctrl+g", "generate password"),
		renderKeyHint("ctrl+r", "reveal password"),
		renderKeyHint("ctrl+s/enter", "save"),
		renderKeyHint("esc", "cancel"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
}
