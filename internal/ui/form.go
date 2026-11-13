package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
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
	inputs := make([]textinput.Model, formFieldNotes)

	placeholders := []string{
		"e.g., GitHub, Gmail, AWS...",
		"username or email@example.com",
		"Press Ctrl+G to generate a strong password",
		"https://...",
	}

	for i := range formFieldNotes {
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

	ta := textarea.New()
	ta.Placeholder = "Additional notes, recovery codes, SSH keys..."
	ta.SetWidth(52)
	ta.SetHeight(5)
	ta.CharLimit = 4096
	ta.ShowLineNumbers = false
	ta.Blur()

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
			ta.SetValue(notes)
		}
	} else {
		m.isEditing = false
		m.editingEntryID = ""
	}

	m.formInputs = inputs
	m.formNotes = ta
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
			if m.formFocusIdx != formFieldPassword {
				return m, nil
			}
			generated, err := vault.GeneratePassword(vault.DefaultGeneratedPasswordLen)
			if err != nil {
				m.formErr = fmt.Sprintf("Failed to generate password: %v", err)
				return m, nil
			}
			m.formInputs[formFieldPassword].SetValue(generated)
			m.formInputs[formFieldPassword].CursorEnd()
			m.statusMsg = "Generated cryptographically secure password (20 chars)"
			m.statusIsErr = false
			return m, nil

		case "ctrl+r":
			if m.formFocusIdx != formFieldPassword {
				return m, nil
			}
			m.formShowPass = !m.formShowPass
			if m.formShowPass {
				m.formInputs[formFieldPassword].EchoMode = textinput.EchoNormal
			} else {
				m.formInputs[formFieldPassword].EchoMode = textinput.EchoPassword
			}
			return m, nil

		case "ctrl+s":
			return m.submitForm()

		case "tab":
			m.formFocusIdx = (m.formFocusIdx + 1) % formFieldCount
			return m, m.focusFormInput()

		case "shift+tab":
			m.formFocusIdx = (m.formFocusIdx - 1 + formFieldCount) % formFieldCount
			return m, m.focusFormInput()
		}
	}

	var cmd tea.Cmd
	if m.formFocusIdx == formFieldNotes {
		m.formNotes, cmd = m.formNotes.Update(msg)
	} else {
		m.formInputs[m.formFocusIdx], cmd = m.formInputs[m.formFocusIdx].Update(msg)
	}
	return m, cmd
}

func (m *Model) focusFormInput() tea.Cmd {
	cmds := make([]tea.Cmd, 0, formFieldCount)
	for i := range formFieldNotes {
		if i == m.formFocusIdx {
			cmds = append(cmds, m.formInputs[i].Focus())
		} else {
			m.formInputs[i].Blur()
		}
	}
	if m.formFocusIdx == formFieldNotes {
		cmds = append(cmds, m.formNotes.Focus())
	} else {
		m.formNotes.Blur()
	}
	return tea.Batch(cmds...)
}

func (m Model) submitForm() (tea.Model, tea.Cmd) {
	title := strings.TrimSpace(m.formInputs[formFieldTitle].Value())
	username := strings.TrimSpace(m.formInputs[formFieldUsername].Value())
	password := m.formInputs[formFieldPassword].Value()
	url := strings.TrimSpace(m.formInputs[formFieldURL].Value())
	notes := m.formNotes.Value()

	if title == "" {
		m.formErr = "Field \"Title\" is required"
		m.formFocusIdx = formFieldTitle
		return m, m.focusFormInput()
	}
	if password == "" {
		m.formErr = "Field \"Password\" cannot be empty (press Ctrl+G on Password field to generate)"
		m.formFocusIdx = formFieldPassword
		return m, m.focusFormInput()
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
		m.statusMsg = fmt.Sprintf("Entry \"%s\" updated and saved atomically", updated.Title)
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
	m.statusMsg = fmt.Sprintf("Entry \"%s\" created and encrypted", created.Title)
	m.statusIsErr = false
	return m, nil
}

func (m *Model) clearFormInputs() {
	for i := range m.formInputs {
		m.formInputs[i].SetValue("")
		m.formInputs[i].Blur()
	}
	m.formNotes.SetValue("")
	m.formNotes.Blur()
	m.formErr = ""
	m.isEditing = false
	m.editingEntryID = ""
}

func (m Model) viewForm() string {
	var b strings.Builder

	if m.isEditing {
		b.WriteString(HeaderBadgeStyle.Render("Edit entry"))
		b.WriteString("\n\n")
	} else {
		b.WriteString(HeaderBadgeStyle.Render("New entry"))
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
		if i == formFieldNotes {
			b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, lbl, " ", m.formNotes.View()))
			b.WriteString("\n\n")
			continue
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
		b.WriteString(ErrorStyle.Render(m.formErr))
		b.WriteString("\n")
	}

	card := CardStyle.Width(min(92, max(64, m.width-8))).Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("tab", "next field"),
		renderKeyHint("shift+tab", "prev field"),
		renderKeyHint("ctrl+g", "generate password"),
		renderKeyHint("ctrl+r", "reveal password"),
		renderKeyHint("ctrl+s", "save"),
		renderKeyHint("esc", "cancel"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
}
