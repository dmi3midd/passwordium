package ui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dmi3midd/passwordium/internal/vault"
)

func newAuthInputs(isNewVault bool) []textinput.Model {
	authCount := 1
	if isNewVault {
		authCount = 2
	}
	inputs := make([]textinput.Model, authCount)
	for i := range authCount {
		ti := textinput.New()
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
		ti.CharLimit = 256
		ti.Width = 42
		if i == 0 {
			ti.Placeholder = "Enter master password..."
			ti.Focus()
		} else {
			ti.Placeholder = "Confirm master password..."
		}
		inputs[i] = ti
	}
	return inputs
}

func (m Model) updateAuth(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit

		case "tab":
			if !m.isNewVault {
				return m, nil
			}
			m.authFocusIdx = (m.authFocusIdx + 1) % len(m.authInputs)
			return m, m.focusAuthInput()

		case "shift+tab":
			if !m.isNewVault {
				return m, nil
			}
			m.authFocusIdx = (m.authFocusIdx - 1 + len(m.authInputs)) % len(m.authInputs)
			return m, m.focusAuthInput()

		case "enter":
			return m.submitAuth()
		}
	}

	var cmd tea.Cmd
	m.authInputs[m.authFocusIdx], cmd = m.authInputs[m.authFocusIdx].Update(msg)
	return m, cmd
}

func (m *Model) focusAuthInput() tea.Cmd {
	cmds := make([]tea.Cmd, len(m.authInputs))
	for i := range m.authInputs {
		if i == m.authFocusIdx {
			cmds[i] = m.authInputs[i].Focus()
		} else {
			m.authInputs[i].Blur()
		}
	}
	return tea.Batch(cmds...)
}

func (m Model) submitAuth() (tea.Model, tea.Cmd) {
	pw := m.authInputs[0].Value()
	if len(pw) == 0 {
		m.authErr = "Master password cannot be empty"
		m.authFocusIdx = 0
		return m, m.focusAuthInput()
	}

	if m.isNewVault {
		confirm := m.authInputs[1].Value()
		if pw != confirm {
			m.authErr = "Passwords do not match. Please try again"
			m.authInputs[1].SetValue("")
			m.authFocusIdx = 1
			return m, m.focusAuthInput()
		}

		pwBytes := []byte(pw)
		v, err := vault.Create(m.vaultPath, pwBytes)
		vault.ZeroBytes(pwBytes)
		if err != nil {
			m.authErr = fmt.Sprintf("Failed to create vault: %v", err)
			return m, nil
		}

		m.vault = v
		m.clearAuthInputs()
		m.refreshListItems("")
		m.state = StateList
		m.statusMsg = "✨ New encrypted vault created successfully"
		m.statusIsErr = false
		return m, nil
	}

	pwBytes := []byte(pw)
	v, err := vault.Open(m.vaultPath, pwBytes)
	vault.ZeroBytes(pwBytes)
	if err != nil {
		m.authInputs[0].SetValue("")
		if errors.Is(err, vault.ErrInvalidMasterPassword) {
			m.authErr = "Invalid master password"
		} else {
			m.authErr = fmt.Sprintf("Failed to open vault: %v", err)
		}
		return m, m.authInputs[0].Focus()
	}

	m.vault = v
	m.clearAuthInputs()
	m.refreshListItems("")
	m.state = StateList
	m.statusMsg = "🔓 Vault unlocked successfully"
	m.statusIsErr = false
	return m, nil
}

func (m *Model) clearAuthInputs() {
	for i := range m.authInputs {
		m.authInputs[i].SetValue("")
		m.authInputs[i].Blur()
	}
	m.authErr = ""
}

func (m Model) viewAuth() string {
	var b strings.Builder

	header := HeaderBadgeStyle.Render("Passwordium")
	b.WriteString(header)
	b.WriteString("\n\n")

	if m.isNewVault {
		b.WriteString(ValueStyle.Bold(true).Render("Initialize New Vault"))
		b.WriteString("\n")
		b.WriteString(SubHeaderStyle.Render(fmt.Sprintf("File %s not found. Create a master password.", m.vaultPath)))
		b.WriteString("\n\n")

		lbl1 := LabelStyle.Render("Master Password:")
		if m.authFocusIdx == 0 {
			lbl1 = FocusedLabelStyle.Render("▸ Master Password:")
		}
		b.WriteString(lbl1)
		b.WriteString(" ")
		b.WriteString(m.authInputs[0].View())
		b.WriteString("\n\n")

		lbl2 := LabelStyle.Render("Confirm Password:")
		if m.authFocusIdx == 1 {
			lbl2 = FocusedLabelStyle.Render("▸ Confirm Password:")
		}
		b.WriteString(lbl2)
		b.WriteString(" ")
		b.WriteString(m.authInputs[1].View())
		b.WriteString("\n")
	} else {
		b.WriteString(ValueStyle.Bold(true).Render("Unlock Vault"))
		b.WriteString("\n")
		b.WriteString(SubHeaderStyle.Render(fmt.Sprintf("Vault: %s", m.vaultPath)))
		b.WriteString("\n\n")

		lbl := FocusedLabelStyle.Render("▸ Master Password:")
		b.WriteString(lbl)
		b.WriteString(" ")
		b.WriteString(m.authInputs[0].View())
		b.WriteString("\n")
	}

	if m.authErr != "" {
		b.WriteString("\n")
		b.WriteString(ErrorStyle.Render(m.authErr))
		b.WriteString("\n")
	}

	hints := []string{
		renderKeyHint("enter", "unlock"),
	}
	if m.isNewVault {
		hints = []string{
			renderKeyHint("tab", "next field"),
			renderKeyHint("shift+tab", "prev field"),
			renderKeyHint("enter", "create vault"),
		}
	}
	hints = append(hints, renderKeyHint("esc", "quit"))

	card := CardStyle.Width(min(74, max(54, m.width-8))).Render(b.String())
	return lipgloss.JoinVertical(lipgloss.Left, card, StatusBarStyle.Render(strings.Join(hints, "   ")))
}
