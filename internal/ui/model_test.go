package ui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestUIStateMachineFlow(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.enc")

	m := NewModel(vaultPath)
	if m.state != StateAuth || !m.isNewVault {
		t.Fatalf("expected initial StateAuth with isNewVault=true, got state=%v isNewVault=%v", m.state, m.isNewVault)
	}

	// Set master password and confirmation, then press Enter to create vault
	m.authInputs[0].SetValue("SuperSecretMaster123!")
	m.authInputs[1].SetValue("SuperSecretMaster123!")
	m.authFocusIdx = 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.state != StateList {
		t.Fatalf("expected StateList after vault creation, got %v (err: %s)", m.state, m.authErr)
	}

	// Press 'n' in StateList to create a new entry -> StateForm
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m = updated.(Model)
	if m.state != StateForm {
		t.Fatalf("expected StateForm after pressing 'n', got %v", m.state)
	}

	// Fill Title & Username, then press Ctrl+G to generate a cryptographic password
	m.formInputs[formFieldTitle].SetValue("GitLab")
	m.formInputs[formFieldUsername].SetValue("dev@example.com")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	m = updated.(Model)

	genPw := m.formInputs[formFieldPassword].Value()
	if len(genPw) < 16 {
		t.Fatalf("expected Ctrl+G to generate a strong password, got %q", genPw)
	}

	// Save form via Ctrl+S -> transitions to StateDetail with password hidden by default
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	if m.state != StateDetail {
		t.Fatalf("expected StateDetail after saving form, got %v (formErr: %s)", m.state, m.formErr)
	}
	if m.passwordRevealed {
		t.Fatalf("expected password to be hidden by default in StateDetail")
	}
	if strings.Contains(m.View(), genPw) {
		t.Fatalf("expected hidden password not to appear in View() before pressing 'v'")
	}

	// Press 'v' to temporarily decrypt and reveal the password via entryKey
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	m = updated.(Model)
	if !m.passwordRevealed || m.revealedPassword != genPw {
		t.Fatalf("expected password to be decrypted and revealed after 'v'")
	}
	if !strings.Contains(m.View(), genPw) {
		t.Fatalf("expected View() to display decrypted password after pressing 'v'")
	}

	// Press 'esc' to return to StateList and wipe revealed password from UI state
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.state != StateList {
		t.Fatalf("expected StateList after pressing 'esc', got %v", m.state)
	}
	if m.revealedPassword != "" || m.passwordRevealed {
		t.Fatalf("expected revealedPassword to be cleared when leaving StateDetail")
	}

	if m.vault != nil {
		m.vault.Close()
	}
}
