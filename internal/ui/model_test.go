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

	// Set master password, press Tab to switch to confirm field, set confirm password, then press Enter
	m.authInputs[0].SetValue("SuperSecretMaster123!")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	m.authInputs[1].SetValue("SuperSecretMaster123!")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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

	// Fill Title, Tab to Username, Tab to Password, then press Ctrl+G to generate a cryptographic password
	m.formInputs[formFieldTitle].SetValue("GitLab")
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	m.formInputs[formFieldUsername].SetValue("dev@example.com")
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	m = updated.(Model)

	genPw := m.formInputs[formFieldPassword].Value()
	if len(genPw) < 16 {
		t.Fatalf("expected Ctrl+G to generate a strong password, got %q", genPw)
	}

	// Tab to URL, Tab to Notes (textarea), and enter multiline notes
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	multilineNotes := "code-1111\ncode-2222"
	m.formNotes.SetValue(multilineNotes)

	// Save form via Ctrl+S -> transitions to StateDetail with password hidden by default
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = updated.(Model)
	if m.state != StateDetail {
		t.Fatalf("expected StateDetail after saving form, got %v (formErr: %s)", m.state, m.formErr)
	}
	if m.decryptedNotes != multilineNotes {
		t.Fatalf("expected multiline notes %q, got %q", multilineNotes, m.decryptedNotes)
	}
	if m.passwordRevealed {
		t.Fatalf("expected password to be hidden by default in StateDetail")
	}
	if strings.Contains(m.View(), genPw) {
		t.Fatalf("expected hidden password not to appear in View() before pressing 'v'")
	}

	// Press 'u' to copy username without starting the 15s auto-clear timer
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'u'}})
	m = updated.(Model)
	if m.clipboardCountdown != 0 {
		t.Fatalf("expected clipboardCountdown to remain 0 after copying username, got %d", m.clipboardCountdown)
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

func TestAutoLockOnInactivity(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.enc")

	m := NewModel(vaultPath)
	m.authInputs[0].SetValue("MasterPass#2026")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	m.authInputs[1].SetValue("MasterPass#2026")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.state != StateList || m.vault == nil {
		t.Fatalf("expected unlocked StateList, got state=%v", m.state)
	}

	// Simulate stale autoLockMsg from an earlier sequence
	staleSeq := m.inactivitySeq - 1
	updated, _ = m.Update(autoLockMsg{seq: staleSeq})
	m = updated.(Model)
	if m.state != StateList || m.vault == nil {
		t.Fatalf("expected stale autoLockMsg not to lock the vault")
	}

	// Simulate active autoLockMsg matching current inactivitySeq
	updated, _ = m.Update(autoLockMsg{seq: m.inactivitySeq})
	m = updated.(Model)
	if m.state != StateAuth {
		t.Fatalf("expected StateAuth after auto-lock, got %v", m.state)
	}
	if m.vault != nil {
		t.Fatalf("expected vault to be closed and cleared on auto-lock")
	}
	if m.isNewVault {
		t.Fatalf("expected isNewVault=false after vault was created and locked")
	}
	if !strings.Contains(m.View(), "inactivity") {
		t.Fatalf("expected auth view to show inactivity notice, got:\n%s", m.View())
	}
}
