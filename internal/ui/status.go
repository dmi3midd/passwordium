package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/dmi3midd/passwordium/internal/clipboard"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

const clipboardClearDuration = 15 * time.Second

type clipboardClearMsg struct {
	seq    int
	secret string
}

type clipboardCountdownMsg struct {
	seq int
}

func (m Model) copyEntryPassword(entry *pb.VaultEntry) (tea.Model, tea.Cmd) {
	pw, err := m.vault.DecryptPassword(entry)
	if err != nil {
		m.statusMsg = fmt.Sprintf("Failed to decrypt password: %v", err)
		m.statusIsErr = true
		return m, nil
	}

	if err := clipboard.Copy(pw); err != nil {
		m.statusMsg = fmt.Sprintf("Failed to copy to clipboard: %v", err)
		m.statusIsErr = true
		return m, nil
	}

	m.clipboardSeq++
	seq := m.clipboardSeq
	m.clipboardCountdown = int(clipboardClearDuration.Seconds())
	m.statusMsg = fmt.Sprintf("📋 Password for \"%s\" copied to clipboard", entry.Title)
	m.statusIsErr = false

	clearCmd := tea.Tick(clipboardClearDuration, func(t time.Time) tea.Msg {
		return clipboardClearMsg{seq: seq, secret: pw}
	})
	countdownCmd := tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return clipboardCountdownMsg{seq: seq}
	})

	return m, tea.Batch(clearCmd, countdownCmd)
}

func (m Model) renderStatusFooter(hints string) string {
	var lines []string

	if m.statusMsg != "" || m.clipboardCountdown > 0 {
		var statusLine string
		if m.statusIsErr {
			statusLine = ErrorStyle.Render(m.statusMsg)
		} else if m.statusMsg != "" {
			statusLine = SuccessStyle.Render(m.statusMsg)
		}
		if m.clipboardCountdown > 0 {
			timerBadge := NoticeStyle.Render(fmt.Sprintf("⏱ Auto-clearing clipboard in %ds", m.clipboardCountdown))
			if statusLine != "" {
				statusLine = statusLine + "   •   " + timerBadge
			} else {
				statusLine = timerBadge
			}
		}
		lines = append(lines, statusLine)
	}

	lines = append(lines, hints)
	return StatusBarStyle.Render(strings.Join(lines, "\n"))
}
