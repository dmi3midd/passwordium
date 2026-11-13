package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func newEntryList() list.Model {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(colorPrimary).
		BorderLeftForeground(colorPrimary)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(colorSecondary).
		BorderLeftForeground(colorPrimary)

	l := list.New([]list.Item{}, delegate, 80, 20)
	l.Title = "🔐 Passwordium — Password Vault"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false)

	// Enforce a single canonical key per list action (no alternative keys)
	l.KeyMap = list.KeyMap{
		CursorUp:             key.NewBinding(key.WithKeys("up"), key.WithHelp("up", "up")),
		CursorDown:           key.NewBinding(key.WithKeys("down"), key.WithHelp("down", "down")),
		PrevPage:             key.NewBinding(key.WithKeys("left"), key.WithHelp("left", "prev page")),
		NextPage:             key.NewBinding(key.WithKeys("right"), key.WithHelp("right", "next page")),
		GoToStart:            key.NewBinding(key.WithKeys("home"), key.WithHelp("home", "start")),
		GoToEnd:              key.NewBinding(key.WithKeys("end"), key.WithHelp("end", "end")),
		Filter:               key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "search")),
		ClearFilter:          key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "clear search")),
		CancelWhileFiltering: key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel")),
		AcceptWhileFiltering: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "apply")),
		ShowFullHelp:         key.NewBinding(key.WithDisabled()),
		CloseFullHelp:        key.NewBinding(key.WithDisabled()),
		Quit:                 key.NewBinding(key.WithDisabled()),
		ForceQuit:            key.NewBinding(key.WithDisabled()),
	}

	return l
}

func (m *Model) refreshListItems(selectID string) {
	if m.vault == nil {
		return
	}
	entries := m.vault.Entries()
	items := make([]list.Item, len(entries))
	selectedIdx := 0
	for i, e := range entries {
		items[i] = entryItem{entry: e}
		if selectID != "" && e.Id == selectID {
			selectedIdx = i
		}
	}
	m.list.SetItems(items)
	if selectID != "" && len(items) > 0 {
		m.list.Select(selectedIdx)
	}
}

func (m Model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	// If the user is actively typing a filter query inside bubbles/list,
	// let bubbles/list handle all keystrokes directly.
	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q":
			m.cleanupSensitiveState()
			if m.vault != nil {
				m.vault.Close()
			}
			return m, tea.Quit

		case "n":
			cmd := m.initForm(nil)
			m.state = StateForm
			return m, cmd

		case "enter":
			item, ok := m.list.SelectedItem().(entryItem)
			if !ok || item.entry == nil {
				return m, nil
			}
			m.openDetail(item.entry)
			return m, nil

		case "c":
			item, ok := m.list.SelectedItem().(entryItem)
			if !ok || item.entry == nil {
				m.statusMsg = "No entry selected to copy"
				m.statusIsErr = true
				return m, nil
			}
			return m.copyEntryPassword(item.entry)

		case "u":
			item, ok := m.list.SelectedItem().(entryItem)
			if !ok || item.entry == nil {
				m.statusMsg = "No entry selected to copy"
				m.statusIsErr = true
				return m, nil
			}
			return m.copyEntryUsername(item.entry)

		case "d":
			item, ok := m.list.SelectedItem().(entryItem)
			if !ok || item.entry == nil {
				return m, nil
			}
			title := item.entry.Title
			if err := m.vault.DeleteEntry(item.entry.Id); err != nil {
				m.statusMsg = fmt.Sprintf("Failed to delete entry: %v", err)
				m.statusIsErr = true
				return m, nil
			}
			m.refreshListItems("")
			m.statusMsg = fmt.Sprintf("Entry \"%s\" deleted", title)
			m.statusIsErr = false
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m Model) viewList() string {
	hints := strings.Join([]string{
		renderKeyHint("up", "up"),
		renderKeyHint("down", "down"),
		renderKeyHint("n", "new"),
		renderKeyHint("enter", "view"),
		renderKeyHint("c", "copy password"),
		renderKeyHint("u", "copy username"),
		renderKeyHint("d", "delete"),
		renderKeyHint("s", "search"),
		renderKeyHint("q", "quit"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		m.list.View(),
		m.renderStatusFooter(hints),
	)
}
