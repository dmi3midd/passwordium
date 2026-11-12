package ui

import (
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/dmi3midd/passwordium/internal/clipboard"
	"github.com/dmi3midd/passwordium/internal/vault"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
)

// SessionState represents the active screen in the Bubble Tea state machine.
type SessionState int

const (
	StateAuth SessionState = iota
	StateList
	StateDetail
	StateForm
)

// Model is the main Bubble Tea finite state machine model for Passwordium.
type Model struct {
	state     SessionState
	vaultPath string
	vault     *vault.Vault

	width  int
	height int

	// StateAuth fields
	isNewVault   bool
	authInputs   []textinput.Model
	authFocusIdx int
	authErr      string

	// StateList fields
	list list.Model

	// StateDetail fields
	selectedEntry    *pb.VaultEntry
	passwordRevealed bool
	revealedPassword string
	decryptedNotes   string

	// StateForm fields
	isEditing      bool
	editingEntryID string
	formInputs     []textinput.Model
	formFocusIdx   int
	formShowPass   bool
	formErr        string

	// Clipboard & Status notifications
	statusMsg          string
	statusIsErr        bool
	clipboardSeq       int
	clipboardCountdown int
}

// NewModel initializes the root Bubble Tea model starting in StateAuth.
func NewModel(vaultPath string) Model {
	isNew := !vault.Exists(vaultPath)

	return Model{
		state:      StateAuth,
		vaultPath:  vaultPath,
		isNewVault: isNew,
		authInputs: newAuthInputs(isNew),
		list:       newEntryList(),
		width:      90,
		height:     28,
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		listWidth := max(40, msg.Width-6)
		listHeight := max(10, msg.Height-8)
		m.list.SetSize(listWidth, listHeight)
		return m, nil

	case clipboardCountdownMsg:
		if msg.seq == m.clipboardSeq && m.clipboardCountdown > 0 {
			m.clipboardCountdown--
			if m.clipboardCountdown > 0 {
				return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
					return clipboardCountdownMsg{seq: msg.seq}
				})
			}
		}
		return m, nil

	case clipboardClearMsg:
		if msg.seq == m.clipboardSeq {
			_ = clipboard.Clear(msg.secret)
			m.clipboardCountdown = 0
			m.statusMsg = "Clipboard automatically cleared (15s elapsed)"
			m.statusIsErr = false
		}
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.cleanupSensitiveState()
			if m.vault != nil {
				m.vault.Close()
			}
			return m, tea.Quit
		}
	}

	switch m.state {
	case StateAuth:
		return m.updateAuth(msg)
	case StateList:
		return m.updateList(msg)
	case StateDetail:
		return m.updateDetail(msg)
	case StateForm:
		return m.updateForm(msg)
	default:
		return m, nil
	}
}

func (m Model) View() string {
	var content string
	switch m.state {
	case StateAuth:
		content = m.viewAuth()
	case StateList:
		content = m.viewList()
	case StateDetail:
		content = m.viewDetail()
	case StateForm:
		content = m.viewForm()
	}
	return AppContainerStyle.Render(content)
}
