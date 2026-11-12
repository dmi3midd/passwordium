package ui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

const (
	formFieldTitle = iota
	formFieldUsername
	formFieldPassword
	formFieldURL
	formFieldNotes
	formFieldCount
)

const clipboardClearDuration = 15 * time.Second

type clipboardClearMsg struct {
	seq    int
	secret string
}

type clipboardCountdownMsg struct {
	seq int
}

// Model is the main Bubble Tea finite state machine model for Passwordium.
type Model struct {
	state     SessionState
	vaultPath string
	vault     *vault.Vault

	width  int
	height int

	// StateAuth fields
	isNewVault    bool
	authInputs    []textinput.Model
	authFocusIdx  int
	authErr       string

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

	authCount := 1
	if isNew {
		authCount = 2
	}
	authInputs := make([]textinput.Model, authCount)
	for i := 0; i < authCount; i++ {
		ti := textinput.New()
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
		ti.CharLimit = 256
		ti.Width = 42
		if i == 0 {
			ti.Placeholder = "Введіть майстер-пароль..."
			ti.Focus()
		} else {
			ti.Placeholder = "Підтвердіть майстер-пароль..."
		}
		authInputs[i] = ti
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(colorPrimary).
		BorderLeftForeground(colorPrimary)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(colorSecondary).
		BorderLeftForeground(colorPrimary)

	l := list.New([]list.Item{}, delegate, 80, 20)
	l.Title = "🔐 Passwordium — Сховище паролів"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false) // Custom status bar rendered at the bottom

	return Model{
		state:      StateAuth,
		vaultPath:  vaultPath,
		isNewVault: isNew,
		authInputs: authInputs,
		list:       l,
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
			m.statusMsg = "🧹 Буфер обміну автоматично очищено (15с минуло)"
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

func (m Model) updateAuth(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit

		case "tab", "shift+tab", "up", "down":
			if !m.isNewVault {
				return m, nil
			}
			if msg.String() == "tab" || msg.String() == "down" {
				m.authFocusIdx = (m.authFocusIdx + 1) % len(m.authInputs)
			} else {
				m.authFocusIdx = (m.authFocusIdx - 1 + len(m.authInputs)) % len(m.authInputs)
			}
			cmds := make([]tea.Cmd, len(m.authInputs))
			for i := range m.authInputs {
				if i == m.authFocusIdx {
					cmds[i] = m.authInputs[i].Focus()
				} else {
					m.authInputs[i].Blur()
				}
			}
			return m, tea.Batch(cmds...)

		case "enter":
			if m.isNewVault && m.authFocusIdx == 0 {
				m.authFocusIdx = 1
				m.authInputs[0].Blur()
				return m, m.authInputs[1].Focus()
			}
			return m.submitAuth()
		}
	}

	var cmd tea.Cmd
	m.authInputs[m.authFocusIdx], cmd = m.authInputs[m.authFocusIdx].Update(msg)
	return m, cmd
}

func (m Model) submitAuth() (tea.Model, tea.Cmd) {
	pw := m.authInputs[0].Value()
	if len(pw) == 0 {
		m.authErr = "Майстер-пароль не може бути порожнім"
		return m, nil
	}

	if m.isNewVault {
		confirm := m.authInputs[1].Value()
		if pw != confirm {
			m.authErr = "Паролі не співпадають. Спробуйте ще раз"
			m.authInputs[1].SetValue("")
			return m, nil
		}

		pwBytes := []byte(pw)
		v, err := vault.Create(m.vaultPath, pwBytes)
		vault.ZeroBytes(pwBytes)
		if err != nil {
			m.authErr = fmt.Sprintf("Помилка створення сховища: %v", err)
			return m, nil
		}

		m.vault = v
		m.clearAuthInputs()
		m.refreshListItems("")
		m.state = StateList
		m.statusMsg = "✨ Нове захищене сховище успішно створено"
		m.statusIsErr = false
		return m, nil
	}

	pwBytes := []byte(pw)
	v, err := vault.Open(m.vaultPath, pwBytes)
	vault.ZeroBytes(pwBytes)
	if err != nil {
		m.authInputs[0].SetValue("")
		if errors.Is(err, vault.ErrInvalidMasterPassword) {
			m.authErr = "❌ Невірний майстер-пароль (помилка автентифікації Poly1305)"
		} else {
			m.authErr = fmt.Sprintf("Помилка відкриття сховища: %v", err)
		}
		return m, m.authInputs[0].Focus()
	}

	m.vault = v
	m.clearAuthInputs()
	m.refreshListItems("")
	m.state = StateList
	m.statusMsg = "🔓 Сховище успішно розблоковано"
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
				m.statusMsg = "Немає вибраного запису для копіювання"
				m.statusIsErr = true
				return m, nil
			}
			return m.copyEntryPassword(item.entry)

		case "d":
			item, ok := m.list.SelectedItem().(entryItem)
			if !ok || item.entry == nil {
				return m, nil
			}
			title := item.entry.Title
			if err := m.vault.DeleteEntry(item.entry.Id); err != nil {
				m.statusMsg = fmt.Sprintf("Помилка видалення: %v", err)
				m.statusIsErr = true
				return m, nil
			}
			m.refreshListItems("")
			m.statusMsg = fmt.Sprintf("🗑️ Запис «%s» видалено", title)
			m.statusIsErr = false
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

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

func (m Model) updateDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.selectedEntry == nil {
		m.state = StateList
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "backspace":
			m.cleanupSensitiveState()
			m.state = StateList
			return m, nil

		case "q":
			m.cleanupSensitiveState()
			if m.vault != nil {
				m.vault.Close()
			}
			return m, tea.Quit

		case "v":
			if m.passwordRevealed {
				m.passwordRevealed = false
				m.revealedPassword = ""
				m.statusMsg = "🙈 Пароль приховано"
				m.statusIsErr = false
				return m, nil
			}
			pw, err := m.vault.DecryptPassword(m.selectedEntry)
			if err != nil {
				m.statusMsg = fmt.Sprintf("Помилка розшифрування пароля: %v", err)
				m.statusIsErr = true
				return m, nil
			}
			m.revealedPassword = pw
			m.passwordRevealed = true
			m.statusMsg = "👁️ Пароль тимчасово розшифровано через entryKey"
			m.statusIsErr = false
			return m, nil

		case "c":
			return m.copyEntryPassword(m.selectedEntry)

		case "e":
			entry := m.selectedEntry
			m.cleanupSensitiveState()
			cmd := m.initForm(entry)
			m.state = StateForm
			return m, cmd

		case "d":
			id := m.selectedEntry.Id
			title := m.selectedEntry.Title
			m.cleanupSensitiveState()
			if err := m.vault.DeleteEntry(id); err != nil {
				m.statusMsg = fmt.Sprintf("Помилка видалення: %v", err)
				m.statusIsErr = true
				return m, nil
			}
			m.refreshListItems("")
			m.state = StateList
			m.statusMsg = fmt.Sprintf("🗑️ Запис «%s» видалено", title)
			m.statusIsErr = false
			return m, nil
		}
	}

	return m, nil
}

func (m Model) copyEntryPassword(entry *pb.VaultEntry) (tea.Model, tea.Cmd) {
	pw, err := m.vault.DecryptPassword(entry)
	if err != nil {
		m.statusMsg = fmt.Sprintf("Помилка розшифрування пароля: %v", err)
		m.statusIsErr = true
		return m, nil
	}

	if err := clipboard.Copy(pw); err != nil {
		m.statusMsg = fmt.Sprintf("Не вдалося скопіювати в буфер обміну: %v", err)
		m.statusIsErr = true
		return m, nil
	}

	m.clipboardSeq++
	seq := m.clipboardSeq
	m.clipboardCountdown = int(clipboardClearDuration.Seconds())
	m.statusMsg = fmt.Sprintf("📋 Пароль для «%s» скопійовано в буфер обміну", entry.Title)
	m.statusIsErr = false

	clearCmd := tea.Tick(clipboardClearDuration, func(t time.Time) tea.Msg {
		return clipboardClearMsg{seq: seq, secret: pw}
	})
	countdownCmd := tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return clipboardCountdownMsg{seq: seq}
	})

	return m, tea.Batch(clearCmd, countdownCmd)
}

func (m *Model) initForm(entry *pb.VaultEntry) tea.Cmd {
	inputs := make([]textinput.Model, formFieldCount)

	placeholders := []string{
		"Наприклад: GitHub, Gmail, AWS...",
		"username або email@example.com",
		"Натисніть Ctrl+G для автогенерації криптостійкого пароля",
		"https://...",
		"Додаткові нотатки, резервні коди, PIN...",
	}

	for i := 0; i < formFieldCount; i++ {
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
				m.formErr = fmt.Sprintf("Помилка генерації пароля: %v", err)
				return m, nil
			}
			m.formInputs[formFieldPassword].SetValue(generated)
			m.formInputs[formFieldPassword].CursorEnd()
			m.statusMsg = "🎲 Згенеровано криптостійкий пароль (20 символів)"
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
			for i := 0; i < formFieldCount; i++ {
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
		m.formErr = "Поле «Назва сервісу (Title)» є обов'язковим"
		m.formInputs[m.formFocusIdx].Blur()
		m.formFocusIdx = formFieldTitle
		return m, m.formInputs[formFieldTitle].Focus()
	}
	if password == "" {
		m.formErr = "Поле «Пароль (Password)» не може бути порожнім (натисніть Ctrl+G для генерації)"
		m.formInputs[m.formFocusIdx].Blur()
		m.formFocusIdx = formFieldPassword
		return m, m.formInputs[formFieldPassword].Focus()
	}

	if m.isEditing {
		updated, err := m.vault.UpdateEntry(m.editingEntryID, title, username, password, url, notes)
		if err != nil {
			m.formErr = fmt.Sprintf("Помилка збереження: %v", err)
			return m, nil
		}
		m.clearFormInputs()
		m.refreshListItems(updated.Id)
		m.openDetail(updated)
		m.statusMsg = fmt.Sprintf("✅ Запис «%s» оновлено та атомарно збережено", updated.Title)
		m.statusIsErr = false
		return m, nil
	}

	created, err := m.vault.AddEntry(title, username, password, url, notes)
	if err != nil {
		m.formErr = fmt.Sprintf("Помилка створення запису: %v", err)
		return m, nil
	}
	m.clearFormInputs()
	m.refreshListItems(created.Id)
	m.openDetail(created)
	m.statusMsg = fmt.Sprintf("✨ Запис «%s» створено та зашифровано", created.Title)
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

func (m *Model) cleanupSensitiveState() {
	m.passwordRevealed = false
	m.revealedPassword = ""
	m.decryptedNotes = ""
	m.selectedEntry = nil
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

func (m Model) viewAuth() string {
	var b strings.Builder

	header := HeaderBadgeStyle.Render("🔐 PASSWORDIUM")
	b.WriteString(header + "\n\n")

	if m.isNewVault {
		b.WriteString(ValueStyle.Bold(true).Render("Ініціалізація нового сховища") + "\n")
		b.WriteString(SubHeaderStyle.Render(fmt.Sprintf("Файл %s не знайдено. Створіть майстер-пароль (Argon2id + XChaCha20-Poly1305).", m.vaultPath)) + "\n\n")

		lbl1 := LabelStyle.Render("Майстер-пароль:")
		if m.authFocusIdx == 0 {
			lbl1 = FocusedLabelStyle.Render("▸ Майстер-пароль:")
		}
		b.WriteString(lbl1 + " " + m.authInputs[0].View() + "\n\n")

		lbl2 := LabelStyle.Render("Підтвердження:")
		if m.authFocusIdx == 1 {
			lbl2 = FocusedLabelStyle.Render("▸ Підтвердження:")
		}
		b.WriteString(lbl2 + " " + m.authInputs[1].View() + "\n")
	} else {
		b.WriteString(ValueStyle.Bold(true).Render("Розблокування сховища") + "\n")
		b.WriteString(SubHeaderStyle.Render(fmt.Sprintf("Сховище: %s", m.vaultPath)) + "\n\n")

		lbl := FocusedLabelStyle.Render("▸ Майстер-пароль:")
		b.WriteString(lbl + " " + m.authInputs[0].View() + "\n")
	}

	if m.authErr != "" {
		b.WriteString("\n" + ErrorStyle.Render(m.authErr) + "\n")
	}

	hints := []string{
		renderKeyHint("enter", "продовжити"),
	}
	if m.isNewVault {
		hints = append(hints, renderKeyHint("tab", "перемкнути поле"))
	}
	hints = append(hints, renderKeyHint("esc/ctrl+c", "вихід"))

	card := CardStyle.Width(min(74, max(54, m.width-8))).Render(b.String())
	return lipgloss.JoinVertical(lipgloss.Left, card, StatusBarStyle.Render(strings.Join(hints, "   ")))
}

func (m Model) viewList() string {
	hints := strings.Join([]string{
		renderKeyHint("n", "новий запис"),
		renderKeyHint("enter", "перегляд"),
		renderKeyHint("c", "копіювати пароль"),
		renderKeyHint("d", "видалити"),
		renderKeyHint("/", "пошук"),
		renderKeyHint("q", "вихід"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		m.list.View(),
		m.renderStatusFooter(hints),
	)
}

func (m Model) viewDetail() string {
	if m.selectedEntry == nil {
		return ""
	}
	e := m.selectedEntry

	var b strings.Builder
	b.WriteString(HeaderBadgeStyle.Render("📄 ПЕРЕГЛЯД ЗАПИСУ") + "  " + MutedStyle.Render("ID: "+e.Id) + "\n\n")

	b.WriteString(LabelStyle.Render("Сервіс:") + " " + ValueStyle.Bold(true).Render(nonEmpty(e.Title, "—")) + "\n")
	b.WriteString(LabelStyle.Render("Користувач:") + " " + ValueStyle.Render(nonEmpty(e.Username, "—")) + "\n")

	var pwRender string
	if m.passwordRevealed {
		pwRender = RevealedPasswordStyle.Render(m.revealedPassword) + " " + MutedStyle.Render("(розшифровано через entryKey)")
	} else {
		pwRender = MaskedPasswordStyle.Render("••••••••••••") + " " + MutedStyle.Render("(зашифровано в RAM, натисніть 'v' для показу)")
	}
	b.WriteString(LabelStyle.Render("Пароль:") + " " + pwRender + "\n")

	b.WriteString(LabelStyle.Render("URL:") + " " + ValueStyle.Render(nonEmpty(e.Url, "—")) + "\n")
	b.WriteString(LabelStyle.Render("Нотатки:") + " " + ValueStyle.Render(nonEmpty(m.decryptedNotes, "—")) + "\n\n")

	createdStr := formatUnixTime(e.CreatedAt)
	updatedStr := formatUnixTime(e.UpdatedAt)
	b.WriteString(MutedStyle.Render(fmt.Sprintf("Створено: %s   |   Оновлено: %s", createdStr, updatedStr)))

	card := CardStyle.Width(min(84, max(58, m.width-8))).Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("v", "показати/сховати пароль"),
		renderKeyHint("c", "копіювати пароль (15с)"),
		renderKeyHint("e", "редагувати"),
		renderKeyHint("d", "видалити"),
		renderKeyHint("esc", "назад до списку"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
}

func (m Model) viewForm() string {
	var b strings.Builder

	if m.isEditing {
		b.WriteString(HeaderBadgeStyle.Render("✏️ РЕДАГУВАННЯ ЗАПИСУ") + "\n\n")
	} else {
		b.WriteString(HeaderBadgeStyle.Render("➕ НОВИЙ ЗАПИС") + "\n\n")
	}

	labels := []string{
		"Сервіс (Title):",
		"Користувач:",
		"Пароль:",
		"URL:",
		"Нотатки:",
	}

	for i := 0; i < formFieldCount; i++ {
		lbl := LabelStyle.Render(labels[i])
		if m.formFocusIdx == i {
			lbl = FocusedLabelStyle.Render("▸ " + labels[i])
		}
		b.WriteString(lbl + " " + m.formInputs[i].View())
		if i == formFieldPassword {
			b.WriteString("  " + MutedStyle.Render("[Ctrl+G: згенерувати | Ctrl+R: показати]"))
		}
		b.WriteString("\n\n")
	}

	if m.formErr != "" {
		b.WriteString(ErrorStyle.Render("⚠️ "+m.formErr) + "\n")
	}

	card := CardStyle.Width(min(92, max(64, m.width-8))).Render(b.String())

	hints := strings.Join([]string{
		renderKeyHint("tab/shift+tab", "навігація"),
		renderKeyHint("ctrl+g", "згенерувати пароль"),
		renderKeyHint("ctrl+r", "показати пароль"),
		renderKeyHint("ctrl+s/enter", "зберегти"),
		renderKeyHint("esc", "скасувати"),
	}, "   ")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		card,
		m.renderStatusFooter(hints),
	)
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
			timerBadge := NoticeStyle.Render(fmt.Sprintf("⏱ Очищення буфера через %dс", m.clipboardCountdown))
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

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func formatUnixTime(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04:05")
}

