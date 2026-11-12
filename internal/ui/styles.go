package ui

import "github.com/charmbracelet/lipgloss"

var (
	colorPrimary   = lipgloss.AdaptiveColor{Light: "#5A32EA", Dark: "#8B5CF6"}
	colorSecondary = lipgloss.AdaptiveColor{Light: "#0D9488", Dark: "#2DD4BF"}
	colorAccent    = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#FBBF24"}
	colorDanger    = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#F87171"}
	colorSuccess   = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#4ADE80"}
	colorMuted     = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"}
	colorSurface   = lipgloss.AdaptiveColor{Light: "#F3F4F6", Dark: "#1F2937"}
	colorText      = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#F9FAFB"}

	AppContainerStyle = lipgloss.NewStyle().
				Padding(1, 2)

	HeaderBadgeStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(colorPrimary).
				Padding(0, 1)

	SubHeaderStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)

	CardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(1, 2)

	LabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorSecondary).
			Width(16)

	FocusedLabelStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorPrimary).
				Width(16)

	ValueStyle = lipgloss.NewStyle().
			Foreground(colorText)

	MaskedPasswordStyle = lipgloss.NewStyle().
				Foreground(colorAccent).
				Bold(true)

	RevealedPasswordStyle = lipgloss.NewStyle().
				Foreground(colorSuccess).
				Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(colorDanger).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(colorSuccess).
			Bold(true)

	NoticeStyle = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	MutedStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	StatusBarStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(colorMuted).
			PaddingTop(1).
			MarginTop(1)

	KeyHelpStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary)

	DescHelpStyle = lipgloss.NewStyle().
			Foreground(colorMuted)
)

func renderKeyHint(key, desc string) string {
	return KeyHelpStyle.Render(key) + " " + DescHelpStyle.Render(desc)
}

