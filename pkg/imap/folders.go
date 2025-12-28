package imap

import (
	"sort"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
)

// FolderType represents the category of an IMAP folder
type FolderType int

const (
	// FolderTypeStandard represents standard folders (INBOX, Sent, Drafts)
	FolderTypeStandard FolderType = iota
	// FolderTypeLabel represents user-created labels/folders
	FolderTypeLabel
	// FolderTypeSystem represents system folders like [Gmail]/All Mail
	FolderTypeSystem
)

// String returns a human-readable representation of the folder type
func (ft FolderType) String() string {
	switch ft {
	case FolderTypeStandard:
		return "folder"
	case FolderTypeLabel:
		return "label"
	case FolderTypeSystem:
		return "system"
	default:
		return "unknown"
	}
}

// FolderInfo contains information about an IMAP folder/mailbox
type FolderInfo struct {
	// Name is the raw IMAP mailbox name (e.g., "[Gmail]/BridgeToBeeper")
	Name string
	// Display is the cleaned name for user presentation (e.g., "BridgeToBeeper")
	Display string
	// Type categorizes the folder
	Type FolderType
	// Icon is an emoji for display
	Icon string
	// Attributes are the raw IMAP attributes
	Attributes []imap.MailboxAttr
	// IsSelectable indicates if the folder can be selected (not \Noselect)
	IsSelectable bool
}

// TypeBracket returns the type in brackets for display (e.g., "[folder]" or "[label]")
func (f FolderInfo) TypeBracket() string {
	return "[" + f.Type.String() + "]"
}

// hasAttribute checks if a folder has a specific IMAP attribute
func hasAttribute(attrs []imap.MailboxAttr, target imap.MailboxAttr) bool {
	for _, attr := range attrs {
		if attr == target {
			return true
		}
	}
	return false
}

// cleanGmailPrefix removes Gmail-specific folder prefixes for cleaner display
func cleanGmailPrefix(name string) string {
	name = strings.TrimPrefix(name, "[Gmail]/")
	name = strings.TrimPrefix(name, "[GoogleMail]/")
	name = strings.TrimPrefix(name, "INBOX.") // Some servers use INBOX.Subfolder
	name = strings.TrimPrefix(name, "INBOX/")
	return name
}

// isHiddenFolder returns true for folders we should skip in the selection UI
func isHiddenFolder(name string, attrs []imap.MailboxAttr) bool {
	// Skip folders marked as not selectable
	if hasAttribute(attrs, imap.MailboxAttrNoSelect) {
		return true
	}

	// Skip spam and trash by default (users rarely want these)
	if hasAttribute(attrs, imap.MailboxAttrJunk) || hasAttribute(attrs, imap.MailboxAttrTrash) {
		return true
	}

	// Skip archive (usually too noisy)
	if hasAttribute(attrs, imap.MailboxAttrArchive) {
		return true
	}

	nameLower := strings.ToLower(name)

	// Skip common system folders that are rarely useful to monitor
	hiddenPatterns := []string{
		"[gmail]/spam",
		"[gmail]/trash",
		"[gmail]/bin",
		"[googlemail]/spam",
		"[googlemail]/trash",
		"junk",
		"deleted",
		"trash",
	}

	for _, pattern := range hiddenPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

// CategorizeFolders takes raw IMAP list data and returns categorized folder info
// suitable for user presentation in the folder selection UI
func CategorizeFolders(mailboxes []*imap.ListData) []FolderInfo {
	var folders []FolderInfo

	for _, mb := range mailboxes {
		// Skip hidden/system folders
		if isHiddenFolder(mb.Mailbox, mb.Attrs) {
			continue
		}

		info := FolderInfo{
			Name:         mb.Mailbox,
			Attributes:   mb.Attrs,
			IsSelectable: !hasAttribute(mb.Attrs, imap.MailboxAttrNoSelect),
		}

		// Categorize based on IMAP special-use attributes (RFC 6154)
		switch {
		case strings.EqualFold(mb.Mailbox, "INBOX"):
			info.Type = FolderTypeStandard
			info.Icon = "📥"
			info.Display = "INBOX"

		case hasAttribute(mb.Attrs, imap.MailboxAttrSent):
			info.Type = FolderTypeStandard
			info.Icon = "📤"
			info.Display = "Sent"

		case hasAttribute(mb.Attrs, imap.MailboxAttrDrafts):
			info.Type = FolderTypeStandard
			info.Icon = "📝"
			info.Display = "Drafts"

		case hasAttribute(mb.Attrs, imap.MailboxAttrAll):
			info.Type = FolderTypeSystem
			info.Icon = "📦"
			info.Display = cleanGmailPrefix(mb.Mailbox)

		case hasAttribute(mb.Attrs, imap.MailboxAttrFlagged):
			info.Type = FolderTypeSystem
			info.Icon = "⭐"
			info.Display = cleanGmailPrefix(mb.Mailbox)

		case hasAttribute(mb.Attrs, imap.MailboxAttrImportant):
			info.Type = FolderTypeSystem
			info.Icon = "❗"
			info.Display = cleanGmailPrefix(mb.Mailbox)

		default:
			// User-created folder or label
			info.Type = FolderTypeLabel
			info.Icon = "🏷️"
			info.Display = cleanGmailPrefix(mb.Mailbox)
		}

		folders = append(folders, info)
	}

	return sortFoldersByType(folders)
}

// sortFoldersByType sorts folders with standard folders first, then labels, then system
func sortFoldersByType(folders []FolderInfo) []FolderInfo {
	sort.Slice(folders, func(i, j int) bool {
		// First sort by type (Standard < Label < System)
		if folders[i].Type != folders[j].Type {
			return folders[i].Type < folders[j].Type
		}
		// Then alphabetically by display name
		return strings.ToLower(folders[i].Display) < strings.ToLower(folders[j].Display)
	})
	return folders
}

// FormatFolderList formats a list of folders for display in the Matrix chat
func FormatFolderList(folders []FolderInfo) string {
	if len(folders) == 0 {
		return "No folders found."
	}

	var sb strings.Builder
	var currentType FolderType = -1

	for i, f := range folders {
		// Add section headers when type changes
		if f.Type != currentType {
			if currentType != -1 {
				sb.WriteString("\n")
			}
			currentType = f.Type

			switch f.Type {
			case FolderTypeStandard:
				sb.WriteString("**Standard Folders:**\n")
			case FolderTypeLabel:
				sb.WriteString("**Labels/Custom Folders:**\n")
			case FolderTypeSystem:
				sb.WriteString("**System Folders:** *(usually not needed)*\n")
			}
		}

		// Format: "  1. 📥 INBOX [folder]"
		sb.WriteString("  ")
		sb.WriteString(strconv.Itoa(i + 1))
		sb.WriteString(". ")
		sb.WriteString(f.Icon)
		sb.WriteString(" ")
		sb.WriteString(f.Display)
		sb.WriteString(" ")
		sb.WriteString(f.TypeBracket())
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatSelectedFolders formats selected folders for confirmation display
func FormatSelectedFolders(folders []FolderInfo) string {
	if len(folders) == 0 {
		return "No folders selected."
	}

	var sb strings.Builder
	sb.WriteString("You selected:\n")

	for _, f := range folders {
		sb.WriteString("  • ")
		sb.WriteString(f.Icon)
		sb.WriteString(" **")
		sb.WriteString(f.Display)
		sb.WriteString("** ")
		sb.WriteString(f.TypeBracket())
		sb.WriteString("\n")
	}

	return sb.String()
}
