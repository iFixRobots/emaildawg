package connector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/iFixRobots/emaildawg/pkg/imap"
)

// FolderSelectionResult represents the result of validating folder selection input
type FolderSelectionResult struct {
	Valid         bool
	SelectedNames []string          // Raw IMAP folder names for database storage
	SelectedInfos []imap.FolderInfo // Full folder info for display
	ErrorMessage  string
	IsCancel      bool
	IsDefault     bool
}

// ValidateFolderSelection parses and validates user input for folder selection
func ValidateFolderSelection(input string, availableFolders []imap.FolderInfo) FolderSelectionResult {
	input = strings.TrimSpace(input)

	// Handle empty input
	if input == "" {
		return FolderSelectionResult{
			Valid:        false,
			ErrorMessage: "Please enter a folder number, or type `default` for INBOX, or `cancel` to abort.",
		}
	}

	inputLower := strings.ToLower(input)

	// Handle special keywords
	if inputLower == "cancel" {
		return FolderSelectionResult{
			Valid:    false,
			IsCancel: true,
		}
	}

	if inputLower == "default" {
		// Find INBOX in the available folders
		for _, f := range availableFolders {
			if strings.EqualFold(f.Display, "INBOX") || strings.EqualFold(f.Name, "INBOX") {
				return FolderSelectionResult{
					Valid:         true,
					IsDefault:     true,
					SelectedNames: []string{f.Name},
					SelectedInfos: []imap.FolderInfo{f},
				}
			}
		}
		// INBOX not found, use literal INBOX as fallback
		return FolderSelectionResult{
			Valid:         true,
			IsDefault:     true,
			SelectedNames: []string{"INBOX"},
			SelectedInfos: []imap.FolderInfo{{
				Name:    "INBOX",
				Display: "INBOX",
				Icon:    "📥",
				Type:    imap.FolderTypeStandard,
			}},
		}
	}

	// Parse comma-separated numbers
	parts := strings.Split(input, ",")
	var selectedIndices []int
	seen := make(map[int]bool)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		num, err := strconv.Atoi(part)
		if err != nil {
			return FolderSelectionResult{
				Valid:        false,
				ErrorMessage: fmt.Sprintf("❌ Invalid input: `%s` is not a number.\n\nPlease enter folder numbers (e.g., `1` or `1,3,5`), `default` for INBOX, or `cancel`.", part),
			}
		}

		if num < 1 || num > len(availableFolders) {
			return FolderSelectionResult{
				Valid:        false,
				ErrorMessage: fmt.Sprintf("❌ Invalid input: `%d` is out of range.\n\nPlease choose a number between 1 and %d.", num, len(availableFolders)),
			}
		}

		// Deduplicate
		idx := num - 1 // Convert to 0-indexed
		if !seen[idx] {
			seen[idx] = true
			selectedIndices = append(selectedIndices, idx)
		}
	}

	if len(selectedIndices) == 0 {
		return FolderSelectionResult{
			Valid:        false,
			ErrorMessage: "Please enter at least one folder number.",
		}
	}

	// Collect selected folders
	var names []string
	var infos []imap.FolderInfo

	for _, idx := range selectedIndices {
		names = append(names, availableFolders[idx].Name)
		infos = append(infos, availableFolders[idx])
	}

	return FolderSelectionResult{
		Valid:         true,
		SelectedNames: names,
		SelectedInfos: infos,
	}
}

// ValidateConfirmation validates yes/no confirmation input
// Returns: confirmed, goBack, errorMsg
func ValidateConfirmation(input string) (confirmed bool, goBack bool, errorMsg string) {
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "yes", "y":
		return true, false, ""
	case "no", "n":
		return false, true, ""
	default:
		return false, false, "❌ Invalid input. Please type `yes` or `no`."
	}
}

// BuildFolderSelectionPrompt creates the folder selection message
func BuildFolderSelectionPrompt(folders []imap.FolderInfo, providerName string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("✅ Connected to **%s** successfully!\n\n", providerName))
	sb.WriteString("📁 **Choose which folders or labels to monitor:**\n\n")
	sb.WriteString(imap.FormatFolderList(folders))
	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("Reply with folder number(s) separated by commas.\n")
	sb.WriteString("**Examples:** `1` for INBOX only, or `1,3` for INBOX + another folder\n")
	sb.WriteString("Type `default` to monitor INBOX (recommended for most users)\n")
	sb.WriteString("Type `cancel` to abort setup")

	return sb.String()
}

// BuildConfirmationPrompt creates the confirmation message
func BuildConfirmationPrompt(folders []imap.FolderInfo) string {
	var sb strings.Builder

	sb.WriteString("📋 **Please confirm your selection:**\n\n")
	sb.WriteString(imap.FormatSelectedFolders(folders))
	sb.WriteString("\n")

	if len(folders) == 1 {
		sb.WriteString("The bridge will only show emails from this folder in Beeper.\n")
	} else {
		sb.WriteString("The bridge will monitor all selected folders in Beeper.\n")
	}

	// Add tip for label-based filtering
	hasLabel := false
	for _, f := range folders {
		if f.Type == imap.FolderTypeLabel {
			hasLabel = true
			break
		}
	}
	if hasLabel {
		sb.WriteString("\n💡 **Tip:** Add the label to any email thread in Gmail to see it in Beeper.\n")
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("Type `yes` to confirm or `no` to go back.")

	return sb.String()
}
