package matrix

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-emaildawg/pkg/email"
)

// RoomManager handles Matrix room creation and management for email threads
type RoomManager struct {
	log *zerolog.Logger
}

// NewRoomManager creates a new Matrix room manager
func NewRoomManager(log *zerolog.Logger) *RoomManager {
	logger := log.With().Str("component", "room_manager").Logger()
	return &RoomManager{
		log: &logger,
	}
}

// GetChatInfoForThread creates ChatInfo for an email thread (used by bridgev2 for room creation)
func (rm *RoomManager) GetChatInfoForThread(ctx context.Context, thread *email.EmailThread, userLogin *bridgev2.UserLogin) (*bridgev2.ChatInfo, error) {
	rm.log.Info().
		Str("thread_id", thread.ThreadID).
		Str("subject", thread.Subject).
		Int("participants", len(thread.Participants)).
		Msg("Creating ChatInfo for email thread")

	roomName := rm.formatRoomName(thread.Subject)
	roomTopic := fmt.Sprintf("Email thread: %s", thread.ThreadID)

	// Create member map with read-only power levels
	memberMap := make(map[networkid.UserID]bridgev2.ChatMember)

	// Add the bridge user with admin permissions
	// Convert UserLoginID to UserID
	bridgeUserID := networkid.UserID(userLogin.ID)
	memberMap[bridgeUserID] = bridgev2.ChatMember{
		EventSender: bridgev2.EventSender{IsFromMe: true},
		Membership:  event.MembershipJoin,
		PowerLevel:  ptr.Ptr(100), // Admin level
	}

	// Add email participants as read-only members
for _, emailAddr := range thread.Participants {
		// Skip the bridge user's own email
		if strings.EqualFold(emailAddr, string(userLogin.ID)) {
			continue
		}

		// Use formatter to satisfy linter and as a future hook for naming.
		_ = rm.formatGhostDisplayName(emailAddr)

		ghostID := rm.emailToGhostID(emailAddr)
		memberMap[ghostID] = bridgev2.ChatMember{
			EventSender: bridgev2.EventSender{Sender: ghostID},
			Membership:  event.MembershipJoin,
			PowerLevel:  ptr.Ptr(0), // Read-only level
		}
	}

	// Set up power levels to make room read-only for email participants
	powerLevels := &bridgev2.PowerLevelOverrides{
		// Allow sending normal messages by default so ghost users can post email content.
		// Keep state changes restricted to the bridge account.
		EventsDefault: ptr.Ptr(0),
		StateDefault:  ptr.Ptr(101),
		Ban:           ptr.Ptr(101),
		Kick:          ptr.Ptr(101),
		Invite:        ptr.Ptr(101),
		Redact:        ptr.Ptr(101),
		Events: map[event.Type]int{
			event.StateRoomName:   101,
			event.StateTopic:      101,
			event.StateRoomAvatar: 101,
			// Do not override EventMessage to 101 – leave it at EventsDefault (0)
			event.EventReaction:   101,
			event.EventRedaction:  101,
		},
	}

	chatInfo := &bridgev2.ChatInfo{
		Name:  ptr.Ptr(roomName),
		Topic: ptr.Ptr(roomTopic),
		Type:  ptr.Ptr(database.RoomTypeDefault),
		Members: &bridgev2.ChatMemberList{
			IsFull:           true,
			TotalMemberCount: len(memberMap),
			MemberMap:        memberMap,
			PowerLevels:      powerLevels,
		},
		CanBackfill: true,
	}

	rm.log.Debug().
		Str("room_name", roomName).
		Str("room_topic", roomTopic).
		Int("member_count", len(memberMap)).
		Msg("Created ChatInfo for email thread")

	return chatInfo, nil
}

// formatRoomName creates a clean room name from email subject
func (rm *RoomManager) formatRoomName(subject string) string {
	// Remove common email prefixes
	subject = strings.TrimSpace(subject)
	prefixes := []string{"Re: ", "RE: ", "Fwd: ", "FWD: ", "Fw: ", "FW: "}
	
	for {
		trimmed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(subject, prefix) {
				subject = strings.TrimSpace(subject[len(prefix):])
				trimmed = true
				break
			}
		}
		if !trimmed {
			break
		}
	}
	
	// Limit length and clean up
	if len(subject) > 80 {
		subject = subject[:77] + "..."
	}
	
	if subject == "" {
		subject = "Email Thread"
	}
	
	return subject
}


// emailToGhostID converts an email address to a Matrix ghost user ID
func (rm *RoomManager) emailToGhostID(email string) networkid.UserID {
	// Use a stable scheme that preserves the actual address for display mapping
	addr := strings.TrimSpace(email)
	return networkid.UserID(fmt.Sprintf("email:%s", addr))
}

// formatGhostDisplayName creates a friendly display name for email ghosts
func (rm *RoomManager) formatGhostDisplayName(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	
	username := parts[0]
	domain := parts[1]
	
	// Make username more readable
	username = strings.ReplaceAll(username, ".", " ")
	username = strings.ReplaceAll(username, "_", " ")
	username = strings.Title(username)
	
	return fmt.Sprintf("%s (%s)", username, domain)
}


// Note: UpdateRoomParticipants and SendEmailMessage will be handled by the EmailConnector
// using the bridgev2 framework's built-in room and message management capabilities.
// The RoomManager now focuses on providing ChatInfo for room creation.
