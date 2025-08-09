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

	"github.com/iFixRobots/emaildawg/pkg/email"
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

	// Add the Matrix user (room owner) using the special empty user ID with IsFromMe: true
	// This ensures the room is auto-joined instead of inviting the user.
	memberMap[networkid.UserID("")] = bridgev2.ChatMember{
		EventSender: bridgev2.EventSender{IsFromMe: true},
		Membership:  event.MembershipJoin,
		PowerLevel:  ptr.Ptr(9001), // Bridge bot admin level (matches createRoom overrides)
	}

	// Build a unique set of participants from the thread plus the monitored email
	participantSet := make(map[string]struct{})
	for _, emailAddr := range thread.Participants {
		addr := strings.ToLower(strings.TrimSpace(emailAddr))
		if addr != "" {
			participantSet[addr] = struct{}{}
		}
	}
	// Ensure the monitored email (derived from userLogin.ID without the "email:" prefix) is included
	monitored := strings.TrimPrefix(string(userLogin.ID), "email:")
	monitored = strings.ToLower(strings.TrimSpace(monitored))
	if monitored != "" {
		participantSet[monitored] = struct{}{}
	}

	// Add email participants (including monitored email) as read-only ghost members
	for emailAddr := range participantSet {
		ghostID := rm.emailToGhostID(emailAddr)
		memberMap[ghostID] = bridgev2.ChatMember{
			EventSender: bridgev2.EventSender{Sender: ghostID},
			Membership:  event.MembershipJoin,
			PowerLevel:  ptr.Ptr(0), // Read-only level
		}
	}

	// Set up power levels to make room read-only for email participants
	powerLevels := &bridgev2.PowerLevelOverrides{
		// Keep state changes restricted to the bridge account. Block user-sent messages/reactions/redactions.
		// The bridge bot has a high power level and can still post bridged content.
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
			event.EventMessage:    101,
			event.EventReaction:   101,
			event.EventRedaction:  101,
		},
	}

	// Also include an explicit member entry for the Matrix user to ensure initial membership at creation
	initialMembers := []bridgev2.ChatMember{
		{
			EventSender: bridgev2.EventSender{IsFromMe: true},
			Membership:  event.MembershipJoin,
			PowerLevel:  ptr.Ptr(9001),
		},
	}
	chatInfo := &bridgev2.ChatInfo{
		Name:  ptr.Ptr(roomName),
		Topic: ptr.Ptr(roomTopic),
		Type:  ptr.Ptr(database.RoomTypeDefault),
		Members: &bridgev2.ChatMemberList{
			IsFull:           true,
			TotalMemberCount: len(memberMap),
			Members:          initialMembers,
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



// Note: UpdateRoomParticipants and SendEmailMessage will be handled by the EmailConnector
// using the bridgev2 framework's built-in room and message management capabilities.
// The RoomManager now focuses on providing ChatInfo for room creation.
