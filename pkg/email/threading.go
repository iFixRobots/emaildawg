package email

import (
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EmailAttachment represents an email attachment (forward declaration)
// The actual struct is defined in processor.go to avoid circular imports
type EmailAttachment struct {
	Filename    string
	ContentType string
	Size        int64
	Data        []byte
	// Inline-related metadata
	ContentID       string // normalized: no <>, lowercase
	ContentLocation string // as in MIME header, normalized path-like string
	Disposition     string // inline or attachment
	IsInline        bool   // derived: Disposition == inline or referenced in HTML
}

// EmailThread represents an email conversation thread
type EmailThread struct {
	ThreadID     string   // Message-ID of the first email in thread
	Subject      string   // Email subject line
	Participants []string // List of email addresses currently active in thread
	MessageID    string   // Current message ID
	InReplyTo    string   // Message this is replying to (for threading)
	References   []string // Full thread chain

	// Participant change tracking for Matrix room updates
	AddedParticipants   []string // Participants added in the latest email
	RemovedParticipants []string // Participants removed in the latest email

	// Cache management
	LastAccessed time.Time // For TTL cleanup
}

// ClearParticipantChanges clears the participant change tracking after processing
func (thread *EmailThread) ClearParticipantChanges() {
	thread.AddedParticipants = nil
	thread.RemovedParticipants = nil
}

// ThreadManager handles email threading detection and management

// ThreadMetadataResolver allows consulting external metadata to resolve a thread ID
// from a message ID for a specific receiver (e.g., bridgev2 metadata).
// Return (threadID, true) if found; otherwise return ("", false).
type ThreadMetadataResolver interface {
	ResolveThreadID(receiver, messageID string) (string, bool)
}

const (
	maxCachedThreads = 10000          // Maximum number of threads to cache
	threadCacheTTL   = 24 * time.Hour // TTL for cached threads
)

type ThreadManager struct {
	// Cache of known threads with size and TTL limits to prevent memory leaks
	knownThreads map[string]*EmailThread // key: receiver|threadID
	// Performance optimization: message ID -> thread lookup index
	messageIDIndex map[string]*EmailThread // key: messageID, value: thread containing that message
	mu             sync.RWMutex
	resolver       ThreadMetadataResolver // optional external resolver
	lastCleanup    time.Time              // Last time we ran cache cleanup
}

// NewThreadManager creates a new email thread manager
func NewThreadManager(resolver ThreadMetadataResolver) *ThreadManager {
	return &ThreadManager{
		knownThreads:   make(map[string]*EmailThread),
		messageIDIndex: make(map[string]*EmailThread),
		resolver:       resolver,
		lastCleanup:    time.Now(),
	}
}

// GetThreadByID returns a thread by its ThreadID if known
func (tm *ThreadManager) GetThreadByID(receiver, threadID string) *EmailThread {
	key := receiver + "|" + threadID
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Clean up expired threads periodically
	tm.cleanupExpiredThreadsIfNeeded()

	if th, ok := tm.knownThreads[key]; ok {
		th.LastAccessed = time.Now()
		return th
	}
	// Fallback to legacy key without receiver for backward compatibility
	if th, ok := tm.knownThreads[threadID]; ok {
		th.LastAccessed = time.Now()
		return th
	}
	return nil
}

func (tm *ThreadManager) getCachedThread(receiver, threadID string) *EmailThread {
	return tm.GetThreadByID(receiver, threadID)
}

func (tm *ThreadManager) cacheThread(receiver string, thread *EmailThread) {
	if thread == nil || thread.ThreadID == "" {
		return
	}
	key := receiver + "|" + thread.ThreadID
	tm.mu.Lock()
	defer tm.mu.Unlock()

	thread.LastAccessed = time.Now()
	tm.knownThreads[key] = thread

	// Update message ID index for fast lookups
	tm.updateMessageIDIndex(thread)

	// Enforce cache size limit
	if len(tm.knownThreads) > maxCachedThreads {
		tm.evictOldestThreads(maxCachedThreads / 4) // Remove 25% when limit exceeded
	}
}

// updateMessageIDIndex maintains the message ID -> thread index
func (tm *ThreadManager) updateMessageIDIndex(thread *EmailThread) {
	// Index the thread ID itself
	if thread.ThreadID != "" {
		tm.messageIDIndex[thread.ThreadID] = thread
	}
	// Index all message IDs in the references chain
	for _, ref := range thread.References {
		if ref != "" {
			tm.messageIDIndex[ref] = thread
		}
	}
	// Index the current message ID if different from thread ID
	if thread.MessageID != "" && thread.MessageID != thread.ThreadID {
		tm.messageIDIndex[thread.MessageID] = thread
	}
}

// CacheForReceiver exposes caching to callers (e.g., processor) to store a thread under a receiver scope.
func (tm *ThreadManager) CacheForReceiver(receiver string, thread *EmailThread) {
	tm.cacheThread(receiver, thread)
}

// ParsedEmail represents a parsed email message
type ParsedEmail struct {
	MessageID   string
	InReplyTo   string
	References  []string
	Subject     string
	From        string
	To          []string
	Cc          []string
	Bcc         []string
	Date        time.Time
	TextContent string
	HTMLContent string
	Attachments []*EmailAttachment
}

// isForwardedMessage checks if an email is a forward based on subject and content
func isForwardedMessage(email *ParsedEmail) bool {
	if email == nil {
		return false
	}

	// Check subject for forward prefixes
	subject := strings.ToLower(strings.TrimSpace(email.Subject))
	forwardPrefixes := []string{"fwd:", "fw:", "forward:"}
	for _, prefix := range forwardPrefixes {
		if strings.HasPrefix(subject, prefix) {
			return true
		}
	}

	// Check body content for forward markers (reuse existing logic)
	content := strings.ToLower(email.TextContent + " " + email.HTMLContent)
	forwardMarkers := []string{
		"-----original message-----",
		"begin forwarded message",
		"forwarded message",
		"---------- forwarded message ----------",
	}
	for _, marker := range forwardMarkers {
		if strings.Contains(content, marker) {
			return true
		}
	}

	return false
}

// DetermineThread analyzes an email and determines which thread it belongs to
func (tm *ThreadManager) DetermineThread(receiver string, email *ParsedEmail) *EmailThread {
	// Forwarded emails always create new threads to avoid contaminating existing conversations
	if isForwardedMessage(email) {
		return tm.createNewThread(email)
	}
	// Step 0a: Consult external resolver if available
	if tm.resolver != nil {
		if email.InReplyTo != "" {
			if tid, ok := tm.resolver.ResolveThreadID(receiver, email.InReplyTo); ok && tid != "" {
				if thread := tm.getCachedThread(receiver, tid); thread != nil {
					return tm.addToExistingThread(thread, email)
				}
				thread := &EmailThread{ThreadID: tid, Subject: email.Subject}
				return tm.addToExistingThread(thread, email)
			}
		}
		for _, refID := range email.References {
			if tid, ok := tm.resolver.ResolveThreadID(receiver, refID); ok && tid != "" {
				if thread := tm.getCachedThread(receiver, tid); thread != nil {
					return tm.addToExistingThread(thread, email)
				}
				thread := &EmailThread{ThreadID: tid, Subject: email.Subject}
				return tm.addToExistingThread(thread, email)
			}
		}
	}

	// Step 1: Check if this is a reply based on In-Reply-To header (in-memory)
	if email.InReplyTo != "" {
		if thread := tm.findThreadByMessageID(email.InReplyTo); thread != nil {
			return tm.addToExistingThread(thread, email)
		}
	}

	// Step 2: Check References header for thread chain
	if len(email.References) > 0 {
		// Check each reference (starting from the oldest)
		for _, refID := range email.References {
			if thread := tm.findThreadByMessageID(refID); thread != nil {
				return tm.addToExistingThread(thread, email)
			}
		}
	}

	// Step 3: This is a new thread (subject-based threading removed to prevent false positives)
	return tm.createNewThread(email)
}

// findThreadByMessageID finds an existing thread that contains a specific Message-ID
func (tm *ThreadManager) findThreadByMessageID(messageID string) *EmailThread {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Use O(1) index lookup instead of O(n) linear search
	if thread, exists := tm.messageIDIndex[messageID]; exists {
		return thread
	}
	return nil
}

// addToExistingThread adds a new email to an existing thread
func (tm *ThreadManager) addToExistingThread(thread *EmailThread, email *ParsedEmail) *EmailThread {
	// Track participant changes
	oldParticipants := make(map[string]bool)
	for _, p := range thread.Participants {
		oldParticipants[strings.ToLower(p)] = true
	}

	// Get current email participants (From, To, CC)
	currentEmailParticipants := make(map[string]bool)

	// Add sender
	if fromAddr := extractEmailAddress(email.From); fromAddr != "" {
		currentEmailParticipants[strings.ToLower(fromAddr)] = true
	}
	// Add To recipients
	for _, addr := range email.To {
		if cleanAddr := extractEmailAddress(addr); cleanAddr != "" {
			currentEmailParticipants[strings.ToLower(cleanAddr)] = true
		}
	}
	// Add CC recipients
	for _, addr := range email.Cc {
		if cleanAddr := extractEmailAddress(addr); cleanAddr != "" {
			currentEmailParticipants[strings.ToLower(cleanAddr)] = true
		}
	}

	// Merge with existing participants for the thread's active participant list
	allParticipants := make(map[string]bool)
	for participant := range oldParticipants {
		allParticipants[participant] = true
	}
	for participant := range currentEmailParticipants {
		allParticipants[participant] = true
	}

	// Store participant changes for Matrix room updates
	var addedParticipants, removedParticipants []string

	// Find newly added participants (in current email but not in thread)
	for participant := range currentEmailParticipants {
		if !oldParticipants[participant] {
			addedParticipants = append(addedParticipants, participant)
		}
	}

	// Find potentially removed participants (in thread but not in current email)
	// Only consider someone "removed" if they were active and are explicitly absent
	if len(thread.Participants) > 0 { // Only check removals for existing threads
		for participant := range oldParticipants {
			if !currentEmailParticipants[participant] {
				// This participant was removed from the current email
				removedParticipants = append(removedParticipants, participant)
			}
		}
	}

	// Update thread with current email participants (represents "active" participants)
	// This affects who can see new messages
	var activeParticipants []string
	for participant := range currentEmailParticipants {
		activeParticipants = append(activeParticipants, participant)
	}
	thread.Participants = activeParticipants

	// Store metadata for Matrix room management
	thread.AddedParticipants = addedParticipants
	thread.RemovedParticipants = removedParticipants

	// Update references chain
	if email.MessageID != "" {
		// Add this message to the references chain
		thread.References = appendUnique(thread.References, email.MessageID)
		// Note: Index update will be handled by CacheForReceiver path under write lock
	}

	return thread
}

// createNewThread creates a new email thread
func (tm *ThreadManager) createNewThread(email *ParsedEmail) *EmailThread {
	threadID := email.MessageID
	if threadID == "" {
		// Fallback: generate thread ID from subject and timestamp
		threadID = generateThreadID(email.Subject, email.Date)
	}

	// Collect all participants
	var participants []string
	participantMap := make(map[string]bool)

	if fromAddr := extractEmailAddress(email.From); fromAddr != "" {
		participantMap[strings.ToLower(fromAddr)] = true
	}
	for _, addr := range email.To {
		if cleanAddr := extractEmailAddress(addr); cleanAddr != "" {
			participantMap[strings.ToLower(cleanAddr)] = true
		}
	}
	for _, addr := range email.Cc {
		if cleanAddr := extractEmailAddress(addr); cleanAddr != "" {
			participantMap[strings.ToLower(cleanAddr)] = true
		}
	}

	for email := range participantMap {
		participants = append(participants, email)
	}

	// Create new thread
	thread := &EmailThread{
		ThreadID:     threadID,
		Subject:      email.Subject,
		Participants: participants,
		MessageID:    email.MessageID,
		InReplyTo:    email.InReplyTo,
		References:   email.References,
		LastAccessed: time.Now(),
	}

	// Add to known threads (no receiver here; caller will cache after DetermineThread using receiver)
	// For now, store under empty receiver to keep legacy behavior.
	tm.mu.Lock()
	tm.knownThreads[threadID] = thread

	// Enforce cache size limit
	if len(tm.knownThreads) > maxCachedThreads {
		tm.evictOldestThreads(maxCachedThreads / 4) // Remove 25% when limit exceeded
	}
	tm.mu.Unlock()

	return thread
}

// Helper functions

// cleanMessageID removes angle brackets from Message-ID
func cleanMessageID(messageID string) string {
	messageID = strings.TrimSpace(messageID)
	messageID = strings.TrimPrefix(messageID, "<")
	messageID = strings.TrimSuffix(messageID, ">")
	return messageID
}

// parseReferences parses the References header into individual Message-IDs
func parseReferences(references string) []string {
	// References header contains space-separated Message-IDs in angle brackets
	re := regexp.MustCompile(`<([^>]+)>`)
	matches := re.FindAllStringSubmatch(references, -1)

	var result []string
	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, match[1])
		}
	}
	return result
}

// extractEmailAddress extracts email address from "Name <email@domain.com>" format
func extractEmailAddress(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// Use mail package to parse
	addr, err := mail.ParseAddress(input)
	if err == nil {
		return addr.Address
	}

	// Fallback: simple regex extraction
	re := regexp.MustCompile(`<([^>]+)>`)
	if matches := re.FindStringSubmatch(input); len(matches) > 1 {
		return matches[1]
	}

	// If no angle brackets, check if it looks like an email
	if strings.Contains(input, "@") && strings.Contains(input, ".") {
		return input
	}

	return ""
}

// normalizeSubject removes common email prefixes and normalizes subject for threading
func normalizeSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	subject = strings.ToLower(subject)

	// Remove common prefixes
	prefixes := []string{"re:", "fwd:", "fw:", "re[", "fwd[", "fw["}
	for {
		trimmed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(subject, prefix) {
				if strings.HasSuffix(prefix, "[") {
					// Handle "Re[2]:" format
					closeBracket := strings.Index(subject[len(prefix):], "]")
					if closeBracket != -1 {
						subject = strings.TrimSpace(subject[len(prefix)+closeBracket+1:])
						if strings.HasPrefix(subject, ":") {
							subject = strings.TrimSpace(subject[1:])
						}
					} else {
						subject = strings.TrimSpace(subject[len(prefix):])
					}
				} else {
					subject = strings.TrimSpace(subject[len(prefix):])
				}
				trimmed = true
				break
			}
		}
		if !trimmed {
			break
		}
	}

	return subject
}

// generateThreadID generates a fallback thread ID when Message-ID is missing
func generateThreadID(subject string, date time.Time) string {
	normalized := normalizeSubject(subject)
	if normalized == "" {
		normalized = "no-subject"
	}

	// Create a simple hash-like ID
	return strings.ReplaceAll(normalized, " ", "-") + "-" + date.Format("20060102150405")
}

// appendUnique appends a string to a slice only if it's not already present
func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

// cleanupExpiredThreadsIfNeeded runs cache cleanup periodically to prevent memory leaks
func (tm *ThreadManager) cleanupExpiredThreadsIfNeeded() {
	// Only run cleanup every hour to avoid excessive overhead
	if time.Since(tm.lastCleanup) < time.Hour {
		return
	}

	tm.lastCleanup = time.Now()
	expiredKeys := make([]string, 0)
	cutoff := time.Now().Add(-threadCacheTTL)

	for key, thread := range tm.knownThreads {
		if thread.LastAccessed.Before(cutoff) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		// Remove from main cache and also clean up message ID index
		if thread := tm.knownThreads[key]; thread != nil {
			tm.removeFromMessageIDIndex(thread)
		}
		delete(tm.knownThreads, key)
	}
}

// evictOldestThreads removes the oldest threads to enforce cache size limits
func (tm *ThreadManager) evictOldestThreads(countToRemove int) {
	if len(tm.knownThreads) <= countToRemove {
		return
	}

	// Create slice of threads with their keys, sorted by LastAccessed
	type threadEntry struct {
		key          string
		lastAccessed time.Time
	}

	threads := make([]threadEntry, 0, len(tm.knownThreads))
	for key, thread := range tm.knownThreads {
		threads = append(threads, threadEntry{
			key:          key,
			lastAccessed: thread.LastAccessed,
		})
	}

	// Sort by LastAccessed (oldest first) using efficient algorithm
	// Use simple insertion sort which is O(n) for nearly-sorted data and O(n²) worst case
	// but much more cache-friendly than bubble sort
	for i := 1; i < len(threads); i++ {
		key := threads[i]
		j := i - 1
		for j >= 0 && threads[j].lastAccessed.After(key.lastAccessed) {
			threads[j+1] = threads[j]
			j--
		}
		threads[j+1] = key
	}

	// Remove the oldest entries
	removedCount := 0
	for _, entry := range threads {
		if removedCount >= countToRemove {
			break
		}
		// Remove from main cache and clean up message ID index
		if thread := tm.knownThreads[entry.key]; thread != nil {
			tm.removeFromMessageIDIndex(thread)
		}
		delete(tm.knownThreads, entry.key)
		removedCount++
	}
}

// removeFromMessageIDIndex removes all entries for a thread from the message ID index
func (tm *ThreadManager) removeFromMessageIDIndex(thread *EmailThread) {
	if thread.ThreadID != "" {
		delete(tm.messageIDIndex, thread.ThreadID)
	}
	if thread.MessageID != "" {
		delete(tm.messageIDIndex, thread.MessageID)
	}
	for _, ref := range thread.References {
		if ref != "" {
			delete(tm.messageIDIndex, ref)
		}
	}
}
