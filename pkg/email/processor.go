package email

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	logging "go.mau.fi/mautrix-emaildawg/pkg/logging"
)

// Processor handles the complete email processing pipeline
type Processor struct {
	log           *zerolog.Logger
	threadManager *ThreadManager

	sanitized bool
	secret    string
}

// NewProcessor creates a new email processor
func NewProcessor(log *zerolog.Logger, threadManager *ThreadManager, sanitized bool, secret string) *Processor {
	logger := log.With().Str("component", "email_processor").Logger()
	return &Processor{
		log:           &logger,
		threadManager: threadManager,
		sanitized:     sanitized,
		secret:       secret,
	}
}

// EmailMessage represents a complete parsed email ready for Matrix bridging
type EmailMessage struct {
	*ParsedEmail
	Thread      *EmailThread
	PortalKey   networkid.PortalKey
	MessageID   networkid.MessageID
	Timestamp   time.Time
	IsOutbound  bool // True if this email was sent by the bridge user
	Attachments []*EmailAttachment
}

// ProcessIMAPMessage processes an IMAP FetchMessageData and converts it to Matrix events
func (p *Processor) ProcessIMAPMessage(ctx context.Context, fetchData *imapclient.FetchMessageData, userLogin *bridgev2.UserLogin) (*EmailMessage, error) {
	p.log.Info().
		Uint32("seq_num", fetchData.SeqNum).
		Msg("Processing IMAP message")

	// Parse the IMAP fetch data into a ParsedEmail
	parsedEmail, err := p.parseIMAPFetchData(fetchData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMAP fetch data: %w", err)
	}

	if p.sanitized {
		p.log.Debug().
			Str("message_id_hash", logging.HashHMAC(parsedEmail.MessageID, p.secret, 10)).
			Str("subject_hash", logging.HashHMAC(parsedEmail.Subject, p.secret, 10)).
			Str("from_masked", logging.MaskEmail(parsedEmail.From)).
			Msg("Successfully parsed email message")
	} else {
		p.log.Debug().
			Str("message_id", parsedEmail.MessageID).
			Str("subject", parsedEmail.Subject).
			Str("from", parsedEmail.From).
			Msg("Successfully parsed email message")
	}

	// Step 1: Determine thread membership
	thread := p.threadManager.DetermineThread(parsedEmail)
	if thread == nil {
		return nil, fmt.Errorf("failed to determine thread for message %s", parsedEmail.MessageID)
	}

	// Step 2: Create portal key for this thread
	portalKey := networkid.PortalKey{
		ID:       networkid.PortalID(fmt.Sprintf("thread:%s", thread.ThreadID)),
		Receiver: userLogin.ID,
	}

	// Step 3: Create network message ID
	networkMessageID := networkid.MessageID(fmt.Sprintf("email:%s", parsedEmail.MessageID))

	// Step 4: Check if this is an outbound message (sent by the bridge user)
	isOutbound := p.isOutboundMessage(parsedEmail, userLogin)

	emailMessage := &EmailMessage{
		ParsedEmail: parsedEmail,
		Thread:      thread,
		PortalKey:   portalKey,
		MessageID:   networkMessageID,
		Timestamp:   parsedEmail.Date,
		IsOutbound:  isOutbound,
	}

	if p.sanitized {
		p.log.Info().
			Str("thread_id", logging.HashHMAC(thread.ThreadID, p.secret, 10)).
			Str("portal_key", logging.HashHMAC(string(portalKey.ID), p.secret, 10)).
			Bool("is_outbound", isOutbound).
			Msg("Successfully processed complete IMAP message")
	} else {
		p.log.Info().
			Str("thread_id", thread.ThreadID).
			Str("portal_key", string(portalKey.ID)).
			Bool("is_outbound", isOutbound).
			Msg("Successfully processed complete IMAP message")
	}

	// Add attachments to the email message (already extracted in parseIMAPFetchData)
	emailMessage.Attachments = parsedEmail.Attachments

	return emailMessage, nil
}

// parseIMAPFetchData parses IMAP fetch data into a ParsedEmail struct
func (p *Processor) parseIMAPFetchData(fetchData *imapclient.FetchMessageData) (*ParsedEmail, error) {
	// Collect the fetch data into a buffer
	buf, err := fetchData.Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to collect fetch data: %w", err)
	}

	// Initialize parsed email with basic information from IMAP fetch data
	parsedEmail := &ParsedEmail{
		MessageID: fmt.Sprintf("uid-%d", buf.UID), // Fallback if no Message-ID found
		Date:     time.Now(), // Fallback if no date found
	}

	// Extract data from envelope if available
	if buf.Envelope != nil {
		env := buf.Envelope
		
		// Extract Message-ID
		if env.MessageID != "" {
			parsedEmail.MessageID = cleanMessageID(env.MessageID)
		}
		
		// Extract subject
		if env.Subject != "" {
			parsedEmail.Subject = env.Subject
		}
		
		// Extract In-Reply-To
		if len(env.InReplyTo) > 0 {
			parsedEmail.InReplyTo = cleanMessageID(env.InReplyTo[0])
		}
		
		// Extract date
		if !env.Date.IsZero() {
			parsedEmail.Date = env.Date
		}
		
		// Extract sender
		if len(env.From) > 0 {
			parsedEmail.From = formatIMAPAddress(&env.From[0])
		}
		
		// Extract recipients
		parsedEmail.To = formatIMAPAddressSlice(env.To)
		parsedEmail.Cc = formatIMAPAddressSlice(env.Cc)
		parsedEmail.Bcc = formatIMAPAddressSlice(env.Bcc)
	}

	// Parse body sections for text and HTML content
	textContent, htmlContent, err := p.parseMessageBody(buf)
	if err != nil {
		p.log.Warn().Err(err).Msg("Failed to parse message body, using fallback")
		textContent = "[Failed to parse message content]"
	}

	parsedEmail.TextContent = textContent
	parsedEmail.HTMLContent = htmlContent

	// Extract attachments if present
	attachments, err := p.extractAttachments(buf)
	if err != nil {
		p.log.Warn().Err(err).Msg("Failed to extract attachments")
	} else if len(attachments) > 0 {
		p.log.Debug().Int("count", len(attachments)).Msg("Extracted attachments from email")
	}
	parsedEmail.Attachments = attachments

	// Extract References from headers if body sections are available
	references := p.extractReferencesFromHeaders(buf)
	if len(references) > 0 {
		parsedEmail.References = references
	}

	return parsedEmail, nil
}

// parseMessageBody extracts text and HTML content from IMAP body sections
func (p *Processor) parseMessageBody(buf *imapclient.FetchMessageBuffer) (textContent, htmlContent string, err error) {
	// Prefer MIME parsing for any non-header sections to avoid dumping boundaries/headers
	for _, section := range buf.BodySection {
		if len(section.Bytes) == 0 {
			continue
		}
		if section.Section.Specifier == imap.PartSpecifierHeader {
			continue
		}
		text, html := p.parseMIMEContent(section.Bytes)
		if text != "" && textContent == "" {
			textContent = text
		}
		if html != "" && htmlContent == "" {
			htmlContent = html
		}
		if textContent != "" && htmlContent != "" {
			break
		}
	}

	// If no text content found, provide a fallback
	if textContent == "" {
		textContent = "[No readable text content found]"
	}

	return textContent, htmlContent, nil
}

// parseMIMEContent attempts to parse MIME content from raw body data
func (p *Processor) parseMIMEContent(data []byte) (textContent, htmlContent string) {
	// Try to parse as a complete email message
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// If not a complete message, heuristically detect multipart boundary
		if boundary := detectBoundary(data); boundary != "" {
			return p.parseMultipartContent(bytes.NewReader(data), boundary)
		}
		// Fallback as raw text
		return string(data), ""
	}

	// Check Content-Type header
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// No content type: try boundary heuristic
		raw, _ := io.ReadAll(msg.Body)
		if boundary := detectBoundary(raw); boundary != "" {
			return p.parseMultipartContent(bytes.NewReader(raw), boundary)
		}
		// Fallback: plain text
		return string(raw), ""
	}

	// Parse media type
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Fallback to plain text
		body, _ := io.ReadAll(msg.Body)
		return string(body), ""
	}

	switch {
	case strings.HasPrefix(mediaType, "text/plain"):
		body, _ := io.ReadAll(msg.Body)
		return string(body), ""
	case strings.HasPrefix(mediaType, "text/html"):
		body, _ := io.ReadAll(msg.Body)
		return "", string(body)
	case strings.HasPrefix(mediaType, "multipart/"):
		// Handle multipart messages
		return p.parseMultipartContent(msg.Body, params["boundary"])
	default:
		// Unknown content type, try to read as text
		body, _ := io.ReadAll(msg.Body)
		return string(body), ""
	}
}

// parseMultipartContent parses multipart MIME content
func (p *Processor) parseMultipartContent(body io.Reader, boundary string) (textContent, htmlContent string) {
	if boundary == "" {
		return "[Multipart message with no boundary]", ""
	}

	mr := multipart.NewReader(body, boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		// Decode part body according to Content-Transfer-Encoding
		cte := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
		decoded := decodeBody(part, cte)
		partData, err := io.ReadAll(decoded)
		part.Close()
		if err != nil {
			continue
		}

		// Check Content-Type of this part
		contentType := part.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)

		switch {
		case strings.HasPrefix(mediaType, "text/plain"):
			if textContent == "" {
				textContent = string(partData)
			}
		case strings.HasPrefix(mediaType, "text/html"):
			if htmlContent == "" {
				htmlContent = string(partData)
			}
		}
	}

	return textContent, htmlContent
}

// extractAttachments extracts attachments from IMAP body sections
func (p *Processor) extractAttachments(buf *imapclient.FetchMessageBuffer) ([]*EmailAttachment, error) {
	if buf == nil {
		return nil, nil
	}

	var attachments []*EmailAttachment

	// Look through body sections for attachments
	for _, section := range buf.BodySection {
		if len(section.Bytes) == 0 {
			continue
		}

		// Check if this section could be an attachment
		if section.Section.Specifier != imap.PartSpecifierText && 
		   section.Section.Specifier != imap.PartSpecifierHeader {
			
			// Try to parse as multipart content for attachments
			attachments = append(attachments, p.extractMultipartAttachments(section.Bytes)...)
		}
	}

	return attachments, nil
}

// extractMultipartAttachments extracts attachments from multipart content
func (p *Processor) extractMultipartAttachments(data []byte) []*EmailAttachment {
	var attachments []*EmailAttachment

	// Try to parse as a complete email message
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return attachments
	}

	// Check Content-Type header
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		return attachments
	}

	// Parse media type
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return attachments
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		// Handle multipart messages for attachments
		boundary := params["boundary"]
		if boundary != "" {
			attachments = p.parseMultipartAttachments(msg.Body, boundary)
		}
	}

	return attachments
}

// parseMultipartAttachments parses multipart content for attachments
func (p *Processor) parseMultipartAttachments(body io.Reader, boundary string) []*EmailAttachment {
	var attachments []*EmailAttachment

	mr := multipart.NewReader(body, boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		// Check if this part is an attachment
		contentDisposition := part.Header.Get("Content-Disposition")
		if strings.Contains(strings.ToLower(contentDisposition), "attachment") {
			// Read attachment data
			data, err := io.ReadAll(part)
			part.Close()
			if err != nil {
				continue
			}

			// Extract filename
			filename := "attachment"
			if _, params, err := mime.ParseMediaType(contentDisposition); err == nil {
				if fn := params["filename"]; fn != "" {
					filename = fn
				}
			}

			// Get content type
			contentType := part.Header.Get("Content-Type")
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			attachment := &EmailAttachment{
				Filename:    filename,
				ContentType: contentType,
				Size:        int64(len(data)),
				Data:        data,
			}

			attachments = append(attachments, attachment)
			p.log.Debug().
				Str("filename", filename).
				Str("content_type", contentType).
				Int64("size", attachment.Size).
				Msg("Extracted email attachment")
		} else {
			// Not an attachment, just close the part
			part.Close()
		}
	}

	return attachments
}

// extractReferencesFromHeaders extracts References header from body sections
func (p *Processor) extractReferencesFromHeaders(buf *imapclient.FetchMessageBuffer) []string {
	// Look for header sections
	for _, section := range buf.BodySection {
		if section.Section.Specifier == imap.PartSpecifierHeader {
			// Parse headers
			headers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(section.Bytes))).ReadMIMEHeader()
			if err != nil {
				continue
			}

			// Extract References header
			if references := headers.Get("References"); references != "" {
				return parseReferences(references)
			}
		}
	}
	return nil
}

// decodeBody wraps the reader according to Content-Transfer-Encoding
func decodeBody(r io.Reader, cte string) io.Reader {
	switch strings.ToLower(cte) {
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	default:
		return r
	}
}

// detectBoundary tries to find a MIME boundary token in a raw body without headers
func detectBoundary(data []byte) string {
	// Look for a line starting with --token and followed soon by a Content-Type header
	// This is a best-effort heuristic for bodies that are raw multipart payloads
	lines := bytes.Split(data, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		line := bytes.TrimRight(lines[i], "\r")
		if bytes.HasPrefix(line, []byte("--")) && len(line) > 2 {
			token := string(line[2:])
			// Skip closing boundary markers like --token--
			if strings.HasSuffix(token, "--") {
				token = strings.TrimSuffix(token, "--")
			}
			// Validate by checking next few lines for Content-Type
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				if bytes.HasPrefix(bytes.ToLower(bytes.TrimSpace(lines[j])), []byte("content-type:")) {
					return token
				}
			}
		}
	}
	return ""
}

// formatIMAPAddress converts an IMAP address to string format
func formatIMAPAddress(addr *imap.Address) string {
	if addr == nil {
		return ""
	}

	if addr.Name != "" {
		return fmt.Sprintf("%s <%s@%s>", addr.Name, addr.Mailbox, addr.Host)
	}
	return fmt.Sprintf("%s@%s", addr.Mailbox, addr.Host)
}

// formatIMAPAddressList converts IMAP addresses to string slice (for v1 compatibility)
func formatIMAPAddressList(addrs []*imap.Address) []string {
	if len(addrs) == 0 {
		return nil
	}

	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = formatIMAPAddress(addr)
	}
	return result
}

// formatIMAPAddressSlice converts IMAP v2 address slices to string slice
func formatIMAPAddressSlice(addrs []imap.Address) []string {
	if len(addrs) == 0 {
		return nil
	}

	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = formatIMAPAddress(&addr)
	}
	return result
}


// isOutboundMessage determines if this email was sent by the bridge user
func (p *Processor) isOutboundMessage(email *ParsedEmail, userLogin *bridgev2.UserLogin) bool {
	userEmail := string(userLogin.ID)
	fromEmail := extractEmailAddress(email.From)
	
	return strings.EqualFold(fromEmail, userEmail)
}

// ToMatrixEvent converts an EmailMessage to a bridgev2 RemoteMessage event
func (p *Processor) ToMatrixEvent(ctx context.Context, emailMsg *EmailMessage, userLogin *bridgev2.UserLogin) bridgev2.RemoteMessage {
	return &EmailMatrixEvent{
		emailMessage: emailMsg,
		userLogin:    *userLogin,
		processor:    p,
	}
}

// EmailMatrixEvent and helper functions

// EmailMatrixEvent implements bridgev2.RemoteMessage for email messages
type EmailMatrixEvent struct {
	emailMessage *EmailMessage
	userLogin    bridgev2.UserLogin
	processor    *Processor
}

// Implement bridgev2.RemoteMessage interface
func (e *EmailMatrixEvent) GetID() networkid.MessageID {
	return e.emailMessage.MessageID
}

func (e *EmailMatrixEvent) GetTimestamp() time.Time {
	return e.emailMessage.Timestamp
}

func (e *EmailMatrixEvent) GetSender() bridgev2.EventSender {
	if e.emailMessage.IsOutbound {
		return bridgev2.EventSender{IsFromMe: true}
	}
	
	// Create ghost sender for the email sender  
	fromEmail := extractEmailAddress(e.emailMessage.From)
	ghostID := emailToGhostID(fromEmail)
	return bridgev2.EventSender{Sender: ghostID}
}

func (e *EmailMatrixEvent) GetPortalKey() networkid.PortalKey {
	return e.emailMessage.PortalKey
}

func (e *EmailMatrixEvent) GetType() bridgev2.RemoteEventType {
	return bridgev2.RemoteEventMessage
}

func (e *EmailMatrixEvent) AddLogContext(c zerolog.Context) zerolog.Context {
	return c.
		Str("email_message_id", string(e.emailMessage.MessageID)).
		Str("email_subject", e.emailMessage.Subject).
		Str("email_from", e.emailMessage.From)
}

func (e *EmailMatrixEvent) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	var parts []*bridgev2.ConvertedMessagePart

	// Create the main text message content
	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    e.emailMessage.TextContent,
	}

	// Add HTML formatting if available
	if e.emailMessage.HTMLContent != "" && e.emailMessage.HTMLContent != e.emailMessage.TextContent {
		content.Format = event.FormatHTML
		content.FormattedBody = e.emailMessage.HTMLContent
	}

	// Add email metadata to the message
	if content.Body == "" {
		content.Body = "[No text content]"
	}


	// Add participant change notification if any
	if participantChangeMsg := generateParticipantChangeMessage(e.emailMessage.Thread); participantChangeMsg != "" {
		changeContent := &event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    participantChangeMsg,
		}
		parts = append(parts, &bridgev2.ConvertedMessagePart{
			Type:    event.EventMessage,
			Content: changeContent,
		})
		
		// Clear the changes after processing
		e.emailMessage.Thread.ClearParticipantChanges()
	}

	// Add the main message part
	parts = append(parts, &bridgev2.ConvertedMessagePart{
		Type:    event.EventMessage,
		Content: content,
	})

	// Process attachments and upload them to Matrix
	for _, attachment := range e.emailMessage.Attachments {
		if attachmentPart, err := e.convertAttachmentToMatrix(ctx, attachment, intent); err == nil {
			parts = append(parts, attachmentPart)
		} else {
			e.processor.log.Warn().Err(err).
				Str("filename", attachment.Filename).
				Msg("Failed to upload attachment to Matrix")
			
			// Add a fallback text message for failed attachment
			fallbackContent := &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    fmt.Sprintf("📎 Attachment failed to upload: %s (%s)", attachment.Filename, attachment.ContentType),
			}
			parts = append(parts, &bridgev2.ConvertedMessagePart{
				Type:    event.EventMessage,
				Content: fallbackContent,
			})
		}
	}

	return &bridgev2.ConvertedMessage{
		Parts: parts,
	}, nil
}


// convertAttachmentToMatrix uploads an email attachment to Matrix and returns a ConvertedMessagePart
func (e *EmailMatrixEvent) convertAttachmentToMatrix(ctx context.Context, attachment *EmailAttachment, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessagePart, error) {
	e.processor.log.Debug().
		Str("filename", attachment.Filename).
		Str("content_type", attachment.ContentType).
		Int64("size", attachment.Size).
		Msg("Uploading email attachment to Matrix")

	// Upload the attachment data to Matrix media repository
	uploadResp, _, err := intent.UploadMedia(ctx, "", attachment.Data, attachment.Filename, attachment.ContentType)
	if err != nil {
		return nil, fmt.Errorf("failed to upload attachment to Matrix: %w", err)
	}

	// Determine the message type based on content type
	msgType := e.getMessageTypeForAttachment(attachment.ContentType)

	// Create the Matrix message content for the attachment
	content := &event.MessageEventContent{
		MsgType: msgType,
		Body:    attachment.Filename,
		URL:     uploadResp,
	}

	// Add basic file info - Matrix will handle the appropriate type
	content.Info = &event.FileInfo{
		MimeType: attachment.ContentType,
		Size:     int(attachment.Size),
	}

	// For images and videos, we could add more specific info in the future
	// but for now, basic FileInfo works for all types

	e.processor.log.Info().
		Str("filename", attachment.Filename).
		Str("matrix_url", string(content.URL)).
		Str("msg_type", string(msgType)).
		Msg("Successfully uploaded attachment to Matrix")

	return &bridgev2.ConvertedMessagePart{
		Type:    event.EventMessage,
		Content: content,
	}, nil
}

// getMessageTypeForAttachment determines the appropriate Matrix message type for an attachment
func (e *EmailMatrixEvent) getMessageTypeForAttachment(contentType string) event.MessageType {
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return event.MsgImage
	case strings.HasPrefix(contentType, "video/"):
		return event.MsgVideo
	case strings.HasPrefix(contentType, "audio/"):
		return event.MsgAudio
	default:
		return event.MsgFile
	}
}

// Helper functions for email processing

// emailToGhostID converts an email address to a Matrix ghost user ID
func emailToGhostID(email string) networkid.UserID {
	addr := strings.TrimSpace(email)
	return networkid.UserID(fmt.Sprintf("email:%s", addr))
}

// generateParticipantChangeMessage creates a timeline message for participant changes
func generateParticipantChangeMessage(thread *EmailThread) string {
	if len(thread.AddedParticipants) == 0 && len(thread.RemovedParticipants) == 0 {
		return ""
	}
	
	var messages []string
	
	// Handle added participants
	if len(thread.AddedParticipants) > 0 {
		if len(thread.AddedParticipants) == 1 {
			messages = append(messages, fmt.Sprintf("📧 %s joined the conversation", thread.AddedParticipants[0]))
		} else {
			messages = append(messages, fmt.Sprintf("📧 %s joined the conversation", strings.Join(thread.AddedParticipants, ", ")))
		}
	}
	
	// Handle removed participants
	if len(thread.RemovedParticipants) > 0 {
		if len(thread.RemovedParticipants) == 1 {
			messages = append(messages, fmt.Sprintf("📧 %s was removed from the conversation", thread.RemovedParticipants[0]))
		} else {
			messages = append(messages, fmt.Sprintf("📧 %s were removed from the conversation", strings.Join(thread.RemovedParticipants, ", ")))
		}
	}
	
	return strings.Join(messages, "\n")
}

