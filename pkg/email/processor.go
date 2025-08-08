package email

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"unicode/utf8"
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

	// MaxUploadBytes limits individual media uploads to Matrix. Items larger than this
	// will either be gzipped (for text/html and text/plain bodies) or skipped with a notice.
	MaxUploadBytes int
	// When true, attempt gzip for oversized original email bodies before giving up.
	GzipLargeBodies bool
}

// NewProcessor creates a new email processor
func NewProcessor(log *zerolog.Logger, threadManager *ThreadManager, sanitized bool, secret string) *Processor {
	logger := log.With().Str("component", "email_processor").Logger()
	return &Processor{
		log:             &logger,
		threadManager:   threadManager,
		sanitized:       sanitized,
		secret:         secret,
		MaxUploadBytes: 10 * 1024 * 1024, // 10 MiB default; can be made configurable later
		GzipLargeBodies: true,
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
	// High-level: log the number of body sections
	p.log.Debug().Int("body_section_count", len(buf.BodySection)).Msg("Parsing message body sections")
	// Prefer MIME parsing for any non-header sections to avoid dumping boundaries/headers
	for idx, section := range buf.BodySection {
		p.log.Trace().
			Int("section_index", idx).
			Str("specifier", string(section.Section.Specifier)).
			Int("bytes", len(section.Bytes)).
			Msg("Processing body section")
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

// If we don't have text/plain but we do have HTML, derive a simple plaintext fallback
	if textContent == "" && htmlContent != "" {
		textContent = simpleHTMLToText(htmlContent)
	}
	// If still no text content found, provide a fallback
	if textContent == "" {
		textContent = "[No readable text content found]"
	}
	p.log.Debug().
		Int("text_len", len(textContent)).
		Int("html_len", len(htmlContent)).
		Msg("Finished parsing message body")

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
		mediaType, params, _ := mime.ParseMediaType(contentType)
		p.log.Trace().
			Str("mime_media_type", mediaType).
			Msg("Multipart content: encountered part")

		switch {
		case strings.HasPrefix(mediaType, "multipart/"):
			// Recurse into nested multiparts (e.g., multipart/alternative inside multipart/mixed)
			childText, childHTML := p.parseMultipartContent(bytes.NewReader(partData), params["boundary"])
			if textContent == "" && childText != "" {
				textContent = childText
			}
			if htmlContent == "" && childHTML != "" {
				htmlContent = childHTML
			}
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
	p.log.Debug().Int("body_section_count", len(buf.BodySection)).Msg("Starting attachment extraction")

	// Look through body sections for attachments
	for idx, section := range buf.BodySection {
		p.log.Trace().
			Int("section_index", idx).
			Str("specifier", string(section.Section.Specifier)).
			Int("bytes", len(section.Bytes)).
			Msg("Examining section for attachments")
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

		contentDisposition := part.Header.Get("Content-Disposition")
		dispLower := strings.ToLower(strings.TrimSpace(contentDisposition))

// Read and decode part body
		cte := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
		decoded := decodeBody(part, cte)
		dataBytes, err := io.ReadAll(decoded)
		part.Close()
		if err != nil {
			continue
		}

		// Determine content type and parameters
		ct := part.Header.Get("Content-Type")
		mediaType, params, _ := mime.ParseMediaType(ct)
		p.log.Trace().
			Str("mime_media_type", mediaType).
			Str("content_disposition", strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Disposition")))).
			Str("cte", cte).
			Int("decoded_bytes", len(dataBytes)).
			Msg("Attachment parsing: encountered part")
		if ct == "" {
			ct = "application/octet-stream"
			mediaType = ct
		}

		// Skip multipart container parts: recurse to find real parts
		if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
			childBoundary := params["boundary"]
			attachments = append(attachments, p.parseMultipartAttachments(bytes.NewReader(dataBytes), childBoundary)...)
			continue
		}

		// Extract potential filename
		filename := ""
		if _, cdParams, err := mime.ParseMediaType(contentDisposition); err == nil {
			if fn := cdParams["filename"]; fn != "" {
				filename = fn
			}
		}

		// Inline-related headers
		contentID := normalizeCIDHeader(part.Header.Get("Content-ID"))
		contentLocation := strings.TrimSpace(part.Header.Get("Content-Location"))
		isInline := strings.Contains(dispLower, "inline")

		// Decide if this is a real attachment to expose:
		// - Always include if disposition is attachment
		// - Include any part with a filename (even text/*)
		// - Include inline images/files if they have Content-ID or Content-Location (for HTML inlining)
		// - Otherwise, skip common body parts like text/plain and text/html without attachment indicators
		isText := strings.HasPrefix(strings.ToLower(mediaType), "text/")
		isAttachmentDisposition := strings.Contains(dispLower, "attachment")
		isInlineReference := contentID != "" || contentLocation != ""
		if !(isAttachmentDisposition || filename != "" || isInlineReference) {
			// Skip non-attachment, non-inline-reference parts (likely body text or generic parts)
			if isText {
				continue
			}
			if filename == "" {
				continue
			}
		}

		// Default filename if still empty
		if filename == "" {
			filename = "attachment"
		}

		attachment := &EmailAttachment{
			Filename:        filename,
			ContentType:     ct,
			Size:            int64(len(dataBytes)),
			Data:            dataBytes,
			ContentID:       contentID,
			ContentLocation: normalizeContentLocation(contentLocation),
			Disposition:     strings.ToLower(strings.TrimSpace(strings.Split(contentDisposition, ";")[0])),
			IsInline:        isInline || isInlineReference,
		}
		attachments = append(attachments, attachment)
		p.log.Debug().
			Str("filename", filename).
			Str("content_type", ct).
			Int64("size", attachment.Size).
			Bool("inline", attachment.IsInline).
			Str("cid", attachment.ContentID).
			Str("cl", attachment.ContentLocation).
			Msg("Extracted email part")
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
			token = strings.TrimSuffix(token, "--")
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
		userLogin:    userLogin,
		processor:    p,
	}
}

// EmailMatrixEvent and helper functions

// EmailMatrixEvent implements bridgev2.RemoteMessage for email messages
type EmailMatrixEvent struct {
	emailMessage *EmailMessage
	userLogin    *bridgev2.UserLogin
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

	// Preprocess inline images for HTML
	usedInline := make(map[int]bool)
	cidToMXC := make(map[string]string)
	locToMXC := make(map[string]string)
	origHTML := e.emailMessage.HTMLContent
	e.processor.log.Debug().
		Int("attachments", len(e.emailMessage.Attachments)).
		Int("text_len", len(e.emailMessage.TextContent)).
		Int("html_len", len(origHTML)).
		Msg("Converting email to Matrix event")
	if origHTML != "" {
		// Early lightweight minification to save space without harming formatting
		if len(origHTML) > 30*1024 {
			origHTML = lightMinifyHTML(origHTML)
		}
		// Externalize data: URLs to MXC and rewrite references
		dataURIsReplaced, replacedCount, failedCount := e.externalizeDataURIs(ctx, intent, origHTML)
		if replacedCount > 0 || failedCount > 0 {
			if replacedCount > 0 {
				n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: fmt.Sprintf("Optimized inline resources: moved %d embedded data URLs to media.", replacedCount)}
				parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
			}
			if failedCount > 0 {
				n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: fmt.Sprintf("Some embedded data URLs were too large or invalid and were omitted (%d).", failedCount)}
				parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
			}
		}
		origHTML = dataURIsReplaced
		// Build index of inline-capable attachments
		for _, att := range e.emailMessage.Attachments {
			if att == nil {
				continue
			}
			if att.ContentID != "" {
				cidToMXC[att.ContentID] = "" // mark as candidate
			}
			if att.ContentLocation != "" {
				locToMXC[att.ContentLocation] = ""
			}
		}
// Find referenced CIDs and content-locations, upload and map to MXC
		referencedCIDs := findCIDsInHTML(origHTML)
		referencedLocs := findContentLocationsInHTML(origHTML)
		pcount := func(m map[string]string) int { c := 0; for _, v := range m { if v != "" { c++ } }; return c }
		e.processor.log.Debug().
			Int("cid_candidates", len(cidToMXC)).
			Int("loc_candidates", len(locToMXC)).
			Int("cid_refs", len(referencedCIDs)).
			Int("loc_refs", len(referencedLocs)).
			Msg("Inline reference analysis before upload")
		// Upload CIDs
		tooLargeInline := 0
		for cid := range referencedCIDs {
			idx := findAttachmentByCID(e.emailMessage.Attachments, cid)
			if idx >= 0 {
				att := e.emailMessage.Attachments[idx]
				if cidToMXC[cid] == "" {
					if e.processor.MaxUploadBytes > 0 && att.Size > int64(e.processor.MaxUploadBytes) {
						tooLargeInline++
						continue
					}
					mxc, _, err := intent.UploadMedia(ctx, "", att.Data, bestFilename(att, cid), att.ContentType)
					if err == nil {
						cidToMXC[cid] = string(mxc)
						usedInline[idx] = true
					}
				}
			}
		}
		// Upload content-locations
		for loc := range referencedLocs {
			idx := findAttachmentByContentLocation(e.emailMessage.Attachments, loc)
			if idx >= 0 {
				att := e.emailMessage.Attachments[idx]
				if locToMXC[loc] == "" {
					if e.processor.MaxUploadBytes > 0 && att.Size > int64(e.processor.MaxUploadBytes) {
						tooLargeInline++
						continue
					}
					mxc, _, err := intent.UploadMedia(ctx, "", att.Data, bestFilename(att, loc), att.ContentType)
					if err == nil {
						locToMXC[loc] = string(mxc)
						usedInline[idx] = true
					}
				}
			}
		}
		if tooLargeInline > 0 {
			n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: fmt.Sprintf("Some inline resources were too large and were omitted (%d).", tooLargeInline)}
			parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
		}
// Rewrite HTML with MXC URLs
		rewritten := rewriteHTMLInline(origHTML, cidToMXC, locToMXC)
		e.processor.log.Debug().
			Int("cid_uploaded", pcount(cidToMXC)).
			Int("loc_uploaded", pcount(locToMXC)).
			Int("new_html_len", len(rewritten)).
			Msg("Rewrote HTML with inline MXC URLs")
		origHTML = rewritten
	}

	// Create the main text message content
	bodyText := e.emailMessage.TextContent
	// Avoid duplicating large content when HTML is present: summarize body
	if origHTML != "" && len(bodyText) > 2048 {
		short, _ := truncateUTF8PreserveWords(bodyText, 1000)
		bodyText = short + "\n\n[HTML version included below]"
	}
	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    bodyText,
	}

// Add HTML formatting if available
	if origHTML != "" && origHTML != e.emailMessage.TextContent {
		content.Format = event.FormatHTML
		content.FormattedBody = origHTML
	}

	// Ensure body isn't empty
	if content.Body == "" {
		content.Body = "[No text content]"
	}

	// Absolute safety limit below Matrix's 64 KiB content cap, with extra margin for encryption overhead
	// Matrix rejects events > 64 KiB after encryption. Use a conservative cap.
	const hardLimit = 48 * 1024

	// Step 1: If we have HTML, try to keep it by minifying when necessary
	if !withinMatrixLimit(content, hardLimit) && content.FormattedBody != "" {
		// Try bounded minification (more conservative target to account for encryption overhead)
		if minified, ok := boundedMinifyHTML(content.FormattedBody, 24*1024); ok {
			content.FormattedBody = minified
		}
			// If still too big, drop HTML but preserve as attachment
			if !withinMatrixLimit(content, hardLimit) {
				content.FormattedBody = ""
				// Add a small notice in the body.
				if content.Body != "" {
					content.Body += "\n\n[Full HTML too large to send inline — attached below]"
				} else {
					content.Body = "[Full HTML too large to send inline — attached below]"
				}
				htmlBytes := []byte(origHTML)
				// Prepare a user-facing notice about data handling
				var noticeText string
				filename := "original-email.html"
				mimeType := "text/html"
				// Enforce upload size limit with gzip fallback for bodies
				if e.processor.MaxUploadBytes > 0 && len(htmlBytes) > e.processor.MaxUploadBytes && e.processor.GzipLargeBodies {
					if gz, ok := gzipBytes(htmlBytes); ok && len(gz) <= e.processor.MaxUploadBytes {
						htmlBytes = gz
						filename = "original-email.html.gz"
						mimeType = "application/gzip"
						noticeText = "HTML body exceeded upload limit — compressed and attached as .gz for review."
					}
				}
				if e.processor.MaxUploadBytes > 0 && len(htmlBytes) > e.processor.MaxUploadBytes {
					// Still too big — send a clear notice and skip
					n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: "HTML body too large to attach; content was omitted."}
					parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
				} else {
					mxc, _, err := intent.UploadMedia(ctx, "", htmlBytes, filename, mimeType)
					if err != nil {
						e.processor.log.Warn().Err(err).Msg("Failed to upload full HTML, sending notice instead")
						n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: "Failed to upload full HTML content."}
						parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
					} else {
						if noticeText != "" {
							n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: noticeText}
							parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
						} else {
							n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: "Full HTML was too large to send inline — attached for review."}
							parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
						}
						att := &event.MessageEventContent{MsgType: event.MsgFile, Body: filename, URL: mxc}
						att.Info = &event.FileInfo{MimeType: mimeType, Size: len(htmlBytes)}
						parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: att})
					}
				}
			}
	}

	// Step 2: If still too large (plain text is huge), truncate body and attach full text.
	if !withinMatrixLimit(content, hardLimit) {
		fullText := content.Body
		// Aim to leave headroom for wrapper keys etc.
		maxBody := hardLimit - 2048
		if maxBody < 1024 {
			maxBody = 1024
		}
		trunc, did := truncateUTF8PreserveWords(fullText, maxBody)
		if did {
			content.Body = trunc + "\n\n[Message truncated — full text attached]"
		} else {
			// As a last resort, cut raw bytes safely
			if len(fullText) > maxBody {
				content.Body = fullText[:maxBody] + "\n\n[Message truncated]"
			}
		}
		// Attach full text (with gzip fallback if oversized)
		textBytes := []byte(fullText)
		filename := "original-email.txt"
		mimeType := "text/plain"
		noticeText := "Full text was too large to send inline — attached for review."
		if e.processor.MaxUploadBytes > 0 && len(textBytes) > e.processor.MaxUploadBytes && e.processor.GzipLargeBodies {
			if gz, ok := gzipBytes(textBytes); ok && len(gz) <= e.processor.MaxUploadBytes {
				textBytes = gz
				filename = "original-email.txt.gz"
				mimeType = "application/gzip"
				noticeText = "Text body exceeded upload limit — compressed and attached as .gz for review."
			}
		}
		if e.processor.MaxUploadBytes > 0 && len(textBytes) > e.processor.MaxUploadBytes {
			// Still too big — clear notice and skip attaching
			n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: "Text body too large to attach; only truncated body was sent."}
			parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
		} else {
			mxc, _, err := intent.UploadMedia(ctx, "", textBytes, filename, mimeType)
			if err != nil {
				e.processor.log.Warn().Err(err).Msg("Failed to upload full text, proceeding with truncated body only")
			} else {
				n := &event.MessageEventContent{MsgType: event.MsgNotice, Body: noticeText}
				parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: n})
				att := &event.MessageEventContent{MsgType: event.MsgFile, Body: filename, URL: mxc}
				att.Info = &event.FileInfo{MimeType: mimeType, Size: len(textBytes)}
				parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: att})
			}
		}
	}

	// After adjustments, if somehow still too big, drop formatted_body to be extra safe
	if content.FormattedBody != "" && !withinMatrixLimit(content, hardLimit) {
		content.FormattedBody = ""
	}

	// Add participant change notification if any
	if participantChangeMsg := generateParticipantChangeMessage(e.emailMessage.Thread); participantChangeMsg != "" {
		changeContent := &event.MessageEventContent{MsgType: event.MsgNotice, Body: participantChangeMsg}
		parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: changeContent})
		// Clear the changes after processing
		e.emailMessage.Thread.ClearParticipantChanges()
	}

	// Add the main message part(s), chunking if necessary to stay well below server limits.
	// Use a conservative per-event target to account for encryption overhead.
	const perEventTarget = 16 * 1024
	if withinMatrixLimit(content, hardLimit) && len(content.Body) <= perEventTarget {
parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: content})
	} else {
		// Split the body into multiple UTF-8 safe chunks.
		remaining := content.Body
		chunkIndex := 1
		for len(remaining) > 0 {
			// Try to cut a chunk that fits comfortably under the target
			chunk, _ := truncateUTF8PreserveWords(remaining, perEventTarget)
			if chunk == "" {
				// Fallback to raw slice to make progress
				cut := perEventTarget
				if cut > len(remaining) { cut = len(remaining) }
				chunk = remaining[:cut]
			}
chunkContent := &event.MessageEventContent{MsgType: event.MsgText, Body: chunk}
			// Make extra sure this chunk fits JSON limit
			for !withinMatrixLimit(chunkContent, hardLimit) && len(chunk) > 0 {
				// Reduce chunk size by 10%
				reduceBy := len(chunk) / 10
				if reduceBy < 256 { reduceBy = 256 }
				newLen := len(chunk) - reduceBy
				if newLen <= 0 { newLen = len(chunk) - 1 }
				chunk = chunk[:newLen]
				chunkContent.Body = chunk
			}
parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: chunkContent})
			// Advance remaining
			if len(chunk) >= len(remaining) {
				remaining = ""
			} else {
				remaining = remaining[len(chunk):]
				// Trim leading whitespace in the next chunk to avoid odd spacing
				remaining = strings.TrimLeft(remaining, " \n\t\r")
			}
			chunkIndex++
		}
	}

// Process attachments and upload them to Matrix (skip those used inline)
	for idx, attachment := range e.emailMessage.Attachments {
		if usedInline[idx] {
			continue
		}
		if attachmentPart, err := e.convertAttachmentToMatrix(ctx, attachment, intent); err == nil {
			parts = append(parts, attachmentPart)
		} else {
			e.processor.log.Warn().Err(err).Str("filename", attachment.Filename).Msg("Failed to upload attachment to Matrix")
			fallbackContent := &event.MessageEventContent{MsgType: event.MsgNotice, Body: fmt.Sprintf("📎 Attachment failed to upload: %s (%s)", attachment.Filename, attachment.ContentType)}
			parts = append(parts, &bridgev2.ConvertedMessagePart{Type: event.EventMessage, Content: fallbackContent})
		}
	}

	return &bridgev2.ConvertedMessage{Parts: parts}, nil
}

// boundedMinifyHTML performs a very simple minification and bounds output size without breaking tags badly.
// Returns (result, ok). If ok=false, caller should assume no useful minification happened.
func boundedMinifyHTML(html string, maxBytes int) (string, bool) {
	// Cheap removals: comments, script/style blocks, excessive whitespace.
	// Note: This is intentionally simple to avoid heavy dependencies.
	// 1) Remove <!-- comments -->
	html = removeHTMLComments(html)
	// 2) Remove <script>...</script> and <style>...</style>
	html = stripTagContent(html, "script")
	html = stripTagContent(html, "style")
	// 3) Collapse runs of whitespace
	html = collapseWhitespace(html)
	if len(html) <= maxBytes {
		return html, true
	}
	// Truncate at a safe boundary: try to cut at last closing tag before maxBytes
	if maxBytes < len(html) {
		cut := maxBytes
		// backtrack to a tag boundary to avoid cutting in the middle of a tag
		for cut > 0 {
			c := html[cut-1]
			if c == '>' || c == '\n' || c == ' ' {
				break
			}
			cut--
		}
		if cut < 1 {
			cut = maxBytes
		}
		res := html[:cut] + "\n<!-- truncated -->"
		return res, true
	}
	return html, false
}

func removeHTMLComments(s string) string {
	// Remove <!-- ... --> blocks (non-greedy). This is simplistic and won't handle edge cases with "--" in text.
	for {
		start := strings.Index(s, "<!--")
		if start == -1 { break }
		end := strings.Index(s[start+4:], "-->")
		if end == -1 { break }
		end += start + 4
		s = s[:start] + s[end+3:]
	}
	return s
}

func stripTagContent(s, tag string) string {
	open := "<" + tag
	close := "</" + tag + ">"
	for {
		start := strings.Index(strings.ToLower(s), open)
		if start == -1 { break }
		end := strings.Index(strings.ToLower(s[start:]), close)
		if end == -1 { // no close, remove from start to end
			s = s[:start]
			break
		}
		end = start + end + len(close)
		s = s[:start] + s[end:]
	}
	return s
}

func collapseWhitespace(s string) string {
	// Replace runs of spaces/tabs/newlines with a single space/newline where appropriate.
	// For simplicity, collapse consecutive whitespace to a single space.
	var b strings.Builder
	b.Grow(len(s))
	prevWS := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' { // whitespace
			if !prevWS {
				b.WriteByte(' ')
				prevWS = true
			}
			continue
		}
		prevWS = false
		b.WriteRune(r)
	}
return b.String()
}

// gzipBytes compresses the input using gzip with default compression. Returns (gzipped, ok).
func gzipBytes(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, false
	}
	if err := zw.Close(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// withinMatrixLimit marshals the content to JSON to estimate the actual event content size
func withinMatrixLimit(content *event.MessageEventContent, limit int) bool {
	// Only include fields that are part of the event content
	type minimal struct {
		MsgType        event.MessageType `json:"msgtype,omitempty"`
		Body           string            `json:"body,omitempty"`
		Format         string            `json:"format,omitempty"`
		FormattedBody  string            `json:"formatted_body,omitempty"`
		URL            string            `json:"url,omitempty"`
		Info           *event.FileInfo   `json:"info,omitempty"`
	}
	m := minimal{
		MsgType:       content.MsgType,
		Body:          content.Body,
		Format:        string(content.Format),
		FormattedBody: content.FormattedBody,
		URL:           string(content.URL),
		Info:          content.Info,
	}
	b, err := json.Marshal(m)
	if err != nil {
		// Fallback: approximate using lengths
		sz := len(content.Body) + len(content.FormattedBody)
		if content.URL != "" {
			sz += len(content.URL)
		}
		if content.Info != nil {
			sz += 128 // rough overhead
		}
		return sz <= limit
	}
	return len(b) <= limit
}

// truncateUTF8PreserveWords trims a string to maxBytes without splitting UTF-8 runes and tries to cut at a space.
// Returns (result, truncated)
func truncateUTF8PreserveWords(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	// Ensure we don't cut in the middle of a rune
	cut := maxBytes
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	if cut <= 0 {
		cut = maxBytes
	}
	// Try to cut at last space before cut
	lastSpace := strings.LastIndexByte(s[:cut], ' ')
	if lastSpace > 0 && cut-lastSpace < 512 { // don't backtrack too far
		cut = lastSpace
	}
	return s[:cut], true
}


// convertAttachmentToMatrix uploads an email attachment to Matrix and returns a ConvertedMessagePart
func (e *EmailMatrixEvent) convertAttachmentToMatrix(ctx context.Context, attachment *EmailAttachment, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessagePart, error) {
	e.processor.log.Debug().
		Str("filename", attachment.Filename).
		Str("content_type", attachment.ContentType).
		Int64("size", attachment.Size).
		Msg("Uploading email attachment to Matrix")

	// Enforce upload size limit for general attachments
	if e.processor.MaxUploadBytes > 0 && attachment.Size > int64(e.processor.MaxUploadBytes) {
		return nil, fmt.Errorf("attachment exceeds upload limit (%d bytes > %d bytes)", attachment.Size, e.processor.MaxUploadBytes)
	}

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

// normalizeCIDHeader cleans a Content-ID header value by trimming <> and lowercasing
func normalizeCIDHeader(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return strings.ToLower(s)
}

func normalizeCIDRef(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToLower(s), "cid:")
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

func normalizeContentLocation(s string) string {
	s = strings.TrimSpace(s)
	return s
}

// findCIDsInHTML finds cid: references in img/src and css url()
func findCIDsInHTML(html string) map[string]struct{} {
	res := make(map[string]struct{})
	// Match img src with cid: without using angle brackets to avoid encoding issues
	reImg, err := regexp.Compile(`(?i)src\s*=\s*['"]?\s*cid:([^'"\s)]+)`)
	if err == nil {
		matches := reImg.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) > 1 {
				res[normalizeCIDRef(m[1])] = struct{}{}
			}
		}
	}
	// Match CSS url(cid:...)
	reCSS, err := regexp.Compile(`(?i)url\(\s*cid:([^) \t\r\n]+)\s*\)`)
	if err == nil {
		matches := reCSS.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) > 1 {
				res[normalizeCIDRef(m[1])] = struct{}{}
			}
		}
	}
	return res
}

// findContentLocationsInHTML finds Content-Location references used in src attributes
func findContentLocationsInHTML(html string) map[string]struct{} {
	res := make(map[string]struct{})
	// src\s*=\s*['\"]([^'\"]+)['\"] and not cid: or http(s)
	re := regexp.MustCompile(`(?i)src\s*=\s*['\"]([^'\"]+)['\"]`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			val := strings.TrimSpace(m[1])
			low := strings.ToLower(val)
			if strings.HasPrefix(low, "cid:") || strings.HasPrefix(low, "http:") || strings.HasPrefix(low, "https:") || strings.HasPrefix(low, "data:") {
				continue
			}
			res[normalizeContentLocation(val)] = struct{}{}
		}
	}
	return res
}

func findAttachmentByCID(atts []*EmailAttachment, cid string) int {
	for i, a := range atts {
		if a != nil && a.ContentID != "" {
			if normalizeCIDRef(a.ContentID) == normalizeCIDRef(cid) {
				return i
			}
		}
	}
	return -1
}

func findAttachmentByContentLocation(atts []*EmailAttachment, loc string) int {
	for i, a := range atts {
		if a != nil && a.ContentLocation != "" && strings.EqualFold(a.ContentLocation, loc) {
			return i
		}
	}
	return -1
}

func bestFilename(att *EmailAttachment, fallback string) string {
	if att.Filename != "" {
		return att.Filename
	}
	if fallback != "" {
		return fallback
	}
	return "inline"
}

// externalizeDataURIs finds data: URLs in HTML, uploads them to media, and rewrites to mxc URLs.
// Returns (rewrittenHTML, replaced, failed)
func (e *EmailMatrixEvent) externalizeDataURIs(ctx context.Context, intent bridgev2.MatrixAPI, html string) (string, int, int) {
	out := html
	reDataImg := regexp.MustCompile(`(?i)(src\s*=\s*)(['"])\s*data:([a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+);base64,([a-z0-9+/=]+)\s*\2`)
	reDataCSS := regexp.MustCompile(`(?i)url\(\s*data:([a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+);base64,([a-z0-9+/=]+)\s*\)`)
	replaced := 0
	failed := 0
	// Replace <img src="data:...">
	out = reDataImg.ReplaceAllStringFunc(out, func(m string) string {
		subs := reDataImg.FindStringSubmatch(m)
		if len(subs) < 5 { return m }
		attr := subs[1]
		quote := subs[2]
		mimeType := strings.ToLower(subs[3])
		b64 := subs[4]
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			failed++
			return m
		}
		if e.processor.MaxUploadBytes > 0 && len(data) > e.processor.MaxUploadBytes {
			failed++
			return m
		}
		name := "inline"
		if strings.HasPrefix(mimeType, "image/") {
			name = "inline." + strings.TrimPrefix(mimeType, "image/")
		}
		mxc, _, err := intent.UploadMedia(ctx, "", data, name, mimeType)
		if err != nil {
			failed++
			return m
		}
		replaced++
		return attr + quote + string(mxc) + quote
	})
	// Replace CSS url(data:...)
	out = reDataCSS.ReplaceAllStringFunc(out, func(m string) string {
		subs := reDataCSS.FindStringSubmatch(m)
		if len(subs) < 3 { return m }
		mimeType := strings.ToLower(subs[1])
		b64 := subs[2]
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			failed++
			return m
		}
		if e.processor.MaxUploadBytes > 0 && len(data) > e.processor.MaxUploadBytes {
			failed++
			return m
		}
		name := "inline"
		mxc, _, err := intent.UploadMedia(ctx, "", data, name, mimeType)
		if err != nil {
			failed++
			return m
		}
		replaced++
		return "url(" + string(mxc) + ")"
	})
return out, replaced, failed
}

// rewriteHTMLInline replaces cid: and content-location references with mxc urls
func rewriteHTMLInline(html string, cidToMXC map[string]string, locToMXC map[string]string) string {
	out := html
	// Replace cid: in img src and preserve the original quoting
	reImg, err := regexp.Compile(`(?i)(src\s*=\s*)(['"])\s*cid:([^'"\s)]+)`) 
	if err == nil {
		out = reImg.ReplaceAllStringFunc(out, func(m string) string {
			subs := reImg.FindStringSubmatch(m)
			if len(subs) > 3 {
				attr := subs[1]   // src=
				quote := subs[2]  // ' or "
				cidRef := subs[3]
				cid := normalizeCIDRef(cidRef)
				if mxc, ok := cidToMXC[cid]; ok && mxc != "" {
					return attr + quote + mxc + quote
				}
			}
			return m
		})
	}
	// Replace CSS url(cid:...)
	reCSS, err := regexp.Compile(`(?i)url\(\s*cid:([^) \t\r\n]+)\s*\)`) 
	if err == nil {
		out = reCSS.ReplaceAllStringFunc(out, func(m string) string {
			subs := reCSS.FindStringSubmatch(m)
			if len(subs) > 1 {
				cid := normalizeCIDRef(subs[1])
				if mxc, ok := cidToMXC[cid]; ok && mxc != "" {
					return "url(" + mxc + ")"
				}
			}
			return m
		})
	}
	// Replace content-location src references
	reLoc, err := regexp.Compile(`(?i)src\s*=\s*(['\"])([^'\"]+)(['\"])`)
	if err == nil {
		out = reLoc.ReplaceAllStringFunc(out, func(m string) string {
			subs := reLoc.FindStringSubmatch(m)
			if len(subs) > 3 {
				open := subs[1]
				val := subs[2]
				close := subs[3]
				// ensure matching quotes
				if open != close {
					return m
				}
				low := strings.ToLower(val)
				if strings.HasPrefix(low, "http:") || strings.HasPrefix(low, "https:") || strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "cid:") {
					return m
				}
				key := normalizeContentLocation(val)
				if mxc, ok := locToMXC[key]; ok && mxc != "" {
					return "src=" + open + mxc + close
				}
			}
			return m
		})
	}
return out
}

// lightMinifyHTML removes comments and collapses whitespace conservatively to preserve formatting fidelity.
func lightMinifyHTML(s string) string {
	before := len(s)
	s = removeHTMLComments(s)
	s = collapseWhitespace(s)
	_ = before // keep variable for potential future metrics
	return s
}

// simpleHTMLToText converts basic HTML into readable plaintext.
// It strips script/style, removes tags, collapses whitespace, and decodes common entities.
func simpleHTMLToText(s string) string {
	// Remove script and style blocks
	s = stripTagContent(s, "script")
	s = stripTagContent(s, "style")
	// Replace <br> and <p> with newlines to preserve structure
	reBR := regexp.MustCompile(`(?is)<\s*br\s*/?>`)
	s = reBR.ReplaceAllString(s, "\n")
	reP := regexp.MustCompile(`(?is)<\s*/?p\s*>`)
	s = reP.ReplaceAllString(s, "\n")
	// Strip remaining tags
	reTags := regexp.MustCompile(`(?is)<[^>]+>`) 
	s = reTags.ReplaceAllString(s, "")
	// Decode a few common HTML entities
	replacer := strings.NewReplacer(
		"&nbsp;", " ",
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
	)
	s = replacer.Replace(s)
	// Collapse whitespace
	s = strings.TrimSpace(collapseWhitespace(s))
	return s
}

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

