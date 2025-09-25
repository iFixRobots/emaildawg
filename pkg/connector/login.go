package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/iFixRobots/emaildawg/pkg/imap"
)

// EmailLoginProcess represents the email login flow
type EmailLoginProcess struct {
	user        *bridgev2.User
	connector   *EmailConnector
	email       string
	username    string
	password    string
	imapHost    string
	imapPort    int
	imapPortSet bool
}

var (
	_ bridgev2.LoginProcess          = (*EmailLoginProcess)(nil)
	_ bridgev2.LoginProcessUserInput = (*EmailLoginProcess)(nil)
)

// EmailLoginMetadata contains email-specific login metadata
type EmailLoginMetadata struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

// Start begins the login process
func (elp *EmailLoginProcess) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       "credentials",
		Instructions: elp.buildLoginInstructions(),
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{
				{
					Type:        bridgev2.LoginInputFieldTypeEmail,
					ID:          "email",
					Name:        "Email Address",
					Description: "Your full email address",
				},
				{
					Type:        bridgev2.LoginInputFieldTypePassword,
					ID:          "password",
					Name:        "Password",
					Description: "Your email password or App Password",
				},
				{
					Type:        bridgev2.LoginInputFieldTypeDomain,
					ID:          "imap_host",
					Name:        "IMAP Server (optional)",
					Description: "Override auto-detected server, e.g. imap.gmail.com",
				},
			},
		},
	}, nil
}

// buildLoginInstructions creates helpful login instructions based on common email providers
func (elp *EmailLoginProcess) buildLoginInstructions() string {
	return `**Email Bridge Login**

📧 **Please enter your email credentials using the form fields below.**

**Important Notes:**
• For Gmail/Yahoo/Outlook: Use an **App Password** (not your regular password)
• The bridge will automatically detect your email provider settings
• Custom domains using hosted email (e.g. Google Workspace) can set the IMAP hostname manually
• Your password will be encrypted and stored securely

**App Password Setup Guide:**
📱 **Gmail:** Settings → Security → 2-Step Verification → App passwords
📱 **Yahoo:** Account Info → Account security → Generate app password  
📱 **Outlook:** Security → Sign-in options → App passwords
📱 **iCloud:** Sign-In and Security → App-Specific Passwords

**Popular Providers Supported:**
Gmail, Yahoo, Outlook, iCloud, FastMail - Auto-configured
Custom IMAP servers - Auto-detected or manually specified via the optional IMAP Server field

*The bridge will test your IMAP connection automatically after you submit your credentials.*

**Need help?** Use ` + "`!email help`" + ` for more information or ` + "`!email status`" + ` to check connection status.`
}

// Cancel cancels the login process
func (elp *EmailLoginProcess) Cancel() {
	// Nothing to clean up for now
}

// SubmitUserInput handles a login step submission
func (elp *EmailLoginProcess) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	// Extract credentials from user input data
	for key, value := range input {
		switch key {
		case "email":
			elp.email = strings.TrimSpace(value)
		case "password":
			elp.password = strings.TrimSpace(value)
		case "imap_host":
			if err := elp.setIMAPServer(value); err != nil {
				return nil, err
			}
		}
	}

	// Set username to email if not provided separately
	if elp.username == "" {
		elp.username = elp.email
	}

	// Validate required fields
	if elp.email == "" {
		return nil, fmt.Errorf("email address is required")
	}
	if elp.password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Detect email provider and give specific guidance
	providerInfo := elp.detectEmailProvider()

	// Show provider detection results to user
	if providerInfo != nil && providerInfo.Name != "Custom Provider" {
		// Known provider detected
		elp.connector.Bridge.Log.Info().
			Str("provider", providerInfo.Name).
			Str("domain", providerInfo.Domain).
			Msg("Known provider detected, using optimized settings")
	} else {
		// Unknown provider - using auto-detection fallback
		parts := strings.Split(elp.email, "@")
		if len(parts) == 2 {
			domain := parts[1]
			fallbackHost := fmt.Sprintf("imap.%s", domain)
			if elp.imapHost != "" {
				fallbackHost = elp.imapHost
			}
			elp.connector.Bridge.Log.Info().
				Str("domain", domain).
				Str("fallback_host", fallbackHost).
				Msg("Unknown provider detected, attempting auto-detection")
		}
	}

	// Test IMAP connection with helpful error messages
	if err := elp.testIMAPConnection(ctx); err != nil {
		// Provide provider-specific troubleshooting
		errorMsg := elp.buildConnectionErrorMessage(err, providerInfo)
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Save credentials to database FIRST (before creating user login)
	// This ensures LoadUserLogin can find the account when it's called
	if err := elp.saveAccount(ctx); err != nil {
		return nil, fmt.Errorf("failed to save account: %w", err)
	}

	// Create new user login using the bridgev2 pattern
	// This will trigger LoadUserLogin which needs the account to exist in DB
	userLoginID := networkid.UserLoginID(fmt.Sprintf("email:%s", elp.email))
	userLogin, err := elp.user.NewLogin(ctx, &database.UserLogin{
		ID:         userLoginID,
		RemoteName: elp.email,
		Metadata: &EmailLoginMetadata{
			Email:    elp.email,
			Username: elp.username,
		},
	}, &bridgev2.NewLoginParams{
		DeleteOnConflict: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user login: %w", err)
	}

	// The IMAP monitoring will be started when the client connects
	// via the LoadUserLogin -> Connect flow

	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "complete",
		Instructions: fmt.Sprintf("Successfully logged in as %s", elp.email),
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: userLogin.ID,
			UserLogin:   userLogin,
		},
	}, nil
}

// EmailUserLogin represents a logged-in email account
type EmailUserLogin struct {
	UserLogin *bridgev2.UserLogin
	connector *EmailConnector
	Email     string
	Password  string
	IMAPHost  string
	IMAPPort  int
	TLS       bool
}

func (eul *EmailUserLogin) Connect(ctx context.Context) error {
	// Connection is handled by the IMAP manager
	return eul.connector.IMAPManager.AddAccount(eul.UserLogin, eul.Email, eul.Email, eul.Password)
}

func (eul *EmailUserLogin) Disconnect() {
	// Disconnection is handled by the IMAP manager
	eul.connector.IMAPManager.RemoveAccount(eul.UserLogin.UserMXID.String(), eul.Email)
}

func (eul *EmailUserLogin) IsLoggedIn() bool {
	// Check if account is active in IMAP manager
	statuses := eul.connector.IMAPManager.GetAccountStatus(eul.UserLogin.UserMXID.String())
	for _, status := range statuses {
		if status.Email == eul.Email {
			return status.Connected
		}
	}
	return false
}

func (eul *EmailUserLogin) GetRemoteID() networkid.UserLoginID {
	return networkid.UserLoginID(fmt.Sprintf("email:%s", eul.Email))
}

func (eul *EmailUserLogin) GetRemoteName() string {
	return eul.Email
}

func (elp *EmailLoginProcess) setIMAPServer(input string) error {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		elp.imapHost = ""
		elp.imapPort = 0
		elp.imapPortSet = false
		return nil
	}

	sanitized := strings.TrimSpace(trimmed)
	sanitized = strings.TrimPrefix(sanitized, "imaps://")
	sanitized = strings.TrimPrefix(sanitized, "imap://")
	sanitized = strings.TrimPrefix(sanitized, "https://")
	sanitized = strings.TrimPrefix(sanitized, "http://")
	sanitized = strings.TrimSuffix(sanitized, "/")

	host := sanitized
	port := 0
	portSet := false

	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		closing := strings.Index(host, "]")
		if closing == -1 {
			return fmt.Errorf("invalid IMAP server override: %s", input)
		}
		base := strings.TrimSpace(host[1:closing])
		rest := strings.TrimSpace(host[closing+1:])
		host = base
		if strings.HasPrefix(rest, ":") {
			portPart := strings.TrimSpace(rest[1:])
			if portPart != "" {
				parsed, err := strconv.Atoi(portPart)
				if err != nil || parsed <= 0 || parsed > 65535 {
					return fmt.Errorf("invalid IMAP server port: %s", portPart)
				}
				port = parsed
				portSet = true
			}
		} else if rest != "" {
			return fmt.Errorf("invalid IMAP server override: %s", input)
		}
	} else {
		colonCount := strings.Count(host, ":")
		if colonCount == 1 {
			idx := strings.LastIndex(host, ":")
			portPart := strings.TrimSpace(host[idx+1:])
			hostPart := strings.TrimSpace(host[:idx])
			if hostPart == "" {
				return fmt.Errorf("IMAP server override must include a hostname")
			}
			parsed, err := strconv.Atoi(portPart)
			if err != nil || parsed <= 0 || parsed > 65535 {
				return fmt.Errorf("invalid IMAP server port: %s", portPart)
			}
			host = hostPart
			port = parsed
			portSet = true
		} else if colonCount > 1 {
			// Assume IPv6 literal without port; keep host as-is.
		}
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("IMAP server override must include a hostname")
	}
	if strings.Contains(host, " ") || strings.Contains(host, "/") {
		return fmt.Errorf("IMAP server hostname cannot contain spaces or paths")
	}

	elp.imapHost = host
	if portSet {
		elp.imapPort = port
		elp.imapPortSet = true
	} else {
		elp.imapPort = 0
		elp.imapPortSet = false
	}

	return nil
}

func (elp *EmailLoginProcess) connectionOverrides() *imap.ConnectionOverrides {
	if elp.imapHost == "" && !elp.imapPortSet {
		return nil
	}

	overrides := &imap.ConnectionOverrides{}
	if elp.imapHost != "" {
		overrides.Host = elp.imapHost
	}
	if elp.imapPortSet && elp.imapPort > 0 {
		overrides.Port = elp.imapPort
	}

	if overrides.Host == "" && overrides.Port == 0 {
		return nil
	}

	return overrides
}

// testIMAPConnection tests the IMAP connection with provided credentials
func (elp *EmailLoginProcess) testIMAPConnection(ctx context.Context) error {
	// Keep ctx parameter used to satisfy linters even if not currently leveraged here.
	_ = ctx
	// Create a temporary logger for testing (NO PASSWORDS LOGGED)
	logger := elp.connector.Bridge.Log.With().
		Str("component", "login_test").
		Str("email", elp.email)

	// Safely extract domain for logging
	if parts := strings.Split(elp.email, "@"); len(parts) == 2 {
		logger = logger.Str("host_detected", parts[1])
	}

	finalLogger := logger.Logger()

	// Create test IMAP client without UserLogin (just for testing connection)
	client, err := imap.NewClient(elp.email, elp.username, elp.password, elp.connectionOverrides(), nil, &finalLogger, elp.connector.Config.Logging.Sanitized, elp.connector.Config.Logging.PseudonymSecret, elp.connector.Config.Network.IMAP.StartupBackfillSeconds, elp.connector.Config.Network.IMAP.StartupBackfillMax, elp.connector.Config.Network.IMAP.InitialIdleTimeoutSeconds, nil)
	if err != nil {
		return fmt.Errorf("failed to create IMAP client: %w", err)
	}

	// Test connection
	err = client.Connect()
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	// Clean up test connection
	client.Disconnect()

	finalLogger.Info().Msg("IMAP connection test successful")
	return nil
}

// saveAccount saves the email account credentials to database
func (elp *EmailLoginProcess) saveAccount(ctx context.Context) error {
	logger := elp.connector.Bridge.Log.With().
		Str("component", "login_save").
		Str("email", elp.email).
		Logger()

	logger.Info().Msg("Saving account credentials to database")

	// Auto-detect provider settings for saving
	parts := strings.Split(elp.email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format: %s", elp.email)
	}
	domain := strings.ToLower(parts[1])
	var host string
	var port int
	var tls bool

	if provider, ok := imap.CommonProviders[domain]; ok {
		host = provider.Host
		port = provider.Port
		tls = provider.TLS
	} else {
		// Default IMAP settings
		host = fmt.Sprintf("imap.%s", domain)
		port = 993
		tls = true
	}

	if elp.imapHost != "" {
		host = elp.imapHost
	}

	if elp.imapPortSet && elp.imapPort > 0 {
		port = elp.imapPort
	} else if port == 0 {
		port = 993
	}

	host = strings.TrimSpace(host)

	account := &EmailAccount{
		UserMXID:     elp.user.MXID.String(),
		Email:        elp.email,
		Username:     elp.username,
		Password:     elp.password,
		Host:         host,
		Port:         port,
		TLS:          tls,
		CreatedAt:    time.Now(),
		LastSyncTime: time.Now(),
	}

	logger.Debug().Str("host", host).Int("port", port).Bool("tls", tls).Msg("Attempting to save account to database")

	if err := elp.connector.DB.UpsertAccount(ctx, account); err != nil {
		logger.Error().Err(err).Msg("Failed to save account credentials to database")
		return err
	}

	logger.Info().Msg("Successfully saved account credentials to database")
	return nil
}

// ProviderInfo contains information about an email provider
type ProviderInfo struct {
	Name        string
	Domain      string
	NeedsAppPwd bool
	HelpURL     string
}

// detectEmailProvider detects the email provider from the email address
func (elp *EmailLoginProcess) detectEmailProvider() *ProviderInfo {
	if elp.email == "" {
		return nil
	}

	parts := strings.Split(elp.email, "@")
	if len(parts) != 2 {
		return nil
	}

	domain := strings.ToLower(parts[1])

	switch domain {
	case "gmail.com", "googlemail.com":
		return &ProviderInfo{
			Name:        "Gmail",
			Domain:      domain,
			NeedsAppPwd: true,
			HelpURL:     "https://support.google.com/accounts/answer/185833",
		}
	case "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de":
		return &ProviderInfo{
			Name:        "Yahoo",
			Domain:      domain,
			NeedsAppPwd: true,
			HelpURL:     "https://help.yahoo.com/kb/generate-third-party-passwords-sln15241.html",
		}
	case "outlook.com", "hotmail.com", "live.com", "msn.com":
		return &ProviderInfo{
			Name:        "Outlook/Hotmail",
			Domain:      domain,
			NeedsAppPwd: true,
			HelpURL:     "https://support.microsoft.com/en-us/account-billing/using-app-passwords-with-apps-that-don-t-support-two-step-verification-5896ed9b-4263-e681-128a-a6f2979a7944",
		}
	case "icloud.com", "me.com", "mac.com":
		return &ProviderInfo{
			Name:        "iCloud",
			Domain:      domain,
			NeedsAppPwd: true,
			HelpURL:     "https://support.apple.com/en-us/HT204397",
		}
	default:
		if elp.imapHost != "" {
			switch strings.ToLower(elp.imapHost) {
			case "imap.gmail.com":
				return &ProviderInfo{
					Name:        "Gmail (custom domain)",
					Domain:      domain,
					NeedsAppPwd: true,
					HelpURL:     "https://support.google.com/accounts/answer/185833",
				}
			case "outlook.office365.com":
				return &ProviderInfo{
					Name:        "Outlook (custom domain)",
					Domain:      domain,
					NeedsAppPwd: true,
					HelpURL:     "https://support.microsoft.com/en-us/account-billing/using-app-passwords-with-apps-that-don-t-support-two-step-verification-5896ed9b-4263-e681-128a-a6f2979a7944",
				}
			case "imap.mail.yahoo.com":
				return &ProviderInfo{
					Name:        "Yahoo (custom domain)",
					Domain:      domain,
					NeedsAppPwd: true,
					HelpURL:     "https://help.yahoo.com/kb/generate-third-party-passwords-sln15241.html",
				}
			case "imap.mail.me.com":
				return &ProviderInfo{
					Name:        "iCloud (custom domain)",
					Domain:      domain,
					NeedsAppPwd: true,
					HelpURL:     "https://support.apple.com/en-us/HT204397",
				}
			case "imap.fastmail.com":
				return &ProviderInfo{
					Name:        "FastMail (custom domain)",
					Domain:      domain,
					NeedsAppPwd: false,
					HelpURL:     "https://www.fastmail.help/hc/en-us/articles/360058752754-App-passwords",
				}
			}
		}
		return &ProviderInfo{
			Name:        "Custom Provider",
			Domain:      domain,
			NeedsAppPwd: false,
			HelpURL:     "",
		}
	}
}

// buildConnectionErrorMessage creates a helpful error message based on the provider
func (elp *EmailLoginProcess) buildConnectionErrorMessage(err error, provider *ProviderInfo) string {
	baseError := fmt.Sprintf("Connection failed: %v", err)

	if provider == nil {
		return baseError
	}

	// Check for common authentication errors
	errorStr := strings.ToLower(err.Error())
	isAuthError := strings.Contains(errorStr, "authentication") ||
		strings.Contains(errorStr, "login") ||
		strings.Contains(errorStr, "password") ||
		strings.Contains(errorStr, "credentials")

	if isAuthError && provider.NeedsAppPwd {
		return fmt.Sprintf(`❌ **%s Login Failed**

**Most likely cause:** You need to use an **App Password** instead of your regular password.

**How to fix:**
1. Go to your %s security settings
2. Enable 2-Factor Authentication (if not already enabled)
3. Generate an App Password specifically for this email bridge
4. Use the App Password instead of your regular password

**Help Link:** %s

**Original Error:** %v`,
			provider.Name, provider.Name, provider.HelpURL, err)
	}

	if isAuthError {
		return fmt.Sprintf(`❌ **%s Login Failed**

**Possible causes:**
• Incorrect email address or password
• Two-factor authentication enabled (you may need an App Password)
• IMAP access disabled in your email settings
• Account temporarily locked

**Please double-check:**
✓ Email address is correct
✓ Password is correct (or use App Password if 2FA is enabled)
✓ IMAP is enabled in your %s settings

**Original Error:** %v`,
			provider.Name, provider.Name, err)
	}

	// Handle custom providers (auto-detection fallback) differently
	if provider.Name == "Custom Provider" {
		parts := strings.Split(elp.email, "@")
		domain := "your email provider"
		fallbackHost := "imap.domain.com"
		if len(parts) == 2 {
			domain = parts[1]
			fallbackHost = fmt.Sprintf("imap.%s", domain)
		}

		return fmt.Sprintf(`❌ **Connection Failed - Auto-Detection Used**

🔍 **We attempted to connect using:** %s:993

**This is an unknown email provider, so we used auto-detection.**

**Possible solutions:**

**1. Check with %s for correct IMAP settings:**
• IMAP server address (might not be %s)
• Port number (usually 993 or 143)
• Security settings (SSL/TLS)
• IMAP access needs to be enabled

**2. Common IMAP settings to try:**
• mail.%s:993 (SSL)
• %s:993 (SSL)  
• %s:143 (STARTTLS)

**3. If your provider uses non-standard settings:**
Contact your email administrator or check your provider's documentation

**Original Error:** %v`,
			fallbackHost, domain, fallbackHost, domain, fallbackHost, fallbackHost, err)
	}

	// Generic connection error for known providers
	return fmt.Sprintf(`❌ **Connection to %s Failed**

**Possible causes:**
• Network connectivity issues
• Firewall blocking IMAP connections
• Email provider server temporarily unavailable
• Account settings may need adjustment

**Please try:**
✓ Check your internet connection
✓ Verify IMAP is enabled in your %s account settings
✓ Try again in a few minutes
✓ Contact your email provider if the issue persists

**Original Error:** %v`,
		provider.Name, provider.Name, err)
}

// IMAP monitoring is now handled by the EmailClient in client.go
