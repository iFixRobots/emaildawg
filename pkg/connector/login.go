package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-emaildawg/pkg/imap"
)

// EmailLoginProcess represents the email login flow
type EmailLoginProcess struct {
	user       *bridgev2.User
	email      string
	username   string
	password   string
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
			},
		},
	}, nil
}

// buildLoginInstructions creates helpful login instructions based on common email providers
func (elp *EmailLoginProcess) buildLoginInstructions() string {
	return `🔐 **Email Bridge Login**

**Quick Setup:**
• Just enter your email address and password
• The bridge will automatically detect your email provider settings
• For Gmail/Yahoo/Outlook: Use an **App Password** (not your regular password)

**Popular Providers Supported:**
✅ Gmail (gmail.com) - Auto-configured
✅ Yahoo (yahoo.com) - Auto-configured  
✅ Outlook/Hotmail (outlook.com, hotmail.com) - Auto-configured
✅ iCloud (icloud.com) - Auto-configured
✅ Custom IMAP servers - Auto-detected

**App Password Setup:**
📱 **Gmail:** Settings → Security → 2-Step Verification → App passwords
📱 **Yahoo:** Account Info → Account security → Generate app password
📱 **Outlook:** Security → Sign-in options → App passwords

*The bridge will test your connection automatically!*`
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
			elp.password = value
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
	
	// Test IMAP connection with helpful error messages
	if err := elp.testIMAPConnection(ctx); err != nil {
		// Provide provider-specific troubleshooting
		errorMsg := elp.buildConnectionErrorMessage(err, providerInfo)
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Create new user login using the bridgev2 pattern
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

	// Save credentials to database
	if err := elp.saveAccount(ctx); err != nil {
		return nil, fmt.Errorf("failed to save account: %w", err)
	}

	// The IMAP monitoring will be started when the client connects
	// via the LoadUserLogin -> Connect flow

	return &bridgev2.LoginStep{
		Type:           bridgev2.LoginStepTypeComplete,
		StepID:         "complete",
		Instructions:   fmt.Sprintf("Successfully logged in as %s", elp.email),
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: userLogin.ID,
			UserLogin:   userLogin,
		},
	}, nil
}

// EmailUserLogin represents a logged-in email account
type EmailUserLogin struct {
	UserLogin *bridgev2.UserLogin
	Email     string
	Password  string
	IMAPHost  string
	IMAPPort  int
	TLS       bool
}

func (eul *EmailUserLogin) Connect(ctx context.Context) error {
	// Connection is handled by the IMAP manager
	return ConnectorInstance.IMAPManager.AddAccount(eul.UserLogin, eul.Email, eul.Email, eul.Password)
}

func (eul *EmailUserLogin) Disconnect() {
	// Disconnection is handled by the IMAP manager
	ConnectorInstance.IMAPManager.RemoveAccount(eul.UserLogin.UserMXID.String(), eul.Email)
}

func (eul *EmailUserLogin) IsLoggedIn() bool {
	// Check if account is active in IMAP manager
	statuses := ConnectorInstance.IMAPManager.GetAccountStatus(eul.UserLogin.UserMXID.String())
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

// testIMAPConnection tests the IMAP connection with provided credentials
func (elp *EmailLoginProcess) testIMAPConnection(ctx context.Context) error {
	// Create a temporary logger for testing (NO PASSWORDS LOGGED)
	logger := ConnectorInstance.Bridge.Log.With().
		Str("component", "login_test").
		Str("email", elp.email).
		Str("host_detected", strings.Split(elp.email, "@")[1]).
		Logger()

	// Create test IMAP client without UserLogin (just for testing connection)
	client, err := imap.NewClient(elp.email, elp.username, elp.password, nil, &logger)
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

	logger.Info().Msg("IMAP connection test successful")
	return nil
}

// saveAccount saves the email account credentials to database
func (elp *EmailLoginProcess) saveAccount(ctx context.Context) error {
	// Auto-detect provider settings for saving
	domain := strings.ToLower(strings.Split(elp.email, "@")[1])
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

	return ConnectorInstance.DB.UpsertAccount(ctx, account)
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
	
	// Generic connection error
	return fmt.Sprintf(`❌ **Connection to %s Failed**

**Possible causes:**
• Network connectivity issues
• Firewall blocking IMAP connections
• Email provider server temporarily unavailable
• Incorrect IMAP server settings (auto-detection failed)

**Please try:**
✓ Check your internet connection
✓ Try again in a few minutes
✓ Contact your email provider if the issue persists

**Original Error:** %v`,
		provider.Name, err)
}

// IMAP monitoring is now handled by the EmailClient in client.go
