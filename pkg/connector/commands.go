package connector

import (
	"context"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"go.mau.fi/mautrix-emaildawg/pkg/imap"
)

var (
	HelpSectionAuth = commands.HelpSection{Name: "Authentication", Order: 10}
	HelpSectionInfo = commands.HelpSection{Name: "Information", Order: 5}
	HelpSectionAdmin = commands.HelpSection{Name: "Administration", Order: 15}

	CommandPing = &commands.FullHandler{
		Func: fnPing,
		Name: "ping",
		Help: commands.HelpMeta{
			Section:     HelpSectionInfo,
			Description: "Check if the bridge is alive",
		},
	}

	CommandStatus = &commands.FullHandler{
		Func: fnStatus,
		Name: "status",
		Help: commands.HelpMeta{
			Section:     HelpSectionInfo,
			Description: "Show bridge and connection status including health, sync status, and recent activity",
		},
	}

	CommandLogin = &commands.FullHandler{
		Func: fnLogin,
		Name: "login",
		Help: commands.HelpMeta{
			Section:     HelpSectionAuth,
			Description: "Connect to an email account with interactive login process",
			Args:        "[<email address>]",
		},
	}

	CommandLogout = &commands.FullHandler{
		Func: fnLogout,
		Name: "logout",
		Help: commands.HelpMeta{
			Section:     HelpSectionAuth,
			Description: "Disconnect from a specific email account or all accounts",
			Args:        "[<email address>]",
		},
		RequiresLogin: true,
	}

	CommandList = &commands.FullHandler{
		Func: fnList,
		Name: "list",
		Help: commands.HelpMeta{
			Section:     HelpSectionAuth,
			Description: "List connected email accounts",
		},
		RequiresLogin: true,
	}

	CommandSync = &commands.FullHandler{
		Func: fnSync,
		Name: "sync",
		Help: commands.HelpMeta{
			Section:     HelpSectionAdmin,
			Description: "Force sync emails from server",
			Args:        "[account]",
		},
		RequiresLogin: true,
	}

	CommandReconnect = &commands.FullHandler{
		Func: fnReconnect,
		Name: "reconnect",
		Help: commands.HelpMeta{
			Section:     HelpSectionAdmin,
			Description: "Reconnect to IMAP server for a specific account",
			Args:        "[<email address>]",
		},
		RequiresLogin: true,
	}
)

func fnPing(ce *commands.Event) {
	ce.Reply("🏓 **Pong!** The EmailDawg bridge is alive and running.")
}

func fnStatus(ce *commands.Event) {
	logins := ce.User.GetUserLogins()
	
	if len(logins) == 0 {
		ce.Reply(`
📊 **EmailDawg Bridge Status**

ℹ️ **Connection Status:** Not connected
🔌 **Email Accounts:** 0
🏠 **Matrix Rooms:** 0 email rooms

🎆 **Bridge is ready!** Use ` + "`!email login`" + ` to connect your first email account.
`)
		return
	}

	// Get real account status from IMAP manager
	if ConnectorInstance == nil || ConnectorInstance.IMAPManager == nil {
		ce.Reply("⚠️ **Bridge Error:** IMAP manager not initialized")
		return
	}

	accountStatuses := ConnectorInstance.IMAPManager.GetAccountStatus(ce.User.MXID.String())
	
	if len(accountStatuses) == 0 {
		ce.Reply(`
📊 **EmailDawg Bridge Status**

ℹ️ **Connection Status:** No active email connections
🔌 **Email Accounts:** 0 monitoring
🏠 **Matrix Rooms:** 0 email rooms

💡 **Note:** You have bridge login(s) but no active IMAP connections. Use ` + "`!email login`" + ` to add email accounts.
`)
		return
	}

	// Build status report
	statusMsg := `
📊 **EmailDawg Bridge Status**

`

	connectedCount := 0
	idleCount := 0

	for _, status := range accountStatuses {
		if status.Connected {
			connectedCount++
		}
		if status.IDLEActive {
			idleCount++
		}

		var statusIcon string
		var statusText string

		if status.Connected && status.IDLEActive {
			statusIcon = "✅"
			statusText = "Connected, monitoring"
		} else if status.Connected {
			statusIcon = "🔄"
			statusText = "Connected, starting monitoring"
		} else {
			statusIcon = "❌"
			statusText = "Disconnected"
		}

		statusMsg += fmt.Sprintf("📧 %s **%s** (%s:%d) - %s\n", statusIcon, status.Email, status.Host, status.Port, statusText)
	}

	statusMsg += fmt.Sprintf(`
**Summary:**
🔌 **Email Accounts:** %d total, %d connected
🔄 **Real-time Monitoring:** %d active IMAP IDLE sessions
🏠 **Matrix Rooms:** Calculating...

`, len(accountStatuses), connectedCount, idleCount)

	if connectedCount == len(accountStatuses) && idleCount == len(accountStatuses) {
		statusMsg += "✅ **All systems operational!** Your emails are being monitored in real-time."
	} else if connectedCount > 0 {
		statusMsg += "⚠️ **Partial connectivity** - Some accounts may need attention."
	} else {
		statusMsg += "❌ **No active connections** - Use `!email login` to reconnect."
	}

	ce.Reply(statusMsg)
}

func fnLogin(ce *commands.Event) {
	// Check if user has any active logins
	logins := ce.User.GetUserLogins()
	if len(logins) > 0 {
		ce.Reply("✅ You're already logged into %d email account(s). Use `!email list` to see them, or `!email logout` to disconnect.", len(logins))
		return
	}

	// Start the interactive login process
	ce.Reply("📧 Starting email login process...")
	
	// Trigger the bridgev2 login flow
	// The user will be guided through the login process via the bridge bot
	ce.Reply(`✨ **EmailDawg Login**

🔐 Use the bridge manager to start the login process:
` + "`!login`" + `

The bridge will guide you through:
1. 📧 **Email Address** - Enter your email (e.g., user@gmail.com)
2. 👤 **Username** - Usually same as email (for most providers)
3. 🔒 **Password** - Your email password or app password
4. 🧪 **Connection Test** - Bridge will test the IMAP connection
5. ✅ **Success** - Real-time email monitoring will begin!

💡 **Important Notes:**
• **Gmail**: Requires App Password (not regular password)
• **Yahoo**: Requires App Password for IMAP access
• **Outlook**: May require App Password if 2FA enabled
• **Custom domains**: May need separate username

Once connected, all your email threads will appear as Matrix rooms! 🎉`)
}

func fnLogout(ce *commands.Event) {
	// Check if user has any active logins
	logins := ce.User.GetUserLogins()
	if len(logins) == 0 {
		ce.Reply("ℹ️ You're not connected to any email accounts. Use `!email login` to get started.")
		return
	}

	// Check if user specified an email to logout from
	if len(ce.Args) > 0 {
		emailAddr := ce.Args[0]
		ce.Reply("🔌 Disconnecting from **%s**...", emailAddr)
		
		// Find the specific login for this email
		var targetLogin *bridgev2.UserLogin
		for _, login := range logins {
			if client, ok := login.Client.(*EmailClient); ok && client.Email == emailAddr {
				targetLogin = login
				break
			}
		}
		
		if targetLogin == nil {
			ce.Reply("❌ Email account **%s** not found in your connected accounts.", emailAddr)
			return
		}
		
		// Use LogoutRemote for proper cleanup
		ctx := context.Background()
		if client, ok := targetLogin.Client.(*EmailClient); ok {
			client.LogoutRemote(ctx)
			ce.Reply("✅ Successfully disconnected from **%s**", emailAddr)
		} else {
			ce.Reply("❌ Failed to disconnect from **%s**: invalid client type", emailAddr)
		}
		return
	}

	// Logout all accounts
	ce.Reply("🔌 Disconnecting from all %d email account(s)...", len(logins))
	
	// Use LogoutRemote for each login for proper cleanup
	ctx := context.Background()
	var failures []string
	
	for _, login := range logins {
		if client, ok := login.Client.(*EmailClient); ok {
			try := func() {
				client.LogoutRemote(ctx)
			}
			
			// Use a simple panic recovery to catch any logout failures
			func() {
				defer func() {
					if r := recover(); r != nil {
						failures = append(failures, fmt.Sprintf("LogoutRemote for %s: panic %v", client.Email, r))
					}
				}()
				try()
			}()
		} else {
			failures = append(failures, fmt.Sprintf("Invalid client type for login %s", login.ID))
		}
	}
	
	if len(failures) == 0 {
		ce.Reply("✅ Successfully disconnected from all email accounts.")
	} else {
		ce.Reply("⚠️ Logout completed with some issues:\n• %s", strings.Join(failures, "\n• "))
	}
}

func fnList(ce *commands.Event) {
	// Check if user has any active logins
	logins := ce.User.GetUserLogins()
	if len(logins) == 0 {
		ce.Reply(`
📭 **No email accounts connected**

To get started:
1. Use ` + "`!email login`" + ` to connect your first email account
2. The bridge supports Gmail, Outlook, Yahoo, FastMail, and custom IMAP servers
3. Once connected, new emails will automatically create Matrix rooms

Need help? Use ` + "`!email help`" + ` for more information.
`)
		return
	}

	// Get real account list from database
	ctx := context.Background()
	accounts, err := ConnectorInstance.DB.GetUserAccounts(ctx, ce.User.MXID.String())
	if err != nil {
		ce.Reply("❌ Failed to get account list: %s", err.Error())
		return
	}
	
	if len(accounts) == 0 {
		ce.Reply("📭 No email accounts found in database. Use `!email login` to add one.")
		return
	}
	
	// Get account status from IMAP manager
	statusMap := make(map[string]imap.AccountStatus)
	statuses := ConnectorInstance.IMAPManager.GetAccountStatus(ce.User.MXID.String())
	for _, status := range statuses {
		statusMap[status.Email] = status
	}
	
	// Build response
	response := fmt.Sprintf("📧 **Connected Email Accounts:** %d\n\n", len(accounts))
	
	for _, account := range accounts {
		status, hasStatus := statusMap[account.Email]
		
		var statusIcon string
		var statusText string
		var provider string
		
		// Determine provider name
		domain := strings.ToLower(strings.Split(account.Email, "@")[1])
		if p, ok := imap.CommonProviders[domain]; ok {
			provider = p.Name
		} else {
			provider = "Custom IMAP"
		}
		
		if hasStatus {
			if status.Connected && status.IDLEActive {
				statusIcon = "✅"
				statusText = "Connected, monitoring"
			} else if status.Connected {
				statusIcon = "🔄"
				statusText = "Connected, starting monitoring"
			} else {
				statusIcon = "❌"
				statusText = "Disconnected"
			}
		} else {
			statusIcon = "⚠️"
			statusText = "Status unknown"
		}
		
		response += fmt.Sprintf("• %s **%s** (%s) - %s\n", statusIcon, account.Email, provider, statusText)
		if hasStatus && status.Host != "" {
			response += fmt.Sprintf("   📡 %s:%d\n", status.Host, status.Port)
		}
		response += fmt.Sprintf("   🕒 Added: %s\n\n", account.CreatedAt.Format("Jan 2, 2006"))
	}
	
	response += "💡 Use `!email logout <email>` to remove a specific account."
	ce.Reply(response)
}

func fnSync(ce *commands.Event) {
	// Get user's logins
	logins := ce.User.GetUserLogins()
	if len(logins) == 0 {
		ce.Reply("ℹ️ You're not connected to any email accounts. Use `!email login` to get started.")
		return
	}

	// If specific account provided, sync only that one
	if len(ce.Args) > 0 {
		emailAddr := ce.Args[0]
		var targetLogin *bridgev2.UserLogin
		for _, login := range logins {
			if client, ok := login.Client.(*EmailClient); ok && client.Email == emailAddr {
				targetLogin = login
				break
			}
		}

		if targetLogin == nil {
			ce.Reply("❌ Email account **%s** not found in your connected accounts.", emailAddr)
			return
		}

		ce.Reply("🔄 Forcing sync for **%s**...", emailAddr)
		if client, ok := targetLogin.Client.(*EmailClient); ok {
			if client.IMAPClient != nil && client.IMAPClient.IsConnected() {
				if err := client.IMAPClient.CheckNewMessages(); err != nil {
					ce.Reply("❌ Sync failed for **%s**: %s", emailAddr, err.Error())
					return
				}
				ce.Reply("✅ Sync completed for **%s**", emailAddr)
			} else {
				ce.Reply("⚠️ **%s** is not connected to IMAP server", emailAddr)
			}
		}
		return
	}

	// Sync all accounts
	ce.Reply("🔄 Forcing sync for all %d email account(s)...", len(logins))
	var successes []string
	var failures []string

	for _, login := range logins {
		if client, ok := login.Client.(*EmailClient); ok {
			if client.IMAPClient != nil && client.IMAPClient.IsConnected() {
				if err := client.IMAPClient.CheckNewMessages(); err != nil {
					failures = append(failures, fmt.Sprintf("%s: %s", client.Email, err.Error()))
				} else {
					successes = append(successes, client.Email)
				}
			} else {
				failures = append(failures, fmt.Sprintf("%s: not connected", client.Email))
			}
		}
	}

	var result strings.Builder
	if len(successes) > 0 {
		result.WriteString(fmt.Sprintf("✅ Successfully synced: %s\n", strings.Join(successes, ", ")))
	}
	if len(failures) > 0 {
		result.WriteString(fmt.Sprintf("❌ Failed to sync: %s", strings.Join(failures, "; ")))
	}

	ce.Reply(result.String())
}

func fnReconnect(ce *commands.Event) {
	// Get user's logins
	logins := ce.User.GetUserLogins()
	if len(logins) == 0 {
		ce.Reply("ℹ️ You're not connected to any email accounts. Use `!email login` to get started.")
		return
	}

	// If specific account provided, reconnect only that one
	if len(ce.Args) > 0 {
		emailAddr := ce.Args[0]
		var targetLogin *bridgev2.UserLogin
		for _, login := range logins {
			if client, ok := login.Client.(*EmailClient); ok && client.Email == emailAddr {
				targetLogin = login
				break
			}
		}

		if targetLogin == nil {
			ce.Reply("❌ Email account **%s** not found in your connected accounts.", emailAddr)
			return
		}

		ce.Reply("🔌 Reconnecting **%s**...", emailAddr)
		if client, ok := targetLogin.Client.(*EmailClient); ok {
			if client.IMAPClient != nil {
				// Disconnect first
				client.IMAPClient.Disconnect()
				// Reconnect
				if err := client.IMAPClient.Connect(); err != nil {
					ce.Reply("❌ Reconnection failed for **%s**: %s", emailAddr, err.Error())
					return
				}
				// Restart IDLE
				if err := client.IMAPClient.StartIDLE(); err != nil {
					ce.Reply("⚠️ Reconnected **%s** but IDLE failed to start: %s", emailAddr, err.Error())
				} else {
					ce.Reply("✅ Successfully reconnected **%s**", emailAddr)
				}
			} else {
				ce.Reply("❌ No IMAP client found for **%s**", emailAddr)
			}
		}
		return
	}

	// Reconnect all accounts
	ce.Reply("🔌 Reconnecting all %d email account(s)...", len(logins))
	var successes []string
	var failures []string

	for _, login := range logins {
		if client, ok := login.Client.(*EmailClient); ok && client.IMAPClient != nil {
			// Disconnect first
			client.IMAPClient.Disconnect()
			// Reconnect
			if err := client.IMAPClient.Connect(); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %s", client.Email, err.Error()))
				continue
			}
			// Restart IDLE
			if err := client.IMAPClient.StartIDLE(); err != nil {
				failures = append(failures, fmt.Sprintf("%s: IDLE failed - %s", client.Email, err.Error()))
			} else {
				successes = append(successes, client.Email)
			}
		}
	}

	var result strings.Builder
	if len(successes) > 0 {
		result.WriteString(fmt.Sprintf("✅ Successfully reconnected: %s\n", strings.Join(successes, ", ")))
	}
	if len(failures) > 0 {
		result.WriteString(fmt.Sprintf("❌ Failed to reconnect: %s", strings.Join(failures, "; ")))
	}

	ce.Reply(result.String())
}
