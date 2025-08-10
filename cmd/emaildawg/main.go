package main

import (
	_ "github.com/mattn/go-sqlite3"
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"

	"github.com/iFixRobots/emaildawg/pkg/connector"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var c = &connector.EmailConnector{}
var m = mxmain.BridgeMain{
	Name:        "emaildawg",
	URL:         "https://github.com/iFixRobots/emaildawg",
	Description: "A Matrix-Email puppeting bridge.",
	Version:     "0.1.0",
	Connector:   c,
}

func main() {
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
