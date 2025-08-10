#!/bin/sh
set -euo pipefail
MAUTRIX_VERSION=$(grep -E '^\s*maunium.net/go/mautrix\s' go.mod | awk '{ print $$2 }')
TAG=$(git describe --exact-match --tags 2>/dev/null || echo unknown)
COMMIT=$(git rev-parse HEAD)
BUILD_TIME=$(date -Iseconds)
GO_LDFLAGS="-s -w -X main.Tag=$TAG -X main.Commit=$COMMIT -X main.BuildTime=$BUILD_TIME -X maunium.net/go/mautrix.GoModVersion=$MAUTRIX_VERSION"
go build -ldflags="$GO_LDFLAGS" "$@" ./cmd/emaildawg
