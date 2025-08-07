# Makefile for mautrix-emaildawg bridge

# Detect platform
UNAME_S := $(shell uname -s)

# Auto-detect libolm paths
ifeq ($(UNAME_S),Darwin)
	# Try multiple possible locations on macOS
	LIBOLM_PREFIX := $(shell brew --prefix libolm 2>/dev/null || ([ -d /opt/homebrew/opt/libolm ] && echo "/opt/homebrew/opt/libolm") || ([ -d /usr/local/opt/libolm ] && echo "/usr/local/opt/libolm") || echo "")
	ifneq ($(LIBOLM_PREFIX),)
		CGO_CFLAGS := -I$(LIBOLM_PREFIX)/include
		CGO_LDFLAGS := -L$(LIBOLM_PREFIX)/lib
	else
		$(error libolm not found. Please install with: brew install libolm)
	endif
endif

ifeq ($(UNAME_S),Linux)
	# Check for libolm on Linux
	ifneq ($(wildcard /usr/include/olm/olm.h),)
		CGO_CFLAGS := -I/usr/include/olm
		CGO_LDFLAGS := -L/usr/lib
	else ifneq ($(wildcard /usr/local/include/olm/olm.h),)
		CGO_CFLAGS := -I/usr/local/include/olm
		CGO_LDFLAGS := -L/usr/local/lib
	else
		$(error libolm not found. Please install libolm-dev package)
	endif
endif

# Build targets
.PHONY: build clean install test

build:
	CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" go build -o mautrix-emaildawg ./cmd/mautrix-emaildawg

clean:
	rm -f mautrix-emaildawg

install: build
	install -m 755 mautrix-emaildawg /usr/local/bin/

test:
	CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" go test ./...

# Development targets
dev-deps:
ifeq ($(UNAME_S),Darwin)
	@echo "Installing dependencies on macOS..."
	brew install libolm
endif
ifeq ($(UNAME_S),Linux)
	@echo "On Linux, please install libolm-dev package:"
	@echo "  Ubuntu/Debian: sudo apt install libolm-dev"
	@echo "  Fedora: sudo dnf install libolm-devel"
	@echo "  Arch: sudo pacman -S libolm"
endif

run-example: build
	./mautrix-emaildawg --help

.DEFAULT_GOAL := build
