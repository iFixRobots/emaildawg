# Makefile for mautrix-emaildawg bridge

# Detect platform
UNAME_S := $(shell uname -s)

# Set libolm paths for macOS (Homebrew)
ifeq ($(UNAME_S),Darwin)
	LIBOLM_PREFIX := $(shell brew --prefix libolm 2>/dev/null || echo "/opt/homebrew/opt/libolm")
	CGO_CFLAGS := -I$(LIBOLM_PREFIX)/include
	CGO_LDFLAGS := -L$(LIBOLM_PREFIX)/lib
endif

# Set libolm paths for Linux (system packages)
ifeq ($(UNAME_S),Linux)
	CGO_CFLAGS := -I/usr/include/olm
	CGO_LDFLAGS := -L/usr/lib
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
