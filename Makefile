# Makefile for lunal-attestation

# Variables
BINARY_NAME = attest
INSTALL_PATH = /usr/local/bin
CARGO = cargo

# Default target - build with attestation
.PHONY: all
all: build

# Build with attestation feature
.PHONY: build
build:
	$(CARGO) build --release --features attestation

# Build for WASM web target
.PHONY: wasm
wasm:
	wasm-pack build --target web --features wasm

# Build WASM in dev mode
.PHONY: wasm-dev
wasm-dev:
	wasm-pack build --target web --features wasm --dev

# Install the binary to /usr/local/bin
.PHONY: install
install: build
	sudo cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "$(BINARY_NAME) installed to $(INSTALL_PATH)"

# Uninstall the binary
.PHONY: uninstall
uninstall:
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "$(BINARY_NAME) removed from $(INSTALL_PATH)"

# Clean build artifacts
.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf pkg/

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build     - Build with attestation feature"
	@echo "  wasm      - Build for WASM web target"
	@echo "  wasm-dev  - Build WASM in development mode"
	@echo "  install   - Build and install binary to $(INSTALL_PATH)"
	@echo "  uninstall - Remove binary from $(INSTALL_PATH)"
	@echo "  clean     - Clean build artifacts and pkg directory"