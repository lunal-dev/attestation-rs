# Variables
TDX_BINARY_NAME = attest-tdx
AMD_BINARY_NAME = attest-sev-snp
MAIN_BINARY_NAME = lunal-main
INSTALL_PATH = /usr/local/bin
BIN_DIR = ../bin
CARGO = cargo

# Default target - build all binaries with attestation
.PHONY: all
all: build

# Build all binaries with attestation feature
.PHONY: build
build:
	$(CARGO) build --release --features attestation

# Build only TDX attestation binary
.PHONY: build-tdx
build-tdx:
	$(CARGO) build --release --features attestation-tdx --bin $(TDX_BINARY_NAME)

# Build only AMD attestation binary
.PHONY: build-amd
build-amd:
	$(CARGO) build --release --features attestation --bin attest-amd

# Build release binaries for production deployment
.PHONY: build-release
build-release:
	@echo "Building release binaries..."
	$(CARGO) build --release --features attestation --bin attest-amd
	$(CARGO) build --release --features attestation-tdx --bin $(TDX_BINARY_NAME)
	@echo "Copying binaries to $(BIN_DIR)..."
	@mkdir -p $(BIN_DIR)
	cp target/release/attest-amd $(BIN_DIR)/$(AMD_BINARY_NAME)
	cp target/release/$(TDX_BINARY_NAME) $(BIN_DIR)/$(TDX_BINARY_NAME)
	@echo "Release binaries ready in $(BIN_DIR)/"

# Build for WASM web target
.PHONY: wasm
wasm:
	wasm-pack build --target web --features wasm

# Build WASM in dev mode
.PHONY: wasm-dev
wasm-dev:
	wasm-pack build --target web --features wasm --dev

# Install all binaries to /usr/local/bin
.PHONY: install
install: build
	sudo cp target/release/$(TDX_BINARY_NAME) $(INSTALL_PATH)/$(TDX_BINARY_NAME)
	sudo cp target/release/$(AMD_BINARY_NAME) $(INSTALL_PATH)/$(AMD_BINARY_NAME)
	sudo cp target/release/$(MAIN_BINARY_NAME) $(INSTALL_PATH)/$(MAIN_BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(TDX_BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(AMD_BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(MAIN_BINARY_NAME)
	@echo "Binaries installed to $(INSTALL_PATH)"

# Install only TDX binary
.PHONY: install-tdx
install-tdx: build-tdx
	sudo cp target/release/$(TDX_BINARY_NAME) $(INSTALL_PATH)/$(TDX_BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(TDX_BINARY_NAME)
	@echo "$(TDX_BINARY_NAME) installed to $(INSTALL_PATH)"

# Install only AMD binary
.PHONY: install-amd
install-amd: build-amd
	sudo cp target/release/$(AMD_BINARY_NAME) $(INSTALL_PATH)/$(AMD_BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(AMD_BINARY_NAME)
	@echo "$(AMD_BINARY_NAME) installed to $(INSTALL_PATH)"

# Uninstall all binaries
.PHONY: uninstall
uninstall:
	sudo rm -f $(INSTALL_PATH)/$(TDX_BINARY_NAME)
	sudo rm -f $(INSTALL_PATH)/$(AMD_BINARY_NAME)
	sudo rm -f $(INSTALL_PATH)/$(MAIN_BINARY_NAME)
	@echo "All binaries removed from $(INSTALL_PATH)"

# Clean build artifacts
.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf pkg/
	rm -f evidence.b64
# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build       - Build all binaries with attestation feature"
	@echo "  build-tdx   - Build only TDX attestation binary"
	@echo "  build-amd   - Build only AMD attestation binary"
	@echo "  build-main  - Build main demonstration binary"
	@echo "  wasm        - Build for WASM web target"
	@echo "  wasm-dev    - Build WASM in development mode"
	@echo "  install     - Build and install all binaries to $(INSTALL_PATH)"
	@echo "  install-tdx - Build and install TDX binary to $(INSTALL_PATH)"
	@echo "  install-amd - Build and install AMD binary to $(INSTALL_PATH)"
	@echo "  uninstall   - Remove all binaries from $(INSTALL_PATH)"
	@echo "  clean       - Clean build artifacts and pkg directory"