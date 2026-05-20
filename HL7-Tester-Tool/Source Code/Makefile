BINARY     := hl7-security-tester
BUILD_DIR  := ./build
CMD_DIR    := ./cmd
GO         := go
GOFLAGS    := -trimpath -ldflags="-s -w"

.PHONY: all build clean test run-help run-interactive fmt lint

all: build

## build: Compile the binary to ./build/
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)/...
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## build-all: Cross-compile for Linux, macOS, Windows
build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   $(CMD_DIR)/...
	GOOS=darwin  GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  $(CMD_DIR)/...
	GOOS=darwin  GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  $(CMD_DIR)/...
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows.exe   $(CMD_DIR)/...
	@echo "Cross-compiled binaries in $(BUILD_DIR)/"

## test: Run unit tests
test:
	$(GO) test ./... -v -timeout 60s

## fmt: Format source code
fmt:
	$(GO) fmt ./...

## lint: Vet source code
lint:
	$(GO) vet ./...

## run-help: Show CLI help
run-help: build
	$(BUILD_DIR)/$(BINARY) --help

## run-sample: Run all tests against localhost:2575 using sample messages
run-sample: build
	$(BUILD_DIR)/$(BINARY) \
		-host localhost \
		-port 2575 \
		-file testdata/sample_messages.hl7 \
		-debug \
		-tests all

## run-tls: Run TLS tests (adjust host/port/certs as needed)
run-tls: build
	$(BUILD_DIR)/$(BINARY) \
		-host localhost \
		-port 2575 \
		-tls \
		-skip-verify \
		-file testdata/sample_messages.hl7 \
		-tests encryption,tls,cert,replay \
		-debug

## run-interactive: Launch interactive shell
run-interactive: build
	$(BUILD_DIR)/$(BINARY) \
		-host localhost \
		-port 2575 \
		-file testdata/sample_messages.hl7 \
		-interactive

## run-json: Run all tests and output JSON report
run-json: build
	$(BUILD_DIR)/$(BINARY) \
		-host localhost \
		-port 2575 \
		-file testdata/sample_messages.hl7 \
		-output json \
		-out-file report.json
	@echo "Report saved to report.json"

## clean: Remove built artifacts
clean:
	rm -rf $(BUILD_DIR) report.json

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
