BINARY    := hl7-vulnerable-listener
BUILD_DIR := ./build
GO        := go
GOFLAGS   := -trimpath -ldflags="-s -w"

.PHONY: all build build-linux run run-fixed clean

all: build

## build: Compile for current platform
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) .
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## build-linux: Cross-compile for Linux amd64
build-linux:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 .
	@echo "Built: $(BUILD_DIR)/$(BINARY)-linux-amd64"

## run: Run in fully vulnerable mode (port 2575)
run: build
	$(BUILD_DIR)/$(BINARY) -port 2575 -mode vulnerable -verbose

## run-fixed: Run in fixed mode (port 2576) for comparison
run-fixed: build
	$(BUILD_DIR)/$(BINARY) -port 2576 -mode fixed -verbose

## run-both: Run vulnerable on 2575 and fixed on 2576 simultaneously
run-both: build
	$(BUILD_DIR)/$(BINARY) -port 2575 -mode vulnerable -log vuln.log &
	$(BUILD_DIR)/$(BINARY) -port 2576 -mode fixed -log fixed.log

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR) hl7-listener.log vuln.log fixed.log
