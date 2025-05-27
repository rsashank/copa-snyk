PLUGIN_NAME=copa-snyk
DIST_DIR=dist
GOOS=linux
GOARCH=amd64
OUTPUT=$(DIST_DIR)/$(GOOS)_$(GOARCH)/release/$(PLUGIN_NAME)

.PHONY: all build clean

all: build

build:
	@echo "Building $(PLUGIN_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(DIST_DIR)/$(GOOS)_$(GOARCH)/release
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUTPUT) .

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(DIST_DIR)
