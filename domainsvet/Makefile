.PHONY: build build-all clean

# Build for current OS/arch
build:
	go build -ldflags="-s -w" -o domainsvet .

# Cross-compile for all major platforms
build-all:
	mkdir -p dist
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/domainsvet-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/domainsvet-darwin-arm64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/domainsvet-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/domainsvet-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/domainsvet-windows-amd64.exe .

clean:
	rm -f domainsvet
	rm -rf dist/
