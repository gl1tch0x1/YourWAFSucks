SHELL := /bin/bash
VERSION := 1.0.0
GO_BIN := bin/bypass403-go

.PHONY: all build install test clean fmt vet deps

all: build

deps:
	go mod download
	go mod tidy

build: deps
	@mkdir -p bin
	go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(GO_BIN) ./cmd/bypass403
	@echo "[+] Built: $(GO_BIN)"
	@chmod +x bypass403.sh

install: build
	install -m 0755 $(GO_BIN) /usr/local/bin/bypass403-go
	install -m 0755 bypass403.sh /usr/local/bin/bypass403
	@echo "[+] Installed: /usr/local/bin/bypass403"

test: build
	go test ./...
	@if [ -d .venv ]; then \
		.venv/bin/pytest tests/python -v; \
	else \
		python3 -m pytest tests/python -v || true; \
	fi

fmt:
	gofmt -s -w .

vet:
	go vet ./...

clean:
	rm -rf bin/
	rm -f /tmp/bypass403-findings.jsonl