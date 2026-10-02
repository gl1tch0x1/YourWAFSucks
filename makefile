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
	@if [ -x .venv/Scripts/python.exe ]; then \
		.venv/Scripts/python.exe -m pytest tests/python -v; \
	elif [ -x .venv/bin/python3 ]; then \
		.venv/bin/python3 -m pytest tests/python -v; \
	elif [ -x .venv/bin/python ]; then \
		.venv/bin/python -m pytest tests/python -v; \
	elif command -v python3 >/dev/null 2>&1; then \
		python3 -m pytest tests/python -v; \
	elif command -v python >/dev/null 2>&1; then \
		python -m pytest tests/python -v; \
	else \
		echo "Python unavailable; skipping optional Python tests."; \
	fi

fmt:
	gofmt -s -w .

vet:
	go vet ./...

clean:
	rm -rf bin/
	rm -f /tmp/bypass403-findings.jsonl