GOLANGCI_VERSION=v1.32.2

.PHONY: setup
setup:  ## Install dev tools
	@echo "==> Installing dependencies..."
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s $(GOLANGCI_VERSION)

.PHONY: fmt
fmt: ## Format the code
	@echo "==>"
	@echo "==> Formatting the code..."
	@gofmt -w -s .
	@goimports -w .

	@echo "==>"
	@echo "==> Running go mod tidy..."
	@go mod tidy

.PHONY: lint
lint: ## Lint the code
	@echo "==>"
	@echo "==> Linting all packages..."
	@./bin/golangci-lint run

.PHONY: fix-lint
fix-lint: ## Fix linting errors
	@echo "==>"
	@echo "==> Fixing lint errors"
	@./bin/golangci-lint run --fix

.PHONY: build
build: ## Build the library
	@echo "==>"
	@echo "==> Building the code"
	@go build ./...

.PHONY: test
test: ## Run the tests
	@echo "==>"
	@echo "==> Running tests"
	@go test ./...

.PHONY: all
all: fmt lint build test ## Run all targets

.PHONY: link-git-hooks
link-git-hooks: ## Install git hooks
	@echo "==>"
	@echo "==> Installing all git hooks..."
	@find .git/hooks -type l -exec rm {} \;
	@find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;

.PHONY: help
.DEFAULT_GOAL := help
help:
	@echo
	@echo "Makefile targets:"
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
