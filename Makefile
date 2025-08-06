.PHONY: build run deploy help

# Default target
help:
	@echo "Available targets:"
	@echo "  build   - Build the scaffold binary"
	@echo "  run     - Run the scaffold tool directly"
	@echo "  deploy  - Deploy with git tag (usage: make deploy TAG=v1.0.0)"
	@echo "  help    - Show this help message"

# Build the scaffold binary
build:
	go build -o bin .

# Run the scaffold tool directly
run: build
	./bin

# Deploy with git tag
deploy:
	@if [ -z "$(TAG)" ]; then \
		echo "❌ TAG is required. Usage: make deploy TAG=v1.0.0"; \
		exit 1; \
	fi
	@echo "Deploying with tag $(TAG)..."
	git tag $(TAG)
	@echo "Pushing tag to remote..."
	git push origin $(TAG)
	@echo "Deploy complete! Tag $(TAG) has been pushed to remote."

