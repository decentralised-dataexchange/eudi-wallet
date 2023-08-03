.PHONY: help build run

DOCKER_IMAGE ?= eudi-wallet
GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
NGROK_AUTH_TOKEN ?= 
NGROK_SUBDOMAIN ?= 
KAFKA_TOPIC ?= ebsi

help: ## Print a help message.
	@echo "=================================================="
	@echo "                 EUDI Wallet                      "
	@echo "=================================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image.
	$(eval DOCKER_TAG=$(if $(GIT_TAG),$(GIT_TAG),$(if $(GIT_COMMIT),$(GIT_COMMIT),latest)))
	@echo "Building Docker image with tag: $(DOCKER_TAG)"
	docker build -f ./resources/docker/Dockerfile -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	echo "$(DOCKER_IMAGE):$(DOCKER_TAG)" > deploy_version

run: ## Run the Docker container
	$(eval DOCKER_TAG=$(shell cat deploy_version))
	@echo "Running Docker container with image: $(DOCKER_TAG)"
	docker run -p 9000:9000 --link=broker $(DOCKER_TAG) \
	--port 9000 \
	--ngrok-auth-token $(NGROK_AUTH_TOKEN) \
	--ngrok-subdomain $(NGROK_SUBDOMAIN) \
	--kafka-broker-address broker:29092 \
	--kafka-topic $(KAFKA_TOPIC)

.DEFAULT_GOAL := help
