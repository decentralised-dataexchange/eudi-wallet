.PHONY: help build run

# Docker image name and tag
DOCKER_IMAGE ?= eu.gcr.io/jenkins-189019/igrant-eudi-wallet
GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)

# Save the name of docker image to be deployed in deploy version file
# When make publish is executed it will push the docker image to the container registry
DEPLOY_VERSION_FILE = ./deploy_version
DEPLOY_VERSION = $(shell test -f $(DEPLOY_VERSION_FILE) && cat $(DEPLOY_VERSION_FILE))

# Settings for server
# Ngrok is only required if needs to expose wallet to internet during development
NGROK_AUTH_TOKEN ?= 
DOMAIN ?= 

# Kafka settings is mandatory
KAFKA_TOPIC ?= ebsi
KAFKA_BROKER_ADDRESS ?= broker:29092

# To enable debug mode using debugpy
DEBUG ?= false
DEBUG_HOST ?= 0.0.0.0
DEBUG_PORT ?= 5678

# Settings for database
PG_IMAGE ?= postgres:13
PG_CONTAINER_NAME ?= eudi_wallet_postgres
PG_PORT ?= 5432
PG_USER ?= eudiwallet
PG_PASSWORD ?= secret
PG_DB ?= eudiwalletdb
PG_VOLUME ?= eudi_wallet_pgdata

help: ## Print a help message.
	@echo "=================================================="
	@echo "                 EUDI Wallet                      "
	@echo "=================================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the base container image.
	$(eval DOCKER_TAG=$(shell date +%Y%m%d%H%M%S)-$(if $(GIT_TAG),$(GIT_TAG),$(if $(GIT_COMMIT),$(GIT_COMMIT),latest)))
	@echo "Building Docker image with tag: $(DOCKER_TAG)"
	docker build -f ./resources/docker/server/Dockerfile -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	echo "$(DOCKER_IMAGE):$(DOCKER_TAG)" > $(DEPLOY_VERSION_FILE)

run-config: ## Run the server
	$(eval DOCKER_TAG=$(shell cat deploy_version))
	@echo "Running Docker container with image: $(DOCKER_TAG)"
	docker run \
	--name eudiwallet-config \
	-e "ROUTE_PERMITTED=config" \
	-e "PORT=9000" \
	-e "DOMAIN=$(DOMAIN)" \
	-e "DEBUG=$(DEBUG)" \
	-e "DEBUG_HOST=$(DEBUG_HOST)" \
	-e "DEBUG_PORT=$(DEBUG_PORT)" \
	-e DATABASE_USER=$(PG_USER) \
	-e DATABASE_PASSWORD=$(PG_PASSWORD) \
	-e DATABASE_HOST=$(PG_CONTAINER_NAME) \
	-e DATABASE_PORT=$(PG_PORT) \
	-e DATABASE_DB=$(PG_DB) \
	-p 8080:9000 \
	--link=$(PG_CONTAINER_NAME) \
	$(DOCKER_TAG)

run-service: ## Run the server
	$(eval DOCKER_TAG=$(shell cat deploy_version))
	@echo "Running Docker container with image: $(DOCKER_TAG)"
	docker run \
	--name eudiwallet-service \
	-e "PORT=9000" \
	-e "ROUTE_PERMITTED=service" \
	-e "DOMAIN=$(DOMAIN)" \
	-e "DEBUG=$(DEBUG)" \
	-e "DEBUG_HOST=$(DEBUG_HOST)" \
	-e "DEBUG_PORT=$(DEBUG_PORT)" \
	-e DATABASE_USER=$(PG_USER) \
	-e DATABASE_PASSWORD=$(PG_PASSWORD) \
	-e DATABASE_HOST=$(PG_CONTAINER_NAME) \
	-e DATABASE_PORT=$(PG_PORT) \
	-e DATABASE_DB=$(PG_DB) \
	-p 9000:9000 \
	--link=$(PG_CONTAINER_NAME) \
	$(DOCKER_TAG)

run-db: ## Start the PostgreSQL database
	@echo "Starting PostgreSQL database..."
	docker run -d \
	--name $(PG_CONTAINER_NAME) \
	-e POSTGRES_USER=$(PG_USER) \
	-e POSTGRES_PASSWORD=$(PG_PASSWORD) \
	-e POSTGRES_DB=$(PG_DB) \
	-p $(PG_PORT):5432 \
	-v $(PG_VOLUME):/var/lib/postgresql/data \
	$(PG_IMAGE)

stop-config: ## Stop the config server
	@echo "Stopping config server..."
	docker stop eudiwallet-config && docker rm eudiwallet-config

stop-service: ## Stop the service server
	@echo "Stopping service server..."
	docker stop eudiwallet-service && docker rm eudiwallet-service

stop-db: ## Stop the PostgreSQL database
	@echo "Stopping PostgreSQL database..."
	docker stop $(PG_CONTAINER_NAME) && docker rm $(PG_CONTAINER_NAME)

create-db-volume: ## Create Docker volume for PostgreSQL data
	@echo "Creating Docker volume..."
	docker volume create $(PG_VOLUME)

destroy-db-volume: ## Destroy Docker volume and all associated data
	@echo "Destroying Docker volume..."
	docker volume rm $(PG_VOLUME)

.PHONY: publish
publish: $(DEPLOY_VERSION_FILE) ## Publish latest production Docker image to docker hub
	docker push $(DEPLOY_VERSION)

deploy: $(DEPLOY_VERSION_FILE) ## Deploy to K8s cluster (e.g. make deploy/{preview,staging,production})
	kubectl set image deployment/config-ew config-ew=$(DEPLOY_VERSION) -n eudiwallet
	kubectl set image deployment/service-ew service-ew=$(DEPLOY_VERSION) -n eudiwallet

.DEFAULT_GOAL := help
