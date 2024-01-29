.PHONY: help
help: ## Help for usage
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run-local-dev: ## Run Wazuh cluster with prometheus and exporter.
	docker compose -f tests/single-node/generate-indexer-certs.yml run --rm generator
	docker compose -f docker-compose.yml up -d --build

destroy: ## Destroy docker compose stack and cleanup
	docker compose down --remove-orphans --rmi local -v
	rm -rf tests/single-node/config/wazuh_indexer_ssl_certs/*
test: ## Run unit tests
	pytest  -v  --cov=. --cov-report xml --cov-report html -n auto --capture=sys -x --tb=long
