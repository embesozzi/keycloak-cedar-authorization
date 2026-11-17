COMPOSE = docker compose -f tests/docker-compose.yml

.PHONY: build test cedar-cli policies-check up down logs test-e2e-run test-e2e

# Build the provider jar (runs the unit tests)
build:
	mvn package

test:
	mvn test

# Cedar CLI image used to check the policies
cedar-cli:
	tools/cedar-cli/build.sh

# Format check and strict validation of every tests/policies/<resource-server>/
policies-check: cedar-cli
	tools/cedar-cli/check-policies.sh

# Keycloak with the provider on http://localhost:8082, and the demo realm
up: build
	$(COMPOSE) up -d --wait keycloak
	$(COMPOSE) run --rm keycloak-bootstrap

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f

test-e2e: up test-e2e-run

# End-to-end AuthZEN checks against a running stack
test-e2e-run:
	tests/e2e/evaluate.sh