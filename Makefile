PROJECT_NAME = localstack_recommendation
LOCALSTACK_IMAGE = localstack/localstack
LOCALSTACK_DATA_DIR = ./localstack-data

AWS_CMD=aws --endpoint-url=http://localhost:4566

include .env
export

.PHONY: local-dev-env start-localstack wait-for-localstack stop-localstack clean status create-secrets delete-secrets start-fastapi dev-server stop-fastapi send-message 

ifeq ($(OS),Windows_NT)
  WAIT_CMD = @powershell -Command "& {do {Start-Sleep -Seconds 2} while (-not (Test-Connection -ComputerName localhost))}"
else
	WAIT_CMD = @while ! docker exec localstack-recommendation-engine curl -s http://localhost:4566/health | grep '"secretsmanager": "running"' > /dev/null; do echo "Waiting for Secrets Manager to be ready..."; sleep 2; done; echo "Secrets Manager is ready!"
endif

start-localstack:
	@echo '''' 
	@echo Starting Localstack
	@docker compose -f docker-compose.local.yaml up -d
	@echo ''''

wait-for-localstack:
	@echo Waiting for LocalStack to be ready...
	$(WAIT_CMD)
	@echo LocalStack is ready! && echo ''''

stop-localstack:
	@docker compose -f docker-compose.local.yaml down
	@echo LocalStack stopped.

clean:
	@rm -rf $(LOCALSTACK_DATA_DIR)
	@echo LocalStack data directory removed.
	
create-secrets:
	@if $(AWS_CMD) secretsmanager describe-secret --secret-id $(SECRET_NAME) >/dev/null 2>&1; then \
		echo "Secrets already generated; skipping create-secrets."; \
	else \
		echo "Creating secrets"; \
		sleep 3; \
		echo '{' > tmp_secret.json; \
		cat .env | grep -v '^#' | grep -v '^$$' | awk -F '=' '{gsub(/"/,"\\\""); printf "\"%s\": \"%s\",\n", $$1, $$2}' >> tmp_secret.json; \
		sed -i '' -e '$$s/,$$//' tmp_secret.json; \
		echo '}' >> tmp_secret.json; \
		until $(AWS_CMD) secretsmanager create-secret --name $(SECRET_NAME) --secret-string file://tmp_secret.json; do \
			echo "Retrying secret creation in 2 seconds..."; \
			sleep 2; \
		done; \
		rm -f tmp_secret.json; \
		echo "Created secrets"; \
	fi

view-secrets:
	@$(AWS_CMD) secretsmanager get-secret-value --secret-id $(SECRET_NAME)

delete-secrets:
	$(AWS_CMD) secretsmanager delete-secret --secret-id $(SECRET_NAME) --force-delete-without-recovery


local-dev-env: start-localstack wait-for-localstack create-secrets 
	@echo LocalStack is running and initialized with resources.


unit-test:
	@echo Running unit tests...
	@python -m pytest tests/unit/

integration-test:
	@echo Running integration tests...
	@python -m pytest tests/integration/

test:
	@echo Running all tests...
	@python -m pytest tests/
	
dev-server:
	@echo Starting FastAPI development server...
	cd src && PYTHONPATH=. python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

send-message:
	@bash scripts/send-message.sh $(BODY_JSON)

local:
	@echo Starting local development environment with LocalStack...
	@docker-compose -f docker-compose.local.yaml up -d
	@echo Waiting for LocalStack to be ready...
	@$(MAKE) wait-for-localstack
	@echo Creating secrets
	@$(MAKE) create-secrets
	@echo Local development environment is ready!

stop-local:
	@echo Stopping local development environment...
	@docker-compose -f docker-compose.local.yaml down 


.PHONY: docker-logs
docker-logs:
	@echo Viewing local Docker logs...
	docker compose -f docker-compose.local.yaml logs -f --tail=200 localstack recommendation-engine


