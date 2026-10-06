.PHONY: up test down
up:
	docker compose up --build
test:
	PYTHONPATH=. pytest -q
down:
	docker compose down
