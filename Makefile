.PHONY: test test-unit test-integration run-api run-web evaluate lint format clean

test:
	python -m pytest tests/

test-unit:
	python -m pytest tests/unit/

test-integration:
	python -m pytest tests/integration/

evaluate:
	python scripts/evaluate.py

run-api:
	uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

run-web:
	cd apps/web && npm run dev

lint:
	python -m ruff check src/ apps/ tests/

format:
	python -m ruff format src/ apps/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
