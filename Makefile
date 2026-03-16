.PHONY: install test lint fmt run dry-run serve serve-install

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

lint:
	ruff check syspulse/ tests/
	mypy syspulse/

fmt:
	ruff format syspulse/ tests/

dry-run:
	python3 -m syspulse --dry-run

run:
	python3 -m syspulse

serve-install:
	pip install -r server/requirements.txt

serve:
	cd server && uvicorn main:app --reload --port 8000
