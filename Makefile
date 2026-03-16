.PHONY: install test lint fmt run dry-run

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
