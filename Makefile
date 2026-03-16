.PHONY: install test lint fmt dry-run

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
	python3 -m syspulse --dry-run --format terminal

scan-json:
	python3 -m syspulse --format json

scan-html:
	python3 -m syspulse --format html --output report.html && open report.html
