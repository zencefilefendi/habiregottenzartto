# habiregottenzartto — developer tasks. Zero runtime deps; dev tools optional.
PY ?= python3

.PHONY: help install dev test lint type cov demo clean all

help:
	@echo "make install   editable install (+ console entrypoint 'habir')"
	@echo "make test      run the pytest suite"
	@echo "make lint      ruff check (E,F,W; line-length 100)"
	@echo "make type      mypy (advisory)"
	@echo "make demo      sync + mine + scan the bundled demo project"
	@echo "make all       lint + type + test"

install:
	$(PY) -m pip install -e ".[dev]"

dev:
	$(PY) -m pip install ruff mypy pytest

test:
	$(PY) -m pytest -q

lint:
	ruff check .

type:
	-mypy habir

cov:
	$(PY) -m pytest --cov=habir --cov-report=term-missing

demo:
	$(PY) -m habir db sync
	$(PY) -m habir mine
	$(PY) -m habir scan examples/demo-project --explain

all: lint type test

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
