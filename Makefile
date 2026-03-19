.PHONY: help install dev-install format lint type-check test test-cov clean pre-commit setup-dev

help:
	@echo "Available commands:"
	@echo "  setup-dev     - Install all development dependencies and setup pre-commit"
	@echo "  install       - Install production dependencies"
	@echo "  dev-install   - Install development dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  format        - Format code with ruff"
	@echo "  lint          - Lint code with ruff and pylint"
	@echo "  type-check    - Run type checking with mypy and pyright"
	@echo "  security      - Run security checks with bandit"
	@echo "  check-all     - Run all code quality checks"
	@echo ""
	@echo "Testing:"
	@echo "  test          - Run tests with pytest"
	@echo "  test-cov      - Run tests with coverage reporting"
	@echo ""
	@echo "Development:"
	@echo "  pre-commit    - Run pre-commit hooks on all files"
	@echo "  clean         - Clean up cache files and artifacts"

install:
	poetry install --only=main

dev-install:
	poetry install --with=dev

setup-dev: dev-install
	poetry run pre-commit install
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make check-all' to verify everything works correctly."

format:
	@echo "🎨 Formatting code with ruff..."
	poetry run ruff format .
	@echo "✅ Code formatting complete!"

lint:
	@echo "🔍 Linting code with ruff..."
	poetry run ruff check . --fix
	@echo "📝 Running additional linting with pylint..."
	poetry run pylint exaaiagnt/ --score=no --reports=no
	@echo "✅ Linting complete!"

type-check:
	@echo "🔍 Type checking with mypy..."
	poetry run mypy exaaiagnt/
	@echo "🔍 Type checking with pyright..."
	poetry run pyright exaaiagnt/
	@echo "✅ Type checking complete!"

security:
	@echo "🔒 Running security checks with bandit..."
	poetry run bandit -r exaaiagnt/ -c pyproject.toml
	@echo "✅ Security checks complete!"

check-all: format lint type-check security
	@echo "✅ All code quality checks passed!"

test:
	@echo "🧪 Running tests..."
	poetry run pytest -v
	@echo "✅ Tests complete!"

test-cov:
	@echo "🧪 Running tests with coverage..."
	poetry run pytest -v --cov=exaaiagnt --cov-report=term-missing --cov-report=html
	@echo "✅ Tests with coverage complete!"
	@echo "📊 Coverage report generated in htmlcov/"

pre-commit:
	@echo "🔧 Running pre-commit hooks..."
	poetry run pre-commit run --all-files
	@echo "✅ Pre-commit hooks complete!"

clean:
	@echo "🧹 Cleaning up cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete!"

dev: format lint type-check test
	@echo "✅ Development cycle complete!"
