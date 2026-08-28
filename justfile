unexport VIRTUAL_ENV

UV_FLAGS := env('UV_FLAGS', '--inexact --all-extras')
UV_RUN := 'env VIRTUAL_ENV=.venv uv run ' + UV_FLAGS

[private]
default:
    @just --list

# Format, lint, type-check and test
[group('test')]
all: format lint mypy test

# Auto-fix formatting and lint issues
[group('dev')]
fix: format-fix lint-fix

# Check formatting
[group('dev')]
format:
    @{{ UV_RUN }} --group format ruff format --check

# Apply formatting
[group('dev')]
format-fix:
    @{{ UV_RUN }} --group format ruff format

# Lint sources
[group('dev')]
lint:
    @{{ UV_RUN }} --group lint ruff check

# Auto-fix lint issues
[group('dev')]
lint-fix:
    @{{ UV_RUN }} --group lint ruff check --fix

# Type-check sources
[group('dev')]
mypy:
    @{{ UV_RUN }} --group typing mypy src/enochecker_test/

# Build sdist/wheel
[group('build')]
build:
    @uv build

# Run the test suite, if any tests exist
[group('test')]
test flags='':
    #!/usr/bin/env sh
    set -e
    if [ -d tests ]; then
        {{ UV_RUN }} --group test coverage run -m pytest -W error -v {{ flags }}
        {{ UV_RUN }} --group test coverage report -m
    fi

# Sync the dev environment
[group('dev')]
sync:
    @uv sync {{ UV_FLAGS }}

# Set up lib/enochecker-core as a symlinked submodule checkout for local dev
[group('dev')]
dev:
    @git update-index --assume-unchanged lib/.enochecker-core/pyproject.toml
    @rm -rf lib/.enochecker-core
    @ln -s enochecker-core lib/.enochecker-core
    @git submodule update --init --recursive lib/enochecker-core
