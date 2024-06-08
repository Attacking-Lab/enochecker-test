lint:
	poetry run isort -c enochecker_test/
	poetry run black --check --diff enochecker_test/
	poetry run flake8 --select F --per-file-ignores="__init__.py:F401" enochecker_test/
	poetry run mypy enochecker_test/

format:
	poetry run isort enochecker_test/
	poetry run black enochecker_test/

test:
	poetry run pytest
