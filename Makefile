lint:
	python -m isort -c enochecker_test/
	python -m black --check --diff enochecker_test/
	python -m flake8 --select F --per-file-ignores="__init__.py:F401" enochecker_test/
	python -m mypy enochecker_test/

format:
	python -m isort enochecker_test/
	python -m black enochecker_test/

test:
	pip install .
	python -m pytest
