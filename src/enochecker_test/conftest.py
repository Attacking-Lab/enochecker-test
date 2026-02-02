import pytest


def pytest_addoption(parser):
    parser.addoption("--checker-address", action="store", type=str)
    parser.addoption("--checker-port", action="store", type=int)
    parser.addoption("--service-address", action="store", type=str)
    parser.addoption("--flag-variants", action="store", type=int)
    parser.addoption("--noise-variants", action="store", type=int)
    parser.addoption("--havoc-variants", action="store", type=int)
    parser.addoption("--exploit-variants", action="store", type=int)
    parser.addoption("--test-variants", action="store", type=int)
    parser.addoption("--multiplier", action="store", type=int)
    parser.addoption("--seed", action="store", type=int)
    parser.addoption("--stress", action="store", type=bool)


def pytest_configure(config):
    config.addinivalue_line("markers", "stress: run stress tests")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--stress"):
        return

    skip_stress = pytest.mark.skip(reason="need --stress option to run")
    for item in items:
        if "stress" in item.keywords:
            item.add_marker(skip_stress)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Only print the link if the test actually runs and fails
    if report.when == "call" and report.failed:
        trace_id = getattr(item, "trace_id", None)
        if trace_id:
            report.nodeid += f" [OTEL TRACE ID: {trace_id}]"
