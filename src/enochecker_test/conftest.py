import os

import pytest
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import StatusCode, get_current_span

# Groups tests are annotated with via @pytest.mark.<group>, one per enochecker
# method plus "stress" and "misc" (tests that don't map to a single method).
GROUP_DESCRIPTIONS = {
    "putflag": "tests exercising the checker's putflag method",
    "getflag": "tests exercising the checker's getflag method",
    "putnoise": "tests exercising the checker's putnoise method",
    "getnoise": "tests exercising the checker's getnoise method",
    "havoc": "tests exercising the checker's havoc method",
    "exploit": "tests exercising the checker's exploit method",
    "test": "tests exercising the checker's test method",
    "stress": "run stress tests",
    "misc": "tests that don't map to a single checker method",
}


def pytest_addoption(parser):
    parser.addoption("--checker-address", action="store", type=str)
    parser.addoption("--checker-port", action="store", type=int)
    parser.addoption("--service-address", action="store", type=str)
    parser.addoption("--service-name", action="store", type=str)
    parser.addoption("--flag-variants", action="store", type=int)
    parser.addoption("--noise-variants", action="store", type=int)
    parser.addoption("--havoc-variants", action="store", type=int)
    parser.addoption("--exploit-variants", action="store", type=str)
    parser.addoption("--test-variants", action="store", type=int)
    parser.addoption("--exploit-timeout", action="store", type=int, default=None)
    parser.addoption("--multiplier", action="store", type=int)
    parser.addoption("--seed", action="store", type=int)
    parser.addoption("--stress", action="store", type=bool)
    parser.addoption("--flag-types", action="store", default="ascii,utf8")
    parser.addoption(
        "--with-group",
        action="append",
        default=[],
        metavar="GROUP",
        help="Add all tests in GROUP to the selection (repeatable, comma-separated allowed)",
    )
    parser.addoption(
        "--without-group",
        action="append",
        default=[],
        metavar="GROUP",
        help="Remove all tests in GROUP from the selection (repeatable, comma-separated allowed)",
    )
    parser.addoption(
        "--with",
        dest="with_tests",
        action="append",
        default=[],
        metavar="TEST",
        help="Add TEST (by its function name) to the selection (repeatable, comma-separated allowed)",
    )
    parser.addoption(
        "--without",
        dest="without_tests",
        action="append",
        default=[],
        metavar="TEST",
        help="Remove TEST (by its function name) from the selection (repeatable, comma-separated allowed)",
    )
    parser.addoption(
        "--nullset",
        action="store_true",
        default=False,
        help="Start with no tests selected instead of all of them; use --with/--with-group to opt tests back in",
    )
    parser.addoption(
        "--all",
        action="store_true",
        default=False,
        help="Select all tests, overriding --nullset",
    )


def pytest_configure(config):
    for group, description in GROUP_DESCRIPTIONS.items():
        config.addinivalue_line("markers", f"{group}: {description}")

    # enable tracing if OTEL_EXPORTER_OTLP_ENDPOINT is set
    if otlp_endpoint := os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        print(f"Setting up OLTLP telemetry for endpoint {otlp_endpoint}")

        headers = {}
        if otlp_key := os.environ.get("OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION"):
            headers["authorization"] = otlp_key
        provider = TracerProvider(
            resource=Resource(
                attributes={
                    SERVICE_NAME: f"enochecker_test: {config.getoption('--service-name')}"
                }
            )
        )
        processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        HTTPXClientInstrumentor().instrument()


@pytest.fixture(autouse=True)
def setup_telemetry(request):
    # Start a span for the specific test function
    tracer = trace.get_tracer(f"test: {request.config.getoption('--service-name')}")
    with tracer.start_as_current_span(request.node.nodeid.split("::")[1]) as span:
        request.node.trace_id = format(span.get_span_context().trace_id, "032x")
        yield span


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--stress"):
        skip_stress = pytest.mark.skip(reason="need --stress option to run")
        for item in items:
            if "stress" in item.keywords:
                item.add_marker(skip_stress)

    _apply_test_selection(config, items)


def _split_csv(values):
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def _item_groups(item):
    return {mark.name for mark in item.iter_markers() if mark.name in GROUP_DESCRIPTIONS}


def _item_test_name(item):
    return getattr(item, "originalname", None) or item.name.split("[")[0]


def _apply_test_selection(config, items):
    with_groups = set(_split_csv(config.getoption("with_group")))
    without_groups = set(_split_csv(config.getoption("without_group")))
    with_tests = set(_split_csv(config.getoption("with_tests")))
    without_tests = set(_split_csv(config.getoption("without_tests")))
    nullset = config.getoption("nullset")
    select_all = config.getoption("all")

    if not (
        with_groups or without_groups or with_tests or without_tests or nullset or select_all
    ):
        return

    if select_all:
        selected = set(items)
    elif nullset:
        selected = set()
    else:
        selected = set(items)

    if with_groups or with_tests:
        for item in items:
            if item in selected:
                continue
            if _item_groups(item) & with_groups or _item_test_name(item) in with_tests:
                selected.add(item)

    if without_groups or without_tests:
        for item in list(selected):
            if _item_groups(item) & without_groups or _item_test_name(item) in without_tests:
                selected.discard(item)

    deselected = [item for item in items if item not in selected]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = [item for item in items if item in selected]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    # Only print the link if the test actually runs and fails
    if report.when == "call":
        if report.failed:
            get_current_span().set_status(StatusCode.ERROR)
        trace_id = getattr(item, "trace_id", None)
        if trace_id:
            report.nodeid += f" [OTEL TRACE ID: {trace_id}]"
            if template := os.environ.get("OTEL_TRACE_URL_TEMPLATE"):
                url = template.replace("__TRACEID__", trace_id)
                report.nodeid += f" {url}"
