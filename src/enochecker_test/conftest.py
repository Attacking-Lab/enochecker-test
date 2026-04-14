import os

import pytest
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import StatusCode, get_current_span


def pytest_addoption(parser):
    parser.addoption("--checker-address", action="store", type=str)
    parser.addoption("--checker-port", action="store", type=int)
    parser.addoption("--service-address", action="store", type=str)
    parser.addoption("--service-name", action="store", type=str)
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
    if report.when == "call":
        if report.failed:
            get_current_span().set_status(StatusCode.ERROR)
        trace_id = getattr(item, "trace_id", None)
        if trace_id:
            report.nodeid += f" [OTEL TRACE ID: {trace_id}]"
            if template := os.environ.get("OTEL_TRACE_URL_TEMPLATE"):
                url = template.replace("__TRACEID__", trace_id)
                report.nodeid += f" {url}"
