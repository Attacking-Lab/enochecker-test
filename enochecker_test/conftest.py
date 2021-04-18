def pytest_addoption(parser):
    parser.addoption("--checker-address", action="store", type=str)
    parser.addoption("--checker-port", action="store", type=int)
    parser.addoption("--service-address", action="store", type=str)
    parser.addoption("--flag-count", action="store", type=int)
    parser.addoption("--noise-count", action="store", type=int)
    parser.addoption("--havoc-count", action="store", type=int)
