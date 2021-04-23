def pytest_addoption(parser):
    parser.addoption("--checker-address", action="store", type=str)
    parser.addoption("--checker-port", action="store", type=int)
    parser.addoption("--service-address", action="store", type=str)
    parser.addoption("--flag-variants", action="store", type=int)
    parser.addoption("--noise-variants", action="store", type=int)
    parser.addoption("--havoc-variants", action="store", type=int)
