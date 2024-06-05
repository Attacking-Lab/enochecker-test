# enochecker_test [![PyPI version](https://badge.fury.io/py/enochecker-test.svg)](https://pypi.org/project/enochecker-test) [![Build Status](https://github.com/enowars/enochecker_test/actions/workflows/pythonapp.yml/badge.svg?branch=main)](https://github.com/enowars/enochecker_test/actions/workflows/pythonapp.yml) ![Lines of code](https://tokei.rs/b1/github/enowars/enochecker_test)
Automatically test services/checker using the enochecker API

# Usage
`enochecker_test` can be used to run tests against a checker, optionally you can specify wich tests to run e.g. `enochecker_test test_getflag[0] test_exploit_per_exploit_id` will run only the first `getflag` test and all `exploit_per_exploit_id` tests.

```
usage: enochecker_test [-h] [-a CHECKER_ADDRESS] [-p {1..65535}] [-A SERVICE_ADDRESS] [testexpr]

Utility for testing checkers that implement the enochecker API

positional arguments:
  testexpr              Specify the tests that should be run in the syntax expected by pytests -k flag, e.g. 'test_getflag' or 'not exploit'. If no expr is specified, all tests will be run.

optional arguments:
  -h, --help            show this help message and exit
  -a CHECKER_ADDRESS, --checker-address CHECKER_ADDRESS
                        The address on which the checker is listening (defaults to the ENOCHECKER_TEST_CHECKER_ADDRESS environment variable)
  -p {1..65535}, --checker-port {1..65535}
                        The port on which the checker is listening (defaults to ENOCHECKER_TEST_CHECKER_PORT environment variable)
  -A SERVICE_ADDRESS, --service-address SERVICE_ADDRESS
                        The address on which the checker can reach the service (defaults to ENOCHECKER_TEST_SERVICE_ADDRESS environment variable)

Example Usage:

    $ enochecker_test -a localhost -p 5008 -A 172.20.0.1 test_putflag

Assuming that 172.20.0.1 is the ip address of the gateway of the network of the
service's docker container as obtained by e.g:

    $ docker network inspect service_default | jq ".[].IPAM.Config[].Gateway"
```
