# enochecker_test [![PyPI version](https://badge.fury.io/py/enochecker-test.svg)](https://pypi.org/project/enochecker-test) [![Build Status](https://github.com/enowars/enochecker_test/actions/workflows/pythonapp.yml/badge.svg?branch=main)](https://github.com/enowars/enochecker_test/actions/workflows/pythonapp.yml) ![Lines of code](https://tokei.rs/b1/github/enowars/enochecker_test)
Automatically test services/checker using the enochecker API

# Usage
`enochecker_test` can be used to run tests against a checker, optionally you can specify wich tests to run e.g. `enochecker_test test_getflag[0] test_exploit_per_exploit_id` will run only the first `getflag` test and all `exploit_per_exploit_id` tests.