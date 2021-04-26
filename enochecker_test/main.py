import logging
import os
import sys
from typing import cast

import jsons
import pytest
import requests
from enochecker_core import CheckerInfoMessage
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


def run_tests(host, port, service_address):
    s = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
    )
    s.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    r = s.get(f"http://{host}:{port}/service")
    if r.status_code != 200:
        raise Exception("Failed to get /service from checker")
    print(r.content)
    info: CheckerInfoMessage = jsons.loads(
        r.content, CheckerInfoMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    logging.info(
        "Testing service %s, flagVariants: %d, noiseVariants: %d, havocVariants: %d",
        info.service_name,
        info.flag_variants,
        info.noise_variants,
        info.havoc_variants,
    )

    sys.exit(
        pytest.main(
            [
                f"--checker-address={host}",
                f"--checker-port={port}",
                f"--service-address={service_address}",
                f"--flag-variants={info.flag_variants}",
                f"--noise-variants={info.noise_variants}",
                f"--havoc-variants={info.havoc_variants}",
                os.path.join(os.path.dirname(__file__), "tests.py"),
            ]
        )
    )


def main():
    if not os.getenv("ENOCHECKER_TEST_CHECKER_ADDRESS"):
        raise Exception(
            "Missing enochecker address, please set the ENOCHECKER_TEST_CHECKER_ADDRESS environment variable"
        )
    if not os.getenv("ENOCHECKER_TEST_CHECKER_PORT"):
        raise Exception(
            "Missing enochecker port, please set the ENOCHECKER_TEST_CHECKER_PORT environment variable"
        )
    if not os.getenv("ENOCHECKER_TEST_SERVICE_ADDRESS"):
        raise Exception(
            "Missing service address, please set the ENOCHECKER_TEST_SERVICE_ADDRESS environment variable"
        )
    host = os.getenv("ENOCHECKER_TEST_CHECKER_ADDRESS")
    _service_address = os.getenv("ENOCHECKER_TEST_SERVICE_ADDRESS")
    try:
        port_str = os.getenv("ENOCHECKER_TEST_CHECKER_PORT")
        port = int(cast(str, port_str))
    except ValueError:
        raise Exception("Invalid number in ENOCHECKER_TEST_PORT")

    logging.basicConfig(level=logging.INFO)
    run_tests(host, port, _service_address)
