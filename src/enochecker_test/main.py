import argparse
import logging
import os
import sys

import pytest
import requests
from enochecker_core import CheckerInfoMessage
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def run_tests(
    host: str,
    port: int,
    service_address: str,
    test_expr: str,
    multiplier: int,
    seed: int,
):
    s = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
    )
    s.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    r = s.get(f"http://{host}:{port}/service")
    if r.status_code != 200:
        raise Exception("Failed to get /service from checker")
    info = CheckerInfoMessage.model_validate_json(r.text)
    logging.info(
        "Testing service %s, flagVariants: %d, noiseVariants: %d, havocVariants: %d, exploitVariants: %d, testVariants: %d",
        info.service_name,
        info.flag_variants,
        info.noise_variants,
        info.havoc_variants,
        info.exploit_variants,
        info.test_variants,
    )

    test_args = [
        f"--checker-address={host}",
        f"--checker-port={port}",
        f"--service-address={service_address}",
        f"--flag-variants={info.flag_variants}",
        f"--noise-variants={info.noise_variants}",
        f"--havoc-variants={info.havoc_variants}",
        f"--exploit-variants={info.exploit_variants}",
        f"--test-variants={info.test_variants}",
        f"--multiplier={multiplier}",
        f"--seed={seed}",
        "--durations=0",
        "-v",
    ]

    if test_expr:
        test_args.append("-k")
        test_args.append(test_expr)
    test_args.append(os.path.join(os.path.dirname(__file__), "tests.py"))

    sys.exit(pytest.main(test_args))


def main():
    parser = argparse.ArgumentParser(
        prog="enochecker_test",
        # don't reformat but use description and epilog verbatim
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Utility for testing checkers that implement the enochecker API",
        epilog="""Example Usage:

    $ enochecker_test -a localhost -p 5008 -A 172.20.0.1 test_putflag

Assuming that 172.20.0.1 is the ip address of the gateway of the network of the
service's docker container as obtained by e.g:

    $ docker network inspect service_default | jq ".[].IPAM.Config[].Gateway"
""",
    )
    parser.add_argument(
        "-a",
        "--checker-address",
        help="The address on which the checker is listening (defaults to the ENOCHECKER_CHECKER_ADDRESS environment variable)",
        default=os.environ.get("ENOCHECKER_CHECKER_ADDRESS", "localhost"),
    )
    parser.add_argument(
        "-n",
        "--checker-network",
        help="The name of the checker docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_CHECKER_NETWORK"),
    )
    parser.add_argument(
        "-p",
        "--checker-port",
        help="The port on which the checker is listening (defaults to ENOCHECKER_CHECKER_PORT environment variable)",
        choices=range(1, 65536),
        metavar="{1..65535}",
        type=int,
        default=os.environ.get("ENOCHECKER_CHECKER_PORT"),
    )
    parser.add_argument(
        "-A",
        "--service-address",
        help="The address on which the checker can reach the service (defaults to ENOCHECKER_SERVICE_ADDRESS environment variable)",
        default=os.environ.get("ENOCHECKER_SERVICE_ADDRESS"),
    )
    parser.add_argument(
        "-N",
        "--service-network",
        help="The name of the service docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_SERVICE_NETWORK"),
    )
    parser.add_argument(
        "-m",
        "--multiplier",
        help="Number of times to run for chains with _multiplied methods for",
        type=int,
        default=2,
    )
    parser.add_argument(
        "-s",
        "--seed",
        help="Seed to use for task PRNG (0 = unseeded)",
        type=int,
        default=0,
    )
    parser.add_argument(
        "testexpr",
        help="Specify the tests that should be run in the syntax expected by pytests -k flag, e.g. 'test_getflag' or 'not exploit'. If no expr is specified, all tests will be run.",
        nargs="?",
    )

    args = parser.parse_args()

    if args.service_network or args.checker_network:
        import docker

        client = docker.from_env()

        if args.service_network and not args.service_address:
            network = client.networks.get(args.service_network)
            args.service_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

        if args.checker_network and not args.checker_address:
            network = client.networks.get(args.service_network)
            args.checker_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

    if not args.checker_port:
        parser.print_usage()
        raise Exception(
            "Missing enochecker port, please set the ENOCHECKER_CHECKER_PORT environment variable"
        )
    if not args.service_address and not args.service_network:
        parser.print_usage()
        raise Exception(
            "Missing service address, please set the ENOCHECKER_SERVICE_ADDRESS environment variable"
        )

    logging.basicConfig(level=logging.INFO)
    run_tests(
        args.checker_address,
        args.checker_port,
        args.service_address,
        args.testexpr,
        args.multiplier,
        args.seed,
    )
