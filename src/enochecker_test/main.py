import argparse
import logging
import os
import sys
from typing import Optional

import httpx
import pytest
from enochecker_core import CheckerInfoMessage


def run_tests(
    host: str,
    port: int,
    service_address: str,
    test_expr: str,
    multiplier: int,
    seed: int,
    stress: bool,
    flag_types: str = "ascii,utf8",
    exploit_timeout: Optional[int] = None,
    group_expr: Optional[str] = None,
):
    transport = httpx.HTTPTransport(retries=10)
    with httpx.Client(transport=transport) as client:
        r = client.get(f"http://{host}:{port}/service")
    if r.status_code != 200:
        raise Exception("Failed to get /service from checker")
    try:
        info = CheckerInfoMessage.model_validate_json(r.text)
    except ValueError as e:
        raise Exception(
            "Failed to parse /service from checker. Note that exploitVariants is now "
            "the list of flag variants targeted by each exploit, not their count."
        ) from e
    logging.info(
        "Testing service %s, flagVariants: %d, noiseVariants: %d, havocVariants: %d, exploitVariants: %s, testVariants: %d",
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
        f"--service-name={info.service_name}",
        f"--flag-variants={info.flag_variants}",
        f"--noise-variants={info.noise_variants}",
        f"--havoc-variants={info.havoc_variants}",
        "--exploit-variants=" + ",".join(str(v) for v in info.exploit_variants),
        f"--test-variants={info.test_variants}",
        f"--multiplier={multiplier}",
        f"--seed={seed}",
        "--durations=0",
        "-v",
        "-o",
        "asyncio_mode=auto",
    ]
    if stress:
        test_args.append("--stress")
    test_args.append(f"--flag-types={flag_types}")
    if exploit_timeout is not None:
        test_args.append(f"--exploit-timeout={exploit_timeout}")
    if group_expr:
        test_args.append("-m")
        test_args.append(group_expr)

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

By default all tests run. testexpr (pytest's -k) selects/deselects individual
tests by name; --groups (pytest's -m) selects/deselects whole groups by their
@pytest.mark.<group> marker. Both take a boolean expression (and/or/not/
parens) and, if both are given, a test must match both:

    $ enochecker_test --groups "putflag or getflag" ...
    $ enochecker_test --groups "not exploit" "not test_getflag_twice" ...
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
        "--stress",
        help="Enable stress tests",
        action="store_true",
    )
    parser.add_argument(
        "--flag-types",
        help="Comma-separated list of flag encodings to test (default: ascii,utf8)",
        default=os.environ.get("ENOCHECKER_FLAG_TYPES", "ascii,utf8"),
    )
    parser.add_argument(
        "--exploit-timeout",
        help="Timeout in seconds given to the checker for exploit tasks specifically "
        "(defaults to the same timeout used for all other checker methods, "
        "or ENOCHECKER_EXPLOIT_TIMEOUT if set)",
        type=int,
        default=os.environ.get("ENOCHECKER_EXPLOIT_TIMEOUT"),
    )
    parser.add_argument(
        "-g",
        "--groups",
        dest="group_expr",
        metavar="EXPR",
        help="Select tests by group in the syntax expected by pytest's -m flag, "
        "e.g. 'putflag or getflag' or 'not exploit'. Groups: putflag, getflag, "
        "putnoise, getnoise, havoc, exploit, test, stress, misc. Combines with "
        "testexpr: a test must match both if both are given. If no expr is "
        "specified, no group filtering is applied.",
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
        args.stress,
        args.flag_types,
        args.exploit_timeout,
        args.group_expr,
    )
