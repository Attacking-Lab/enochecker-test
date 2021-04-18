import base64
import logging
import os
import random
from typing import cast

import jsons
import pytest
import requests
from enochecker_core import (
    CheckerInfoMessage,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)

global_round_id = 0


def run_tests(host, port, service_address):
    r = requests.get(f"http://{host}:{port}/service")
    if r.status_code != 200:
        raise Exception("Failed to get /service from checker")
    info: CheckerInfoMessage = jsons.loads(
        r.content, CheckerInfoMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    logging.info(
        "Testing service %s, flagCount: %d, noiseCount: %d, havocCount: %d",
        info.service_name,
        info.flag_count,
        info.noise_count,
        info.havoc_count,
    )

    pytest.main(
        [
            f"--checker-address={host}",
            f"--checker-port={port}",
            f"--service-address={service_address}",
            f"--flag-count={info.flag_count}",
            f"--noise-count={info.noise_count}",
            f"--havoc-count={info.havoc_count}",
            os.path.realpath(__file__),
        ]
    )


@pytest.fixture
def checker_address(request):
    return request.config.getoption("--checker-address")


@pytest.fixture
def checker_port(request):
    return request.config.getoption("--checker-port")


@pytest.fixture
def service_address(request):
    return request.config.getoption("--service-address")


@pytest.fixture
def checker_url(checker_address, checker_port):
    return f"http://{checker_address}:{checker_port}"


def pytest_generate_tests(metafunc):
    flag_count: int = metafunc.config.getoption("--flag-count")
    noise_count: int = metafunc.config.getoption("--noise-count")
    havoc_count: int = metafunc.config.getoption("--havoc-count")

    if "flag_id" in metafunc.fixturenames:
        metafunc.parametrize("flag_id", range(flag_count))
    if "flag_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("flag_id_multiplied", range(flag_count, flag_count * 2))

    if "noise_id" in metafunc.fixturenames:
        metafunc.parametrize("noise_id", range(noise_count))
    if "noise_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("noise_id_multiplied", range(noise_count, noise_count * 2))

    if "havoc_id" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id", range(havoc_count))
    if "havoc_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id_multiplied", range(havoc_count, havoc_count * 2))


def generate_dummyflag() -> str:
    flag = "ENO" + base64.b64encode(random.randbytes(36)).decode()
    assert len(flag) == 51
    return flag


@pytest.fixture
def round_id():
    global global_round_id
    global_round_id += 1
    return global_round_id


def _test_putflag(
    flag,
    round_id,
    flag_id,
    service_address,
    checker_url,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    request_message = CheckerTaskMessage(
        round_id,
        "putflag",
        service_address,
        0,
        "service",
        0,
        "teamname",
        round_id,
        round_id,
        flag,
        flag_id,
        30000,
        60000,
    )
    msg = jsons.dumps(request_message, key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
    assert r.status_code == 200
    result_message: CheckerResultMessage = jsons.loads(
        r.content, CheckerResultMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    assert CheckerTaskResult(result_message.result) == expected_result


def _test_getflag(
    flag,
    round_id,
    flag_id,
    service_address,
    checker_url,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    request_message = CheckerTaskMessage(
        round_id,
        "getflag",
        service_address,
        0,
        "service",
        0,
        "teamname",
        round_id,
        round_id,
        flag,
        flag_id,
        30000,
        60000,
    )
    msg = jsons.dumps(request_message, key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
    assert r.status_code == 200
    result_message: CheckerResultMessage = jsons.loads(
        r.content, CheckerResultMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    assert CheckerTaskResult(result_message.result) == expected_result


def _test_putnoise(
    round_id,
    noise_id,
    service_address,
    checker_url,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    request_message = CheckerTaskMessage(
        round_id,
        "putnoise",
        service_address,
        0,
        "service",
        0,
        "teamname",
        round_id,
        round_id,
        None,
        noise_id,
        30000,
        60000,
    )
    msg = jsons.dumps(request_message, key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
    assert r.status_code == 200
    result_message: CheckerResultMessage = jsons.loads(
        r.content, CheckerResultMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    assert CheckerTaskResult(result_message.result) == expected_result


def _test_getnoise(
    round_id,
    noise_id,
    service_address,
    checker_url,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    request_message = CheckerTaskMessage(
        round_id,
        "getnoise",
        service_address,
        0,
        "service",
        0,
        "teamname",
        round_id,
        round_id,
        None,
        noise_id,
        30000,
        60000,
    )
    msg = jsons.dumps(request_message, key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
    assert r.status_code == 200
    result_message: CheckerResultMessage = jsons.loads(
        r.content, CheckerResultMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    assert CheckerTaskResult(result_message.result) == expected_result


def _test_havoc(
    round_id,
    havoc_id,
    service_address,
    checker_url,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    request_message = CheckerTaskMessage(
        round_id,
        "havoc",
        service_address,
        0,
        "service",
        0,
        "teamname",
        round_id,
        round_id,
        None,
        havoc_id,
        30000,
        60000,
    )
    msg = jsons.dumps(request_message, key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
    assert r.status_code == 200
    result_message: CheckerResultMessage = jsons.loads(
        r.content, CheckerResultMessage, key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE
    )
    assert CheckerTaskResult(result_message.result) == expected_result


def test_putflag(round_id, flag_id, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(flag, round_id, flag_id, service_address, checker_url)


def test_putflag_multiplied(round_id, flag_id_multiplied, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(flag, round_id, flag_id_multiplied, service_address, checker_url)


def test_getflag(round_id, flag_id, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(flag, round_id, flag_id, service_address, checker_url)
    _test_getflag(flag, round_id, flag_id, service_address, checker_url)


def test_getflag_multiplied(round_id, flag_id_multiplied, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(flag, round_id, flag_id_multiplied, service_address, checker_url)
    _test_getflag(flag, round_id, flag_id_multiplied, service_address, checker_url)


def test_putnoise(round_id, noise_id, service_address, checker_url):
    _test_putnoise(round_id, noise_id, service_address, checker_url)


def test_putnoise_multiplied(
    round_id, noise_id_multiplied, service_address, checker_url
):
    _test_putnoise(round_id, noise_id_multiplied, service_address, checker_url)


def test_getnoise(round_id, noise_id, service_address, checker_url):
    _test_putnoise(round_id, noise_id, service_address, checker_url)
    _test_getnoise(round_id, noise_id, service_address, checker_url)


def test_getnoise_multiplied(
    round_id, noise_id_multiplied, service_address, checker_url
):
    _test_putnoise(round_id, noise_id_multiplied, service_address, checker_url)
    _test_getnoise(round_id, noise_id_multiplied, service_address, checker_url)


def test_puthavoc(round_id, havoc_id, service_address, checker_url):
    _test_havoc(round_id, havoc_id, service_address, checker_url)


def test_puthavoc_multiplied(
    round_id, havoc_id_multiplied, service_address, checker_url
):
    _test_havoc(round_id, havoc_id_multiplied, service_address, checker_url)


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
