import base64
import secrets
from typing import Optional

import jsons
import pytest
import requests
from enochecker_core import (
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)

global_round_id = 0


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
    flag_variants: int = metafunc.config.getoption("--flag-variants")
    noise_variants: int = metafunc.config.getoption("--noise-variants")
    havoc_variants: int = metafunc.config.getoption("--havoc-variants")

    if "flag_id" in metafunc.fixturenames:
        metafunc.parametrize("flag_id", range(flag_variants))
    if "flag_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "flag_id_multiplied", range(flag_variants, flag_variants * 2)
        )
    if "flag_variants" in metafunc.fixturenames:
        metafunc.parametrize("flag_variants", [flag_variants])

    if "noise_id" in metafunc.fixturenames:
        metafunc.parametrize("noise_id", range(noise_variants))
    if "noise_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "noise_id_multiplied", range(noise_variants, noise_variants * 2)
        )
    if "noise_variants" in metafunc.fixturenames:
        metafunc.parametrize("noise_variants", [noise_variants])

    if "havoc_id" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id", range(havoc_variants))
    if "havoc_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "havoc_id_multiplied", range(havoc_variants, havoc_variants * 2)
        )
    if "havoc_variants" in metafunc.fixturenames:
        metafunc.parametrize("havoc_variants", [havoc_variants])


def generate_dummyflag() -> str:
    flag = "ENO" + base64.b64encode(secrets.token_bytes(36)).decode()
    assert len(flag) == 51
    return flag


@pytest.fixture
def round_id():
    global global_round_id
    global_round_id += 1
    return global_round_id


def _create_request_message(
    method: str,
    round_id: int,
    variant_id: int,
    service_address: str,
    flag: Optional[str] = None,
    unique_variant_index: Optional[int] = None,
) -> CheckerTaskMessage:
    if unique_variant_index is None:
        unique_variant_index = variant_id

    prefix = "havoc"
    if method in ("putflag", "getflag"):
        prefix = "flag"
    elif method in ("putnoise", "getnoise"):
        prefix = "noise"
    task_chain_id = f"{prefix}_s0_r{round_id}_t0_i{unique_variant_index}"

    return CheckerTaskMessage(
        task_id=round_id,
        method=CheckerMethod(method),
        address=service_address,
        team_id=0,
        team_name="teamname",
        current_round_id=round_id,
        related_round_id=round_id,
        flag=flag,
        variant_id=variant_id,
        timeout=30000,
        round_length=60000,
        task_chain_id=task_chain_id,
    )


def _jsonify_request_message(request_message: CheckerTaskMessage):
    return jsons.dumps(
        request_message,
        use_enum_name=False,
        key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
        strict=True,
    )


def _test_putflag(
    flag,
    round_id,
    flag_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "putflag",
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    msg = _jsonify_request_message(request_message)
    r = requests.post(
        f"{checker_url}", data=msg, headers={"content-type": "application/json"}
    )
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
    unique_variant_index=None,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "getflag",
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    msg = _jsonify_request_message(request_message)
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
    unique_variant_index=None,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "putnoise",
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    msg = _jsonify_request_message(request_message)
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
    unique_variant_index=None,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "getnoise",
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    msg = _jsonify_request_message(request_message)
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
    unique_variant_index=None,
    expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_OK,
):
    if unique_variant_index is None:
        unique_variant_index = havoc_id
    request_message = _create_request_message(
        "havoc",
        round_id,
        havoc_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    msg = _jsonify_request_message(request_message)
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


def test_putflag_multiplied(
    round_id, flag_id_multiplied, flag_variants, service_address, checker_url
):
    flag = generate_dummyflag()
    _test_putflag(
        flag,
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


def test_putflag_invalid_variant(round_id, flag_variants, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(
        flag,
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
    )


def test_getflag(round_id, flag_id, service_address, checker_url):
    flag = generate_dummyflag()
    _test_putflag(flag, round_id, flag_id, service_address, checker_url)
    _test_getflag(flag, round_id, flag_id, service_address, checker_url)


def test_getflag_multiplied(
    round_id, flag_id_multiplied, flag_variants, service_address, checker_url
):
    flag = generate_dummyflag()
    _test_putflag(
        flag,
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )
    _test_getflag(
        flag,
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


def test_getflag_invalid_variant(round_id, flag_variants, service_address, checker_url):
    flag = generate_dummyflag()
    _test_getflag(
        flag,
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
    )


def test_putnoise(round_id, noise_id, service_address, checker_url):
    _test_putnoise(round_id, noise_id, service_address, checker_url)


def test_putnoise_multiplied(
    round_id, noise_id_multiplied, noise_variants, service_address, checker_url
):
    _test_putnoise(
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


def test_putnoise_invalid_variant(
    round_id, noise_variants, service_address, checker_url
):
    _test_putnoise(
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
    )


def test_getnoise(round_id, noise_id, service_address, checker_url):
    _test_putnoise(round_id, noise_id, service_address, checker_url)
    _test_getnoise(round_id, noise_id, service_address, checker_url)


def test_getnoise_multiplied(
    round_id, noise_id_multiplied, noise_variants, service_address, checker_url
):
    _test_putnoise(
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )
    _test_getnoise(
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


def test_getnoise_invalid_variant(
    round_id, noise_variants, service_address, checker_url
):
    _test_getnoise(
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
    )


def test_havoc(round_id, havoc_id, service_address, checker_url):
    _test_havoc(round_id, havoc_id, service_address, checker_url)


def test_havoc_multiplied(
    round_id, havoc_id_multiplied, havoc_variants, service_address, checker_url
):
    _test_havoc(
        round_id,
        havoc_id_multiplied % havoc_variants,
        service_address,
        checker_url,
        unique_variant_index=havoc_id_multiplied,
    )


def test_havoc_invalid_variant(round_id, havoc_variants, service_address, checker_url):
    _test_havoc(
        round_id,
        havoc_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
    )
