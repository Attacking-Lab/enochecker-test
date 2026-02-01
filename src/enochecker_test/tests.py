import asyncio
import base64
import hashlib
import secrets
from typing import Optional
from random import Random, SystemRandom

import httpx
import jsons
import pytest
from enochecker_core import (
    CheckerInfoMessage,
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)

global_round_id = 0
FLAG_REGEX_ASCII = r"ENO[A-Za-z0-9+\/=]{48}"
FLAG_REGEX_UTF8 = r"🥺[A-Za-z0-9+\/=]{48}🥺🥺"
REQUEST_TIMEOUT = 10
TEST_REQUEST_TIMEOUT = 3600
CHAIN_ID_PREFIX = secrets.token_hex(20)

random_source = Random
task_id_random = random_source()


class TaskIdFactory:
    def __init__(self, seed):
        self.rand = random_source(seed)

    def __next__(self):
        return self.rand.randint(0, 1 << 48)


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
    global task_id_random
    global random_source

    seed: int = metafunc.config.getoption("--seed")
    if seed == 0:
        random_source = SystemRandom
    else:
        random_source = Random
    task_id_random = random_source(seed)

    flag_variants: int = metafunc.config.getoption("--flag-variants")
    noise_variants: int = metafunc.config.getoption("--noise-variants")
    havoc_variants: int = metafunc.config.getoption("--havoc-variants")
    exploit_variants: int = metafunc.config.getoption("--exploit-variants")
    test_variants: int = metafunc.config.getoption("--test-variants")
    multiplier: int = metafunc.config.getoption("--multiplier")

    if "flag_id" in metafunc.fixturenames:
        metafunc.parametrize("flag_id", range(flag_variants))
    if "flag_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "flag_id_multiplied", range(flag_variants, flag_variants * multiplier)
        )
    if "flag_variants" in metafunc.fixturenames:
        metafunc.parametrize("flag_variants", [flag_variants])

    if "noise_id" in metafunc.fixturenames:
        metafunc.parametrize("noise_id", range(noise_variants))
    if "noise_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "noise_id_multiplied", range(noise_variants, noise_variants * multiplier)
        )
    if "noise_variants" in metafunc.fixturenames:
        metafunc.parametrize("noise_variants", [noise_variants])

    if "havoc_id" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id", range(havoc_variants))
    if "havoc_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "havoc_id_multiplied", range(havoc_variants, havoc_variants * multiplier)
        )
    if "havoc_variants" in metafunc.fixturenames:
        metafunc.parametrize("havoc_variants", [havoc_variants])

    if "exploit_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "exploit_id_multiplied",
            range(exploit_variants, exploit_variants * multiplier),
        )
    if "exploit_id" in metafunc.fixturenames:
        metafunc.parametrize("exploit_id", range(exploit_variants))
    if "exploit_variants" in metafunc.fixturenames:
        metafunc.parametrize("exploit_variants", [exploit_variants])

    if "test_id" in metafunc.fixturenames:
        metafunc.parametrize("test_id", range(test_variants))

    if "encoding" in metafunc.fixturenames:
        metafunc.parametrize("encoding", ["ascii", "utf8"])

    if "multiplier" in metafunc.fixturenames:
        metafunc.parametrize("multiplier", [32, 128, 512])


def generate_dummyflag(encoding: str) -> str:
    if encoding == "utf8":
        flag = "🥺" + base64.b64encode(secrets.token_bytes(36)).decode() + "🥺🥺"
    else:
        flag = "ENO" + base64.b64encode(secrets.token_bytes(36)).decode()
    assert len(flag) == 51
    return flag


@pytest.fixture
def round_id():
    global global_round_id
    global_round_id += 1
    return global_round_id


@pytest.fixture()
def task_ids():
    return TaskIdFactory(task_id_random.randbytes(8))


def _flag_regex_for_encoding(encoding: str) -> str:
    if encoding == "utf8":
        return FLAG_REGEX_UTF8
    return FLAG_REGEX_ASCII


def _create_request_message(
    method: str,
    task_id: int,
    round_id: int,
    variant_id: int,
    service_address: str,
    flag: Optional[str] = None,
    unique_variant_index: Optional[int] = None,
    flag_regex: Optional[str] = None,
    flag_hash: Optional[str] = None,
    attack_info: Optional[str] = None,
    timeout: Optional[int] = None,
) -> CheckerTaskMessage:
    if unique_variant_index is None:
        unique_variant_index = variant_id

    prefix = "havoc"
    if method in ("putflag", "getflag"):
        prefix = "flag"
    elif method in ("putnoise", "getnoise"):
        prefix = "noise"
    elif method == "exploit":
        prefix = "exploit"
    task_chain_id = (
        f"{CHAIN_ID_PREFIX}_{prefix}_s0_r{round_id}_t0_i{unique_variant_index}"
    )

    return CheckerTaskMessage(
        task_id=task_id,
        method=CheckerMethod(method),
        address=service_address,
        team_id=0,
        team_name="teamname",
        current_round_id=round_id,
        related_round_id=round_id,
        flag=flag,
        variant_id=variant_id,
        timeout=timeout if timeout is not None else REQUEST_TIMEOUT * 1000,
        round_length=60000,
        task_chain_id=task_chain_id,
        flag_regex=flag_regex,
        flag_hash=flag_hash,
        attack_info=attack_info,
    )


async def _execute_request(
    request_message: CheckerTaskMessage,
    checker_url: str,
    expected_result: CheckerTaskResult,
    client: Optional[httpx.AsyncClient],
) -> CheckerResultMessage:
    if client is not None:
        r = await client.post(
            f"{checker_url}",
            json=request_message.model_dump(),
            timeout=REQUEST_TIMEOUT,
        )
    else:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{checker_url}",
                json=request_message.model_dump(),
                timeout=REQUEST_TIMEOUT,
            )
    print(r.content)
    result_message: CheckerResultMessage = CheckerResultMessage.model_validate_json(
        r.content
    )
    assert CheckerTaskResult(result_message.result) == expected_result, (
        f"\nMessage: {result_message.message}\n"
    )
    return result_message


async def _test_putflag(
    flag,
    task_id,
    round_id,
    flag_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
) -> Optional[str]:
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "putflag",
        task_id,
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    result_message: CheckerResultMessage = await _execute_request(
        request_message, checker_url, expected_result, client
    )
    return result_message.attack_info


async def _test_getflag(
    flag,
    task_id,
    round_id,
    flag_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "getflag",
        task_id,
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_putnoise(
    task_id,
    round_id,
    noise_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "putnoise",
        task_id,
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_getnoise(
    task_id,
    round_id,
    noise_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "getnoise",
        task_id,
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_havoc(
    task_id,
    round_id,
    havoc_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = havoc_id
    request_message = _create_request_message(
        "havoc",
        task_id,
        round_id,
        havoc_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_exploit(
    flag_regex,
    flag_hash,
    attack_info,
    task_id,
    round_id,
    exploit_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
) -> Optional[str]:
    if unique_variant_index is None:
        unique_variant_index = exploit_id
    request_message = _create_request_message(
        "exploit",
        task_id,
        round_id,
        exploit_id,
        service_address,
        unique_variant_index=unique_variant_index,
        flag_regex=flag_regex,
        flag_hash=flag_hash,
        attack_info=attack_info,
    )
    result_message: CheckerResultMessage = await _execute_request(
        request_message, checker_url, expected_result, client
    )
    return result_message.flag


async def _test_test(
    task_id,
    round_id,
    test_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = test_id
    request_message = _create_request_message(
        "test",
        task_id,
        round_id,
        test_id,
        service_address,
        unique_variant_index=unique_variant_index,
        timeout=TEST_REQUEST_TIMEOUT * 1000,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def test_putflag(
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )


async def test_putflag_multiplied(
    encoding,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


async def test_putflag_invalid_variant(
    encoding, task_ids, round_id, flag_variants, service_address, checker_url: str
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def test_getflag(
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )
    await _test_getflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )


async def test_getflag_after_second_putflag_with_same_variant_id(
    encoding, task_ids, round_id, flag_id, flag_variants, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )
    await _test_putflag(
        generate_dummyflag(encoding),
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        unique_variant_index=flag_id + flag_variants,
    )
    await _test_getflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )


async def test_getflag_twice(
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )
    await _test_getflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )
    await _test_getflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )


async def test_getflag_wrong_flag(
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag, next(task_ids), round_id, flag_id, service_address, checker_url
    )
    wrong_flag = generate_dummyflag(encoding)
    await _test_getflag(
        wrong_flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


async def test_getflag_without_putflag(
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


async def test_getflag_multiplied(
    encoding,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


async def test_getflag_invalid_variant(
    encoding, task_ids, round_id, flag_variants, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def test_putnoise(round_id, task_ids, noise_id, service_address, checker_url):
    await _test_putnoise(
        round_id, next(task_ids), noise_id, service_address, checker_url
    )


async def test_putnoise_multiplied(
    task_ids,
    round_id,
    noise_id_multiplied,
    noise_variants,
    service_address,
    checker_url,
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


async def test_putnoise_invalid_variant(
    task_ids, round_id, noise_variants, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def test_getnoise(task_ids, round_id, noise_id, service_address, checker_url):
    await _test_putnoise(
        round_id, next(task_ids), noise_id, service_address, checker_url
    )
    await _test_getnoise(
        round_id, next(task_ids), noise_id, service_address, checker_url
    )


async def test_getnoise_after_second_putnoise_with_same_variant_id(
    task_ids, round_id, noise_id, noise_variants, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids), round_id, noise_id, service_address, checker_url
    )
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
        unique_variant_index=noise_id + noise_variants,
    )
    await _test_getnoise(
        next(task_ids), round_id, noise_id, service_address, checker_url
    )


async def test_getnoise_twice(
    task_ids, round_id, noise_id, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids), round_id, noise_id, service_address, checker_url
    )
    await _test_getnoise(
        next(task_ids), round_id, noise_id, service_address, checker_url
    )
    await _test_getnoise(
        next(task_ids), round_id, noise_id, service_address, checker_url
    )


async def test_getnoise_without_putnoise(
    task_ids, round_id, noise_id, service_address, checker_url
):
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


async def test_getnoise_multiplied(
    task_ids,
    round_id,
    noise_id_multiplied,
    noise_variants,
    service_address,
    checker_url,
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


async def test_getnoise_invalid_variant(
    task_ids: TaskIdFactory,
    round_id: int,
    noise_variants: int,
    service_address: str,
    checker_url: str,
):
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def test_havoc(task_ids, round_id, havoc_id, service_address, checker_url):
    await _test_havoc(next(task_ids), round_id, havoc_id, service_address, checker_url)


async def test_havoc_multiplied(
    task_ids: TaskIdFactory,
    round_id: int,
    havoc_id_multiplied: int,
    havoc_variants: int,
    service_address: str,
    checker_url: str,
):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_id_multiplied % havoc_variants,
        service_address,
        checker_url,
        unique_variant_index=havoc_id_multiplied,
    )


async def test_havoc_invalid_variant(
    task_ids, round_id, havoc_variants, service_address, checker_url
):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def _do_exploit_run(
    encoding,
    task_ids: TaskIdFactory,
    round_id,
    exploit_id,
    flag_id,
    service_address,
    checker_url: str,
    tries: int = 1,
):
    try:
        flag = generate_dummyflag(encoding)
        flag_hash = hashlib.sha256(flag.encode()).hexdigest()

        attack_info = await _test_putflag(
            flag, next(task_ids), round_id, flag_id, service_address, checker_url
        )
        for _ in range(tries):
            found_flag = await _test_exploit(
                _flag_regex_for_encoding(encoding),
                flag_hash,
                attack_info,
                next(task_ids),
                round_id,
                exploit_id,
                service_address,
                checker_url,
            )
            if found_flag != flag:
                return False, Exception(
                    f"Found flag is incorrect. Expected: {flag}. Found: {found_flag}"
                )

        return True, None
    except Exception as e:
        return False, e


async def test_exploit_per_exploit_id(
    encoding,
    task_ids,
    round_id,
    exploit_id,
    flag_variants,
    service_address,
    checker_url,
):
    results = [
        await _do_exploit_run(
            encoding,
            task_ids,
            round_id,
            exploit_id,
            flag_id,
            service_address,
            checker_url,
        )
        for flag_id in range(flag_variants)
    ]
    if any(r[0] for r in results):
        return
    raise Exception([r[1] for r in results])


async def test_exploit_twice(
    encoding,
    task_ids,
    round_id,
    exploit_id,
    flag_variants,
    service_address,
    checker_url: str,
):
    results = [
        await _do_exploit_run(
            encoding,
            task_ids,
            round_id,
            exploit_id,
            flag_id,
            service_address,
            checker_url,
            tries=2,
        )
        for flag_id in range(flag_variants)
    ]
    if any(r[0] for r in results):
        return
    raise Exception([r[1] for r in results])


# async def test_exploit_multiplied(
#     encoding,
#     task_ids,
#     round_id,
#     exploit_id_multiplied,
#     exploit_variants,
#     flag_variants,
#     service_address,
#     checker_url,
# ):
#     await _test_exploit(
#         encoding,
#         task_ids,
#         round_id,
#         exploit_id_multiplied % exploit_variants,
#         flag_variants,
#         service_address,
#         checker_url,
#     )


async def test_flagstore_exploitable(
    encoding,
    task_ids,
    round_id,
    exploit_id,
    exploit_variants,
    flag_variants,
    flag_id,
    service_address,
    checker_url: str,
):
    if flag_variants == 0:
        return
    results = [
        await _do_exploit_run(
            encoding,
            task_ids,
            round_id,
            exploit_id,
            flag_id,
            service_address,
            checker_url,
        )
    ]
    if any(r[0] for r in results):
        return
    raise Exception([r[1] for r in results])


async def test_exploit_per_flag_id(
    encoding,
    task_ids,
    round_id,
    exploit_variants,
    flag_id,
    service_address,
    checker_url,
):
    results = [
        await _do_exploit_run(
            encoding,
            task_ids,
            round_id,
            exploit_id,
            flag_id,
            service_address,
            checker_url,
        )
        for exploit_id in range(exploit_variants)
    ]
    if any(r[0] for r in results):
        return
    raise Exception([r[1] for r in results])


async def test_exploit_invalid_variant(
    encoding, task_ids, round_id, exploit_variants, service_address, checker_url: str
):
    flag = generate_dummyflag(encoding)
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    await _test_exploit(
        _flag_regex_for_encoding(encoding),
        flag_hash,
        None,
        next(task_ids),
        round_id,
        exploit_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


async def test_checker_info_message_case(
    checker_url,
):
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{checker_url}/service",
            timeout=REQUEST_TIMEOUT,
        )
    assert r.status_code == 200
    camelcase_json = jsons.dumps(
        r.json(), key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE, sort_keys=True
    )
    assert jsons.dumps(r.json(), sort_keys=True) == camelcase_json
    info_message = CheckerInfoMessage.model_validate_json(r.text)
    assert r.json() == info_message.model_dump(by_alias=True)


async def test_test(task_ids, round_id, test_id, service_address, checker_url):
    await _test_test(next(task_ids), round_id, test_id, service_address, checker_url)


@pytest.mark.stress
async def test_stress(
    encoding,
    task_ids,
    round_id,
    flag_variants,
    noise_variants,
    havoc_variants,
    service_address,
    checker_url,
    multiplier,
):
    transport = httpx.AsyncHTTPTransport(
        limits=httpx.Limits(max_connections=1000, max_keepalive_connections=200)
    )
    async with httpx.AsyncClient(transport=transport) as client:

        async def flag_fn(i, flag_id):
            flag = generate_dummyflag(encoding)
            await _test_putflag(
                flag,
                next(task_ids),
                round_id,
                flag_id,
                service_address,
                checker_url,
                unique_variant_index=i * flag_variants + flag_id,
                client=client,
            )

        async def noise_fn(i, noise_id):
            await _test_putnoise(
                next(task_ids),
                round_id,
                noise_id,
                service_address,
                checker_url,
                unique_variant_index=i * noise_variants + noise_id,
                client=client,
            )

        async def havoc_fn(i, havoc_id):
            await _test_havoc(
                next(task_ids),
                round_id,
                havoc_id,
                service_address,
                checker_url,
                unique_variant_index=i * havoc_variants + havoc_id,
                client=client,
            )

        awaitables = []
        for i in range(multiplier):
            for flag_id in range(flag_variants):
                awaitables.append(flag_fn(i, flag_id))
            for noise_id in range(noise_variants):
                awaitables.append(noise_fn(i, noise_id))
            for havoc_id in range(havoc_variants):
                awaitables.append(havoc_fn(i, havoc_id))

        await asyncio.gather(*awaitables)
