import sys
from unittest.mock import MagicMock, patch

from enochecker_test import main


def _fake_docker_client(gateways: dict[str, str]) -> MagicMock:
    client = MagicMock()

    def get_network(name):
        network = MagicMock()
        network.attrs = {"IPAM": {"Config": [{"Gateway": gateways[name]}]}}
        return network

    client.networks.get.side_effect = get_network
    return client


def _run_main(argv):
    with patch.object(sys, "argv", ["enochecker_test", *argv]):
        main.main()


def test_checker_network_resolves_checker_address_from_checker_network():
    client = _fake_docker_client({"checkernet": "10.0.1.1", "servicenet": "10.0.2.1"})
    with (
        patch("docker.from_env", return_value=client),
        patch.object(main, "run_tests") as run_tests,
    ):
        _run_main(
            [
                "-p",
                "1234",
                "-a",
                "",
                "-n",
                "checkernet",
                "-A",
                "10.9.9.9",
                "putflag",
            ]
        )

    client.networks.get.assert_called_once_with("checkernet")
    checker_address = run_tests.call_args[0][0]
    assert checker_address == "10.0.1.1"


def test_checker_and_service_networks_resolve_independently():
    client = _fake_docker_client({"checkernet": "10.0.1.1", "servicenet": "10.0.2.1"})
    with (
        patch("docker.from_env", return_value=client),
        patch.object(main, "run_tests") as run_tests,
    ):
        _run_main(
            [
                "-p",
                "1234",
                "-a",
                "",
                "-n",
                "checkernet",
                "-N",
                "servicenet",
                "putflag",
            ]
        )

    assert {c.args[0] for c in client.networks.get.call_args_list} == {
        "checkernet",
        "servicenet",
    }
    checker_address, _, service_address = run_tests.call_args[0][:3]
    assert checker_address == "10.0.1.1"
    assert service_address == "10.0.2.1"
