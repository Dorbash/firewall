import pytest

from src.logic.firewall import InvalidNumberOfConnectionsException
from src.logic.models.attack import Attack
from src.logic.models.connection import Connection
from src.logic.models.packet import Packet
from tests.logic.conftest import exactly_attack_packets, attack_packets_in_the_end, attack_packets_in_the_beginning, \
    https_attack_packets


class TestFirewall:
    # Test no connections
    async def test_top_connections_no_connections__should_return_empty(self, firewall, postgres_client):
        postgres_client.get_all_connections.return_value = []
        actual = await firewall.get_top_connections(5)
        assert len(actual) == 0

    # Test negative number
    async def test_top_connections_negative_number__should_throw_exception(self, firewall):
        with pytest.raises(InvalidNumberOfConnectionsException):
            await firewall.get_top_connections(-1)

    # Test postgres exception
    async def test_top_connections_postgres_exception__should_return_empty(self, firewall, postgres_client):
        postgres_client.get_all_connections.side_effect = Exception
        actual = await firewall.get_top_connections(5)
        assert len(actual) == 0

    # Test happy flow
    async def test_5_connections__should_return_top_3(self, firewall, postgres_client):
        postgres_client.get_all_connections.return_value = [Connection(source='1', dest='2', cpu=85),
                                                            Connection(source='3', dest='4', cpu=99),
                                                            Connection(source='5', dest='6', cpu=43),
                                                            Connection(source='7', dest='8', cpu=14),
                                                            Connection(source='9', dest='10', cpu=80)]
        actual = await firewall.get_top_connections(3)
        assert actual == [Connection(source='3', dest='4', cpu=99),
                          Connection(source='1', dest='2', cpu=85),
                          Connection(source='9', dest='10', cpu=80)]

    # Single happy flow for inspect_packets
    async def test_inspect_packets_attack_when_window_begins__should_return_attack(self, firewall, postgres_client):
        postgres_client.get_known_attacks.return_value = [Attack(name='RemoteCodeExecution', severity=5),
                                                          Attack(name='SQLInjection', severity=4)]
        packets = [Packet(uid=1, data='Remote', protocol='http'),
                   Packet(uid=2, data='Code', protocol='http'),
                   Packet(uid=3, data='Execution', protocol='http')]
        attack = await firewall.inspect_packets(packets)
        assert attack == Attack(name='RemoteCodeExecution', severity=5)

    # Happy flows for inspect_packets using parametrize
    @pytest.mark.parametrize("packets", [exactly_attack_packets(), attack_packets_in_the_end(),
                                         attack_packets_in_the_beginning()],
                             ids=['packets are exactly the same as attack',
                                  'packets contain attack at the end',
                                  'packets contain attack at the beginning'])
    async def test_inspect_packets_attack__should_return_attack(self, firewall, postgres_client,
                                                                packets):
        postgres_client.get_known_attacks.return_value = [Attack(name='RemoteCodeExecution', severity=5),
                                                          Attack(name='SQLInjection', severity=4)]
        attack = await firewall.inspect_packets(packets)
        assert attack == Attack(name='RemoteCodeExecution', severity=5)

    # Support Https attacks
    @pytest.mark.parametrize("packets", [exactly_attack_packets(), attack_packets_in_the_end(),
                                         attack_packets_in_the_beginning(), https_attack_packets()],
                             ids=['packets are exactly the same as attack',
                                  'packets contain attack at the end',
                                  'packets contain attack at the beginning',
                                  'https attack packets'])
    async def test_inspect_packets_attack_with_https__should_return_attack(self, firewall, postgres_client,
                                                                           packets):
        postgres_client.get_known_attacks.return_value = [Attack(name='RemoteCodeExecution', severity=5),
                                                          Attack(name='SQLInjection', severity=4)]
        attack = await firewall.inspect_packets(packets)
        assert attack == Attack(name='RemoteCodeExecution', severity=5)
