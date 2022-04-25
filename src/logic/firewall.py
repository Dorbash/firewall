from typing import Optional, List, Iterable

from src.logic.clients.postgres_client import PostgresClient
from src.logic.models.attack import Attack
from src.logic.models.packet import Packet


class InvalidNumberOfConnectionsException(Exception):
    pass


class Firewall:
    def __init__(self, postgres_client: PostgresClient):
        self._postgres_client = postgres_client

    async def get_top_connections(self, number_of_connections: int):
        if number_of_connections < 0:
            raise InvalidNumberOfConnectionsException('number of connections must be a positive number')
        try:
            all_connections = await self._postgres_client.get_all_connections()
        except:
            return []

        top_connections = sorted(all_connections, key=lambda x: x.cpu, reverse=True)
        return top_connections[:number_of_connections]

    async def inspect_packets(self, packets: List[Packet]) -> Optional[Attack]:
        known_attacks = await self._postgres_client.get_known_attacks()
        permutations = self._window(packets, 3)
        for permutation in permutations:
            network_signature = "".join([packet.data[::-1] if packet.protocol == 'https' else packet.data
                                         for packet in permutation])
            attack = [attack for attack in known_attacks if attack.name == network_signature]
            if attack:
                return attack[0]
        return None

    @staticmethod
    def _window(iterable, window_size) -> List[Iterable]:
        permutations = []
        for i in range(len(iterable) - window_size + 1):
            permutations.append(iterable[i: i + window_size])
        return permutations
