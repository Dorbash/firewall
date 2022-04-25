import json
import os
from unittest.mock import AsyncMock

import pytest as pytest

from src.logic.firewall import Firewall
from src.logic.models.packet import Packet


@pytest.fixture
def postgres_client():
    return AsyncMock()


@pytest.fixture
def firewall(postgres_client):
    return Firewall(postgres_client)


def exactly_attack_packets():
    with open(os.path.join(os.path.dirname(__file__), 'resources/exactly_attacks_packets.json')) as f:
        return [Packet(**x) for x in json.load(f)]


def attack_packets_in_the_end():
    with open(os.path.join(os.path.dirname(__file__), 'resources/attack_packets_in_the_end.json')) as f:
        return [Packet(**x) for x in json.load(f)]


def attack_packets_in_the_beginning():
    with open(os.path.join(os.path.dirname(__file__), 'resources/attack_packets_in_the_beginning.json')) as f:
        return [Packet(**x) for x in json.load(f)]


def https_attack_packets():
    with open(os.path.join(os.path.dirname(__file__), 'resources/https_attack.json')) as f:
        return [Packet(**x) for x in json.load(f)]
