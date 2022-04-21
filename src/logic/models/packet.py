from dataclasses import dataclass
from typing import Literal


@dataclass
class Packet:
    uid: int
    signature: bytes
    protocol: Literal['http', 'https']
