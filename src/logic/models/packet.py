from typing import Literal

from pydantic import BaseModel


class Packet(BaseModel):
    uid: int
    data: str
    protocol: Literal['http', 'https']
