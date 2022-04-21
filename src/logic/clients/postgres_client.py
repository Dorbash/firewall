from typing import List

from src.logic.models.attack import Attack
from src.logic.models.connection import Connection


class PostgresClient:
    async def get_all_connections(self) -> List[Connection]:
        pass

    async def get_known_attacks(self) -> List[Attack]:
        pass
