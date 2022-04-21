from pydantic import BaseModel


class Attack(BaseModel):
    name: str
    severity: int

    def signature(self) -> bytes:
        return self.name.encode()
