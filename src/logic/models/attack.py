from pydantic import BaseModel


class Attack(BaseModel):
    name: str
    severity: int
