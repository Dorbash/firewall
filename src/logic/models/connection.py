from pydantic import BaseModel


class Connection(BaseModel):
    source: str
    dest: str
    cpu: float
