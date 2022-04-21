from dataclasses import dataclass


@dataclass
class Connection:
    source: str
    dest: str
    cpu: float
