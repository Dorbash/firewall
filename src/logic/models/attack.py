from dataclasses import dataclass


@dataclass
class Attack:
    name: str
    severity: int

    def signature(self) -> bytes:
        return self.name.encode()
