from dataclasses import dataclass, field
from typing import Dict


@dataclass
class UserCard:
    """What the user’s smart card stores."""
    ID: str
    n0: int
    Ai: int
    Bi: bytes
    n: int
    e: int
    ai_xor_Ai: int
    b: int


@dataclass
class UserReg:
    """What the gateway stores about the user."""
    ID: str
    r: int               # auth_registration random
    ai: int              # secret for fuzzy verifier / honeyword logic
    hID: bytes           # h(ID)
    card: UserCard


@dataclass
class SensorReg:
    """What the gateway stores about a sensor node."""
    SID: str
    Pj: bytes            # shared secret between GWN and Sj


@dataclass
class SystemState:
    """Global gateway/system state."""
    e: int               # public exponent of GWN's RSA
    n: int               # modulus of GWN's RSA
    dx: int              # private exponent of GWN's RSA (x)
    n0: int              # fuzzy verifier modulus
    users_by_id: Dict[str, UserReg] = field(default_factory=dict)
    users_by_hid: Dict[bytes, UserReg] = field(default_factory=dict)
    sensors: Dict[str, SensorReg] = field(default_factory=dict)
