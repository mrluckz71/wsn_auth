from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class SmartCard:
    """
    Data stored on the user's smart card.
    From Registration Step 2: {Ai, Bi, n0, n, e, ai_xor_Ai}
    From Registration Step 3: includes b
    """
    ID: str
    n0: int
    Ai: int
    Bi: int         # Storing as int to match registration.py logic mostly, but legacy used bytes. 
                    # The protocol description implies XOR operations which are easier on bytes usually, 
                    # but registration.py used ints for everything.
                    # I will standardize on bytes where possible in crypto_utils but keep consistent with registration.py if needed.
                    # Actually, registration.py computed Bi as int (xor).
                    # Let's support int/bytes flexibility or stick to one.
                    # Given the new reqs involve encryption (RSA) and hashes, bytes are often cleaner.
                    # But the registration.py used ints. I will stick to what registration.py produced for compatibility 
                    # or refactor registration.py to match this.
                    # Let's make this general.
    n: int
    e: int
    ai_xor_Ai: int
    b: Optional[int] = None

@dataclass
class UserRecord:
    """
    GWN database record for a user.
    From Registration Step 2: {IDi, r, ai, Honey_List}
    """
    IDi: str
    r: int
    ai: int
    honey_list: List[int] = field(default_factory=list)

@dataclass
class SensorRecord:
    """
    GWN database record for a sensor.
    """
    SID: str
    Pj: bytes  # Shared secret

@dataclass
class GatewayNode:
    """
    Represents the GWN with RSA keys and database.
    """
    e: int
    n: int
    dx: int
    n0: int
    user_db: Dict[str, UserRecord] = field(default_factory=dict)
    sensor_db: Dict[str, SensorRecord] = field(default_factory=dict)
