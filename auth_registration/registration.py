import os
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# -----------------------------
# Helper functions
# -----------------------------

def h(*parts: bytes) -> int:
    """
    One-way hash function h(·) -> integer.
    Concatenates all byte parts and hashes them with SHA-256.
    Returns an integer (so we can do mod, XOR, etc.).
    """
    data = b"".join(parts)
    digest = hashlib.sha256(data).digest()
    # Convert to integer (big-endian)
    return int.from_bytes(digest, byteorder="big")


def random_int(bits: int) -> int:
    """
    Returns a random integer with the specified number of bits.
    """
    return int.from_bytes(os.urandom(bits // 8), byteorder="big")


def int_to_bytes(x: int) -> bytes:
    """
    Convert an integer to the minimal number of bytes needed (big-endian).
    This avoids OverflowError for large integers.
    """
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


# -----------------------------
# Data models
# -----------------------------

@dataclass
class SmartCard:
    """
    Data that ends up stored on the user's smart card.
    """
    Ai: int
    Bi: int
    n0: int
    n: int
    e: int
    ai_xor_Ai: int
    # we can store 'b' here after step 3 of registration
    b: Optional[int] = None


@dataclass
class UserRecord:
    """
    What the GWN stores in its backend database for each user.
    """
    IDi: str
    r: int
    ai: int
    honey_list: List[int] = field(default_factory=list)


class GatewayNode:
    """
    Represents the GWN with:
    - RSA keys: (e, n) public, (dx, n) private
    - system parameter n0
    - user database
    """

    def __init__(self, e: int, n: int, dx: int, n0: int):
        self.e = e
        self.n = n
        self.dx = dx  # long-term secret key
        self.n0 = n0
        self.user_db: Dict[str, UserRecord] = {}

    def is_id_available(self, IDi: str) -> bool:
        """
        Check if IDi is already registered.
        """
        return IDi not in self.user_db

    def register_user(self, IDi: str, RPWi: int) -> SmartCard:
        """
        Implements GWN's part of registration:

        Input: {IDi, RPWi}
        Output: SmartCard with {Ai, Bi, n0, n, e, ai ⊕ Ai}
        and storing {IDi, r, ai, Honey_List = Null} in DB.

        This corresponds to:
        Step 2 of the registration phase in the WSN scheme.
        """

        # Step 2: Check identity availability
        if not self.is_id_available(IDi):
            raise ValueError(f"Identity {IDi} is already registered. User must choose another ID.")

        # GWN selects two unique random numbers r and ai for Ui
        # (sizes here are arbitrary; in practice you choose secure sizes)
        r = random_int(128)   # example 128-bit random
        ai = random_int(128)  # example 128-bit random

        # Compute Ai = h(h(IDi) ⊕ h(RPWi)) mod n0
        h_IDi = h(IDi.encode("utf-8"))
        h_RPWi = h(RPWi.to_bytes(32, "big"))  # 32 bytes for SHA-256-sized int
        inner_xor = h_IDi ^ h_RPWi

        # Convert inner_xor to bytes (32 bytes to match SHA-256 size).
        # If you want to be super safe, you can also use int_to_bytes(inner_xor).
        Ai = h(inner_xor.to_bytes(32, "big")) % self.n0

        # Compute Ci = h(IDi ‖ dx ‖ r)
        Ci = h(
            IDi.encode("utf-8"),
            int_to_bytes(self.dx),        # dx might be large (e.g., 2048 bits)
            r.to_bytes(16, "big")         # 16 bytes for 128-bit r
        )

        # Compute Bi = h(IDi ‖ RPWi) ⊕ Ci
        Bi_left = h(
            IDi.encode("utf-8"),
            RPWi.to_bytes(32, "big")
        )
        Bi = Bi_left ^ Ci

        # Store {IDi, r, ai, Honey_List = Null} in backend database
        self.user_db[IDi] = UserRecord(
            IDi=IDi,
            r=r,
            ai=ai,
            honey_list=[]  # initially empty
        )

        # ai ⊕ Ai to be stored on the smart card
        ai_xor_Ai = ai ^ Ai

        # Return the smart card data to the user
        return SmartCard(
            Ai=Ai,
            Bi=Bi,
            n0=self.n0,
            n=self.n,
            e=self.e,
            ai_xor_Ai=ai_xor_Ai
        )


# -----------------------------
# User-side logic
# -----------------------------

def user_registration_phase(gwn: GatewayNode, IDi: str, PWi: str) -> SmartCard:
    """
    Implements User + GWN steps of the registration phase:

    Step 1 (User):
        - choose PWi, IDi and random b
        - compute RPWi = h(PWi ‖ b)
        - send {IDi, RPWi} to GWN

    Step 2 (GWN):
        - handled by gwn.register_user()

    Step 3 (User):
        - input b into the card (we just store it in the SmartCard object)
    """

    # Step 1: On the user side
    # Choose random b (here 128 bits for example)
    b = random_int(128)

    # Compute RPWi = h(PWi ‖ b)
    RPWi = h(
        PWi.encode("utf-8"),
        b.to_bytes(16, "big")  # 16 bytes for 128-bit b
    )

    # Send {IDi, RPWi} to GWN and receive a smart card
    smart_card = gwn.register_user(IDi, RPWi)

    # Step 3: User inputs b into the card
    # We store it in the SmartCard object for later use.
    smart_card.b = b

    return smart_card
