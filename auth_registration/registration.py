from common.crypto_utils import h_int, random_int, int_to_bytes, H
from common.models import SmartCard, UserRecord, GatewayNode


# -----------------------------
# Gateway helper functions
# -----------------------------

def is_id_available(gwn: GatewayNode, IDi: str) -> bool:
    """Check if IDi is already registered."""
    return IDi not in gwn.user_db

def gateway_register_user(gwn: GatewayNode, IDi: str, RPWi: int) -> SmartCard:
    """
    Implements GWN's part of registration:
    Input: {IDi, RPWi}
    Output: SmartCard with {Ai, Bi, n0, n, e, ai ⊕ Ai}
    and storing {IDi, r, ai, Honey_List = Null} in DB.
    """

    # Step 2: Check identity availability
    if not is_id_available(gwn, IDi):
        raise ValueError(f"Identity {IDi} is already registered. User must choose another ID.")

    # GWN selects two unique random numbers r and ai for Ui
    r = random_int(128)
    ai = random_int(128)

    # Compute Ai = h(h(IDi) ⊕ h(RPWi)) mod n0
    # Note: h_int returns an integer.
    # original logic: h(IDi) ^ h(RPWi) then hash the result.
    h_IDi = h_int(IDi)
    # RPWi is int, convert to bytes for consistency if needed, but h_int handles int/str/bytes.
    h_RPWi = h_int(RPWi)
    
    inner_xor = h_IDi ^ h_RPWi
    
    # Ai = h(inner_xor) mod n0
    Ai = h_int(inner_xor) % gwn.n0

    # Compute Ci = h(IDi ‖ dx ‖ r)
    Ci = h_int(IDi, gwn.dx, r)

    # Compute Bi = h(IDi ‖ RPWi) ⊕ Ci
    Bi_left = h_int(IDi, RPWi)
    Bi = Bi_left ^ Ci

    # Store {IDi, r, ai, Honey_List = Null} in backend database
    gwn.user_db[IDi] = UserRecord(
        IDi=IDi,
        r=r,
        ai=ai,
        honey_list=[]
    )

    # ai ⊕ Ai to be stored on the smart card
    ai_xor_Ai = ai ^ Ai

    # Return the smart card data to the user
    return SmartCard(
        ID=IDi,
        n0=gwn.n0,
        Ai=Ai,
        Bi=Bi,
        n=gwn.n,
        e=gwn.e,
        ai_xor_Ai=ai_xor_Ai
    )


# -----------------------------
# User-side logic
# -----------------------------

def user_registration_phase(gwn: GatewayNode, IDi: str, PWi: str) -> SmartCard:
    """
    Implements User + GWN steps of the registration phase.
    """

    # Step 1: On the user side
    b = random_int(128)

    # Compute RPWi = h(PWi ‖ b)
    RPWi = h_int(PWi, b)

    # Send {IDi, RPWi} to GWN and receive a smart card
    smart_card = gateway_register_user(gwn, IDi, RPWi)

    # Step 3: User inputs b into the card
    smart_card.b = b

    return smart_card

