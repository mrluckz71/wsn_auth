import secrets
from typing import Tuple

from .crypto_utils import (
    HASH_LEN,
    H,
    xor_bytes,
    enc_sym,
    dec_sym,
    pack_fields,
    unpack_fields,
)
from .models import SystemState, UserCard, UserReg, SensorReg


# ============================================================
#  System setup
# ============================================================

def setup_system() -> SystemState:
    """
    Initialize the GWN (Gateway Node) with:

      - RSA key (e, dx, n)
      - a small modulus n0 for the fuzzy verifier

    For simplicity we use two known primes and do not implement
    a general prime generator.
    """
    # Mersenne primes (toy, not secure; DO NOT use in real life)
    p = (1 << 61) - 1
    q = (1 << 59) - 1
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    dx = pow(e, -1, phi)  # modular inverse of e modulo phi

    # Choose a small n0 (2^4 <= n0 <= 2^8). We pick 2^6 = 64.
    n0 = 64

    return SystemState(e=e, n=n, dx=dx, n0=n0)


# ============================================================
#  Registration
# ============================================================

def register_sensor(sys: SystemState, SID: str) -> SensorReg:
    """
    Sensor node auth_registration.

    Pj = H(SID, x), where x is the system long-term secret (dx here).
    """
    Pj = H(SID, sys.dx)
    sreg = SensorReg(SID=SID, Pj=Pj)
    sys.sensors[SID] = sreg
    return sreg


def register_user(sys: SystemState, ID: str, PW: str) -> UserCard:
    """
    User auth_registration (Section 6.2-style).

    High-level:
      - User picks ID, PW, random b, computes RPW = H(PW, b).
      - GWN picks r and ai, computes Ai, Bi, etc.
      - GWN returns the smart-card data; user stores b in the card.
    """
    if ID in sys.users_by_id:
        raise ValueError("ID already registered")

    # "User side"
    b = secrets.randbits(64)
    RPW = H(PW, b)

    # Gateway side
    hID = H(ID)
    hRPW = H(RPW)
    xor_id_rpw = xor_bytes(hID, hRPW)
    Ai_val = int.from_bytes(H(xor_id_rpw), "big") % sys.n0

    r = secrets.randbits(64)
    Ci = H(ID, sys.dx, r)
    Bi = xor_bytes(H(ID, RPW), Ci)

    ai = secrets.randbits(32)  # fuzzy verifier / honeyword secret

    card = UserCard(
        ID=ID,
        n0=sys.n0,
        Ai=Ai_val,
        Bi=Bi,
        n=sys.n,
        e=sys.e,
        ai_xor_Ai=ai ^ Ai_val,
        b=b,
    )

    ureg = UserReg(ID=ID, r=r, ai=ai, hID=hID, card=card)
    sys.users_by_id[ID] = ureg
    sys.users_by_hid[hID] = ureg

    return card


# ============================================================
#  Login & Authentication
# ============================================================

def login_and_authenticate(
    sys: SystemState,
    card: UserCard,
    PW: str,
    SID: str,
) -> Tuple[bool, bytes]:
    """
    Run the full login & authentication phase (Section 6.3)
    for one user and one sensor.

    All three parties (Ui, GWN, Sj) are simulated within this function.

    Returns:
        (success_flag, session_key_SK)

    On success:
        SK = H(ri, rj, Xi, Xj)

    On failure:
        (False, b"")
    """

    # --------------------------------------
    # Step 1. Ui  ⇒  GWN (simulated)
    # --------------------------------------
    ID = card.ID
    sensor = sys.sensors.get(SID)
    if sensor is None:
        raise ValueError(f"Unknown sensor SID: {SID}")

    # User inputs ID, PW; card uses stored b
    RPW_prime = H(PW, card.b)
    hID = H(ID)
    hRPW_prime = H(RPW_prime)
    xor_id_rpw_prime = xor_bytes(hID, hRPW_prime)
    A_prime = int.from_bytes(H(xor_id_rpw_prime), "big") % card.n0

    # Local verification
    if A_prime != card.Ai:
        print("Card: password/ID verification failed")
        return False, b""

    # Card chooses ri and uses GWN's RSA for encryption
    ri = secrets.randbits(128)
    ei = 65537
    ni = sys.n

    Xi = pow(ri, sys.e, sys.n)  # encrypt ri with GWN's public key

    # Recover Ci using Bi and new RPW'
    Ci_prime = xor_bytes(card.Bi, H(ID, RPW_prime))

    # Construct D0: encode hID and Ci' with reversible padding
    pad_id = H("ID-pad", ri, Xi, ni)
    pad_C = H("C-pad", ri, Xi, ni)
    D0 = xor_bytes(hID, pad_id) + xor_bytes(Ci_prime, pad_C)  # 32 + 32 = 64 bytes

    # Recover ai from (ai xor Ai) ^ A'
    ai_prime = card.ai_xor_Ai ^ A_prime

    # Pack (ei, ai_prime) into 32 bytes for XOR with hash
    ei_bytes = ei.to_bytes(16, "big")
    ai_bytes = ai_prime.to_bytes(16, "big")
    pair_ea = ei_bytes + ai_bytes

    pad_D1 = H(ri, Ci_prime)
    D1 = xor_bytes(pad_D1, pair_ea)

    # Message authentication code M1
    M1 = H(Xi, ri, ei, ni, ID, Ci_prime)

    # Ui sends {Xi, D0, D1, M1, ni} to GWN
    # --------------------------------------
    # Step 2. GWN side processing
    # --------------------------------------

    # Decrypt ri from Xi
    ri_dec = pow(Xi, sys.dx, sys.n)

    # Recover hID and Ci from D0
    d0_first, d0_second = D0[:HASH_LEN], D0[HASH_LEN:]
    pad_id_g = H("ID-pad", ri_dec, Xi, ni)
    pad_C_g = H("C-pad", ri_dec, Xi, ni)
    hID_recv = xor_bytes(d0_first, pad_id_g)
    Ci_from_D0 = xor_bytes(d0_second, pad_C_g)

    # Find user by hID
    ureg = sys.users_by_hid.get(hID_recv)
    if ureg is None:
        print("GWN: unknown user (hID not found)")
        return False, b""

    # Check Ci
    Ci_star = H(ureg.ID, sys.dx, ureg.r)
    if Ci_star != Ci_from_D0:
        print("GWN: Ci mismatch – possible attack")
        return False, b""

    # Recover (ei, ai') from D1
    pad_D1_g = H(ri_dec, Ci_from_D0)
    pair_ea_g = xor_bytes(D1, pad_D1_g)
    ei_recv = int.from_bytes(pair_ea_g[:16], "big")
    ai_recv = int.from_bytes(pair_ea_g[16:], "big")

    # Check ai'
    if ai_recv != ureg.ai:
        print("GWN: ai mismatch – reject")
        return False, b""

    # Check M1
    M1_expected = H(Xi, ri_dec, ei_recv, ni, ureg.ID, Ci_from_D0)
    if M1_expected != M1:
        print("GWN: M1 mismatch – suspicious login")
        return False, b""

    # GWN authenticates user, now involves sensor Sj
    rn = secrets.randbits(64)
    Pj = H(SID, sys.dx)   # shared secret with Sj

    # Construct D3 = Enc_{Pj}(ei, ni, ri, SID, rn, Pj)
    plaintext_D3 = pack_fields(ei_recv, ni, ri_dec, SID, rn, Pj)
    D3 = enc_sym(Pj, plaintext_D3)

    # MAC for sensor
    M2 = H(Pj, ei_recv, ri_dec, ni, SID, rn)

    # Send {D3, M2, Xi} to Sj
    # --------------------------------------
    # Step 3. Sensor Sj processing
    # --------------------------------------

    plaintext_D3_s = dec_sym(Pj, D3)
    fields = unpack_fields(plaintext_D3_s)
    if len(fields) != 6:
        print("Sensor: invalid D3 field count")
        return False, b""

    ei_s = int.from_bytes(fields[0], "big")
    ni_s = int.from_bytes(fields[1], "big")
    ri_s = int.from_bytes(fields[2], "big")
    SID_s = fields[3].decode("utf-8")
    rn_s = int.from_bytes(fields[4], "big")
    Pj_s = fields[5]

    if SID_s != SID or Pj_s != Pj:
        print("Sensor: SID/Pj mismatch – reject")
        return False, b""

    M2_expected = H(Pj, ei_s, ri_s, ni_s, SID, rn_s)
    if M2_expected != M2:
        print("Sensor: M2 mismatch – reject")
        return False, b""

    # Sensor chooses rj, computes Xj and SKj
    rj = secrets.randbits(128)
    Xj = pow(rj, ei_s, ni_s)
    SKj = H(ri_s, rj, Xi, Xj)  # session key at sensor

    M3 = H(Xj, Pj, rn_s, ri_s, ei_s)
    D5 = H(SKj, Xj, ri_s)

    # Sensor sends {M3, D5, Xj} to GWN
    # --------------------------------------
    # Step 4. GWN verifies Sj and forwards to Ui
    # --------------------------------------

    M3_expected_g = H(Xj, Pj, rn, ri_dec, ei_recv)
    if M3_expected_g != M3:
        print("GWN: M3 mismatch – sensor not trusted")
        return False, b""

    # GWN forwards to Ui, with M4 = H(D5, Ci, Xj, ri)
    M4 = H(D5, Ci_from_D0, Xj, ri_dec)

    # Send {M4, D5, Xj} to Ui
    # --------------------------------------
    # Step 5. Ui verifies sensor and derives SK
    # --------------------------------------

    Ci_prime_again = xor_bytes(card.Bi, H(ID, RPW_prime))
    if Ci_prime_again != Ci_prime:
        print("Ui: internal Ci mismatch (should not happen)")
        return False, b""

    M4_expected_u = H(D5, Ci_prime_again, Xj, ri)
    if M4_expected_u != M4:
        print("Ui: M4 mismatch – reject")
        return False, b""

    # Derive session key as in the scheme
    SK = H(ri, rj, Xi, Xj)

    return True, SK
