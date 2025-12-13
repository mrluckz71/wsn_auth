from typing import Tuple, Optional, Dict
from common.crypto_utils import h_int, H, xor_bytes, random_int, int_to_bytes, enc_sym, dec_sym, unpack_fields, pack_fields
from common.models import SmartCard, GatewayNode, UserRecord, SensorRecord

# -----------------------------
# Helper
# -----------------------------
def h_INT_xor_helper(a: int, b: int) -> int:
    return a ^ b

# -----------------------------
# Login & Authentication Phase
# -----------------------------

def user_login_request(card: SmartCard, ID_prime: str, PW_prime: str) -> Optional[dict]:
    """
    Step 1. Ui => GWN: Login request {Xi, D0, D1, M1, ni}
    Returns dictionary with message components and User state if local auth succeeds.
    """
    # Card computes RPW' = h(PW' || b)
    if card.b is None:
        pass # In a real card, b is stored. In simulation, b must be present.
        # If card.b is None, simplistic fail or assuming it was set.
        # But let's assume it IS set. If not, raise/return None.
        if card.b is None:
             print("User Login: Smart card has not been initialized with 'b'.")
             return None
    
    RPW_prime = h_int(PW_prime, card.b)
    
    # A' = h(h(ID') XOR h(RPW')) mod n0
    h_ID_prime = h_int(ID_prime)
    h_RPW_prime = h_int(RPW_prime)
    A_prime_val = h_INT_xor_helper(h_ID_prime, h_RPW_prime)
    A_prime = h_int(A_prime_val) % card.n0
    
    # Verify Ui
    if A_prime != card.Ai:
        print("User Login: Local authentication failed (A' != Ai).")
        return None
        
    # Select random ri
    ri = random_int(128)
    
    # User generates ephemeral RSA keys (ei, ni) and private key (di, ni)
    # We generate a valid pair where ni > ri (128 bits).
    # p = M127 (127 bits), q = 17 (prime). n = p*q approx 131 bits > 128.
    p_u = (1 << 127) - 1
    q_u = 17
    ni = p_u * q_u
    phi_u = (p_u - 1) * (q_u - 1)
    ei = 65537
    try:
        di = pow(ei, -1, phi_u)
    except ValueError:
        ei = 3
        di = pow(ei, -1, phi_u) 
    
    # Xi = ri^e mod n (Encryption using GWN public key stored on card)
    Xi = pow(ri, card.e, card.n)
    
    # C'i = Bi XOR h(ID' || RPW')
    Bi = card.Bi
    Ci_prime = Bi ^ h_int(ID_prime, RPW_prime)
    
    # D0 = h(ri || Xi || ni) XOR (ID' || C'i)
    mask_D0_bytes = H(ri, Xi, ni)
    plaintext_D0 = pack_fields(ID_prime, Ci_prime)
    D0 = enc_sym(mask_D0_bytes, plaintext_D0)
    
    # a'i = (ai XOR Ai) XOR A'
    ai_prime = card.ai_xor_Ai ^ A_prime
    
    # D1 = h(ri || C'i) XOR (ei || a'i)
    mask_D1_bytes = H(ri, Ci_prime)
    plaintext_D1 = pack_fields(ei, ai_prime)
    D1 = enc_sym(mask_D1_bytes, plaintext_D1)
    
    # M1 = h(Xi || ri || ei || ni || ID' || C'i)
    M1 = H(Xi, ri, ei, ni, ID_prime, Ci_prime)
    
    return {
        "Xi": Xi,
        "D0": D0,
        "D1": D1,
        "M1": M1,
        "ni": ni,
        
        # User internal state to keep for Step 5
        "ei": ei,
        "di": di,
        "ri": ri,
        "ID_prime": ID_prime,
        "Ci_prime": Ci_prime
    }

def gateway_login_processing(gwn: GatewayNode, request: dict) -> Optional[dict]:
    """
    Step 2. GWN => Sj : {D3, M2, Xi}
    """
    Xi = request["Xi"]
    D0 = request["D0"]
    D1 = request["D1"]
    M1 = request["M1"]
    ni = request["ni"]
    
    # Decrypt ri'' = Xi^dx mod n
    ri_prime_prime = pow(Xi, gwn.dx, gwn.n)
    
    # Retrieve ID'' || C'' = h(ri'' || Xi || ni) XOR D0
    mask_D0_bytes = H(ri_prime_prime, Xi, ni)
    plaintext_D0 = dec_sym(mask_D0_bytes, D0)
    
    try:
        fields_D0 = unpack_fields(plaintext_D0)
        ID_prime_prime = fields_D0[0].decode("utf-8")
        Ci_prime_prime = int.from_bytes(fields_D0[1], "big")
    except:
        print("GWN: Failed to unpack D0")
        return None
        
    # C* = h(ID'' || dx || r)
    if ID_prime_prime not in gwn.user_db:
        print("GWN: User not found in DB")
        return None
    
    user_rec = gwn.user_db[ID_prime_prime]
    Ci_star = h_int(ID_prime_prime, gwn.dx, user_rec.r)
    
    # Retrieve (e'' || a'') = h(r'' || C'') XOR D1
    mask_D1_bytes = H(ri_prime_prime, Ci_prime_prime)
    plaintext_D1 = dec_sym(mask_D1_bytes, D1)
    
    try:
        fields_D1 = unpack_fields(plaintext_D1)
        ei_prime_prime = int.from_bytes(fields_D1[0], "big")
        ai_prime_prime = int.from_bytes(fields_D1[1], "big")
    except:
        print("GWN: Failed to unpack D1")
        return None
        
    # Check a'' == ai
    if ai_prime_prime != user_rec.ai:
        print("GWN: ai mismatch. Terminating.")
        return None
        
    # Check M''1 == M1
    M1_expected = H(Xi, ri_prime_prime, ei_prime_prime, ni, ID_prime_prime, Ci_prime_prime)
    
    if M1_expected != M1:
        print("GWN: M1 mismatch. Possible attack.")
        if Ci_star != Ci_prime_prime:
             user_rec.honey_list.append(Ci_prime_prime)
        return None
        
    # Success so far.
    # Select sensor Sj
    if not gwn.sensor_db:
        print("GWN: No sensors registered.")
        return None
    
    target_SID = list(gwn.sensor_db.keys())[0]
    
    rn = random_int(64)
    key_Pj = H(target_SID, gwn.dx) 
    
    # D3 = Enc_P''j(e'' || ni || r'' || SIDj || rn || P''j)
    payload_D3 = pack_fields(
        ei_prime_prime,
        ni,
        ri_prime_prime,
        target_SID,
        rn,
        key_Pj
    )
    D3 = enc_sym(key_Pj, payload_D3)
    
    # M2 = h(P''j || e'' || r'' || ni || SIDj || rn)
    M2 = H(key_Pj, ei_prime_prime, ri_prime_prime, ni, target_SID, rn)
    
    return {
        "D3": D3,
        "M2": M2,
        "Xi": Xi,
        "target_SID": target_SID,
        "Pj": key_Pj, # Used by Sensor logic for simulation
        "gw_state": {
             "ri": ri_prime_prime,
             "rn": rn,
             "ei": ei_prime_prime,
             "Ci": Ci_prime_prime
        }
    }

def sensor_login_processing(sensor_data: SensorRecord, msg: dict) -> Optional[dict]:
    """
    Step 3. Sj => GWN: {M3, D5, Xj}
    """
    D3 = msg["D3"]
    M2 = msg["M2"]
    Xi = msg["Xi"]
    Pj = sensor_data.Pj # bytes
    
    # Decrypt D3
    plaintext_D3 = dec_sym(Pj, D3)
    try:
        fields = unpack_fields(plaintext_D3)
        ei_star = int.from_bytes(fields[0], "big")
        ni_star = int.from_bytes(fields[1], "big")
        ri_star = int.from_bytes(fields[2], "big")
        SID_star = fields[3].decode("utf-8")
        rn_star = int.from_bytes(fields[4], "big")
        Pj_star = fields[5]
    except:
        print("Sensor: Failed check unpack D3")
        return None
    
    if SID_star != sensor_data.SID:
        print(f"Sensor: SID mismatch {SID_star} != {sensor_data.SID}")
        return None
    
    if Pj_star != Pj:
        print("Sensor: Pj mismatch")
        return None
        
    M2_calc = H(Pj, ei_star, ri_star, ni_star, SID_star, rn_star)
    if M2_calc != M2:
        print("Sensor: M2 mismatch")
        return None
        
    rj = random_int(128)
    
    # Xj = rj^e* mod n*  (Encrypt using User's PK provided by GWN)
    Xj = pow(rj, ei_star, ni_star)
    
    # SKj = h(r* || rj || Xi || Xj)
    SKj = H(ri_star, rj, Xi, Xj)
    
    # M3 = h(Xj || Pj || r*n || r* || e*)
    M3 = H(Xj, Pj, rn_star, ri_star, ei_star)
    
    # D5 = h(SKj || Xj || r*)
    D5 = H(SKj, Xj, ri_star)
    
    return {
        "M3": M3,
        "D5": D5,
        "Xj": Xj,
        "SKj": SKj # For verification test
    }

def gateway_response_processing(gwn: GatewayNode, gw_state: dict, sensor_resp: dict) -> Optional[dict]:
    """
    Step 4. GWN => Ui
    """
    M3 = sensor_resp["M3"]
    Xj = sensor_resp["Xj"]
    D5 = sensor_resp["D5"]
    
    ri = gw_state["ri"]
    rn = gw_state["rn"]
    ei = gw_state["ei"]
    Ci = gw_state["Ci"]
    
    # Re-derive Pj for first sensor (Simplification)
    if not gwn.sensor_db: return None
    target_SID = list(gwn.sensor_db.keys())[0]
    Pj = H(target_SID, gwn.dx)
    
    M3_expected = H(Xj, Pj, rn, ri, ei)
    if M3_expected != M3:
        print("GWN: M3 mismatch")
        return None
        
    # M4 = h(D5 || C'' || Xj || r'')
    M4 = H(D5, Ci, Xj, ri)
    
    return {
        "M4": M4,
        "D5": D5,
        "Xj": Xj
    }

def user_final_verification(user_state: dict, card: SmartCard, gwn_resp: dict) -> Optional[bytes]:
    """
    Step 5. Users verifies and derives key SK.
    Returns SK if successful, else None.
    """
    M4 = gwn_resp["M4"]
    D5 = gwn_resp["D5"]
    Xj = gwn_resp["Xj"]
    
    ri = user_state["ri"]
    di = user_state["di"]
    ni = user_state["ni"]
    Ci_prime = user_state["Ci_prime"]
    
    # Verify M4 = h(D5 || C'i || Xj || ri)
    M4_calc = H(D5, Ci_prime, Xj, ri)
    if M4_calc != M4:
         print("User: M4 mismatch - GWN not authentic")
         return None
         
    # Decrypt Xj => r'j = Xj^di mod ni
    rj_prime = pow(Xj, di, ni)
    
    # SKi = h(ri || r'j || Xi || Xj)
    # Xi is needed. It was returned in user_state["Xi"]? No, currently step 1 returns it separate.
    # Using request["Xi"] implies we need to pass it.
    # Let's assume user kept Xi in user_state? Actually Xi is derived from ri.
    # Xi = ri^e mod n. User has card.e, card.n.
    Xi = pow(ri, card.e, card.n)
    
    SKi = H(ri, rj_prime, Xi, Xj)
    
    # Verify D5 = h(SKi || Xj || ri)
    D5_calc = H(SKi, Xj, ri)
    if D5_calc != D5:
         print("User: D5 mismatch - Sensor not authentic")
         return None
         
    return SKi
