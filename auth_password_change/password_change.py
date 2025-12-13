from typing import Tuple, Optional
from common.crypto_utils import h_int, H, xor_bytes, int_to_bytes
from common.models import SmartCard

# -----------------------------
# Password Change Phase
# -----------------------------

def user_password_change(card: SmartCard, IDi: str, PWi: str, PW_new: str) -> bool:
    """
    Implements Section 6.4 Password Change Phase.
    
    Step 1. Ui enters IDi, PWi and new password PW_new.
    Step 2. Smart card authenticates Ui.
    Step 3. Smart card updates stored Ai, Bi with Anew, Bnew.
    
    Returns True if successful, False otherwise.
    """
    if card.b is None:
        print("Password Change: Smart card not initialized (missing b)")
        return False

    # Step 2: Authenticate Ui
    # RPWi = h(PWi || b)
    RPWi = h_int(PWi, card.b)
    
    # A' = h(h(IDi) XOR h(RPWi)) mod n0
    h_IDi = h_int(IDi)
    h_RPWi = h_int(RPWi)
    A_prime_val = h_IDi ^ h_RPWi
    A_prime = h_int(A_prime_val) % card.n0
    
    if A_prime != card.Ai:
        print("Password Change: Old password verification failed.")
        return False
        
    # Step 3: Update Smart Card
    # RPW_new = h(PW_new || b)
    RPW_new = h_int(PW_new, card.b)
    
    # Anew = h(h(IDi) XOR h(RPW_new)) mod n0
    h_RPW_new = h_int(RPW_new)
    A_new_val = h_IDi ^ h_RPW_new
    A_new = h_int(A_new_val) % card.n0
    
    # Bnew = Bi XOR h(IDi || RPWi) XOR h(IDi || RPW_new)
    # Recall Bi = h(IDi || RPWi) XOR Ci
    # So Bi XOR h(IDi || RPWi) recovers Ci.
    # Then Bnew = Ci XOR h(IDi || RPW_new).
    # This matches the formula: Bnew = Bi XOR h(IDi || RPWi) XOR h(IDi || RPW_new)
    # Assuming Bi is int as per our models.
    
    # Calculate terms
    term_old = h_int(IDi, RPWi)
    term_new = h_int(IDi, RPW_new)
    
    B_new = card.Bi ^ term_old ^ term_new
    
    # Update card
    # Implicit Step: We must also update ai_xor_Ai so that Login Step 1 works.
    # stored_val = ai XOR Aold.
    # we want new_stored_val = ai XOR Anew.
    # new_stored_val = stored_val XOR Aold XOR Anew.
    card.ai_xor_Ai = card.ai_xor_Ai ^ card.Ai ^ A_new
    
    card.Ai = A_new
    card.Bi = B_new
    
    return True
