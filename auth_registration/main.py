from common.test_utils import setup_test_gwn
from auth_registration.registration import user_registration_phase

# -----------------------------
# Example usage / demo
# -----------------------------
if __name__ == "__main__":
    # 1) GWN initialization
    gwn = setup_test_gwn()

    # 2) User chooses ID and password and runs auth_registration
    IDi = "alice123"
    PWi = "SuperSecurePassword!"

    smart_card = user_registration_phase(gwn, IDi, PWi)

    print("=== Smart Card Issued to User ===")
    print(f"Ai        = {smart_card.Ai}")
    print(f"Bi        = {smart_card.Bi}")
    print(f"n0        = {smart_card.n0}")
    print(f"n         = {smart_card.n}")
    print(f"e         = {smart_card.e}")
    print(f"ai ⊕ Ai   = {smart_card.ai_xor_Ai}")
    print(f"b (local) = {smart_card.b}")

    print("\n=== GWN Database Entry ===")
    record = gwn.user_db[IDi]
    print(f"IDi       = {record.IDi}")
    print(f"r         = {record.r}")
    print(f"ai        = {record.ai}")
    print(f"HoneyList = {record.honey_list}")
