from common.test_utils import setup_test_gwn
from common.crypto_utils import H
from auth_registration.registration import user_registration_phase
from auth_login.login import (
    user_login_request,
    gateway_login_processing,
    sensor_login_processing,
    gateway_response_processing,
    user_final_verification
)
from common.models import SensorRecord

if __name__ == "__main__":
    print("=== Login Phase Demo ===")
    
    # ---------------------------------------------------
    # 1. System Setup (Simulated)
    # ---------------------------------------------------
    print("\n[1] Setting up System (GWN, User, Sensor)...")
    
    # 1a. Gateway Node
    gwn = setup_test_gwn()
    print("    GWN initialized.")

    # 1b. User Registration
    ID = "Alice"
    PW = "Password123"
    card = user_registration_phase(gwn, ID, PW)
    print(f"    User '{ID}' registered.")

    # 1c. Sensor Setup
    SID = "Sensor1"
    # GWN computes Pj = H(SID || dx)
    Pj_key = H(SID, gwn.dx)
    sensor_rec = SensorRecord(SID=SID, Pj=Pj_key)
    gwn.sensor_db[SID] = sensor_rec
    print(f"    Sensor '{SID}' registered.")

    # ---------------------------------------------------
    # 2. Execution of Protocol
    # ---------------------------------------------------
    print("\n[2] Executing Login Protocol...")

    # Step 1: User -> GWN
    print("\n--- Step 1: User Login Request ---")
    req = user_login_request(card, ID, PW)
    if req:
        print("    User generated login request:")
        print(f"    Xi (encrypted rnd): {req['Xi']}")
        print(f"    D0, D1 (auth tokens generated)")
    else:
        print("    Login failed at User step (wrong password?).")
        exit(1)

    # Step 2: GWN -> Sensor
    print("\n--- Step 2: Gateway Processing ---")
    gw_out = gateway_login_processing(gwn, req)
    if gw_out:
        print("    GWN authenticated User.")
        print(f"    Target Sensor: {gw_out['target_SID']}")
    else:
        print("    GWN rejected request.")
        exit(1)

    # Step 3: Sensor -> GWN
    print("\n--- Step 3: Sensor Processing ---")
    # In a real network, 'gw_out' is sent to the sensor.
    # Here we simulate the sensor process.
    sensor_out = sensor_login_processing(sensor_rec, gw_out)
    if sensor_out:
         print("    Sensor validated parameters.")
         print("    Generated session key contribution (SKj).")
    else:
         print("    Sensor rejected request.")
         exit(1)

    # Step 4: GWN -> User
    print("\n--- Step 4: Gateway Response ---")
    gw_resp = gateway_response_processing(gwn, gw_out["gw_state"], sensor_out)
    if gw_resp:
        print("    GWN validated Sensor response.")
        print("    Forwarding tokens to User.")
    else:
        print("    GWN rejected Sensor response.")
        exit(1)

    # Step 5: User Verification
    print("\n--- Step 5: User Final Verification ---")
    sk_user = user_final_verification(req, card, gw_resp)
    
    if sk_user:
        print("SUCCESS! Mutual Authentication Complete.")
        print(f"Session Key (SK) established: {sk_user.hex().upper()}")
    else:
        print("FAILURE! User failed to verify Gateway/Sensor.")
