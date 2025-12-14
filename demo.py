#!/usr/bin/env python3
"""
WSN Authentication Protocol - TA Demonstration Script

This script demonstrates the full lifecycle of the authentication protocol:
1. System Setup (Gateway Node initialization)
2. User Registration (Alice)
3. Sensor Registration (Sensor1)
4. Login & Authentication (Alice -> Sensor1)
5. Password Change (Alice changes PW)
6. Login with New Password
7. Dynamic Node Addition (Sensor2)

Run this script to verify the protocol works as intended.
"""

import sys
import time
from common.test_utils import setup_test_gwn
from auth_registration.registration import user_registration_phase
from auth_login.login import (
    user_login_request, 
    gateway_login_processing, 
    sensor_login_processing, 
    gateway_response_processing, 
    user_final_verification
)
from auth_password_change.password_change import user_password_change
from auth_node_addition.node_addition import gateway_node_addition

def print_header(msg):
    print("\n" + "="*60)
    print(f" {msg}")
    print("="*60)
    time.sleep(0.5)

def delay_print(msg, delay=0.5):
    print(msg)
    time.sleep(delay)

def main():
    print_header("1. SYSTEM SETUP")
    delay_print("  [.] Initializing Gateway Node keys...")
    
    gwn = setup_test_gwn()
    
    delay_print(f"[+] Gateway Node Initialized.")
    print(f"    Public Key (e, n): ({gwn.e}, {gwn.n})")
    print(f"    Fuzzy Verifier n0: {gwn.n0}")

    # ========================================================
    print_header("2. USER REGISTRATION")
    ID = "Alice"
    PW = "Password123"
    delay_print(f"  [*] Registering User: {ID}")
    delay_print("  [.] Generating Smart Card parameters...")
    time.sleep(1)
    
    card = user_registration_phase(gwn, ID, PW)
    print(f"[+] Registration Successful.")
    print(f"    Smart Card issued with ID: {card.ID}")
    print(f"    Ai: {card.Ai}")
    print(f"    Bi: {card.Bi}")
    
    # ========================================================
    print_header("3. SENSOR REGISTRATION")
    SID = "Sensor1"
    delay_print(f"  [*] Registering Sensor: {SID}")
    delay_print("  [.] Computing shared secret Pj...")
    time.sleep(1)
    
    sensor_rec = gateway_node_addition(gwn, SID)
    print(f"[+] Sensor Registered.")
    print(f"    SID: {sensor_rec.SID}")
    print(f"    Shared Secret Pj: {sensor_rec.Pj.hex()[:16]}...")

    # ========================================================
    print_header("4. LOGIN & AUTHENTICATION")
    delay_print(f"  [*] User {ID} initiating login to {SID}...")
    
    # Step 1: User Request
    delay_print("  [Step 1] User -> GWN: Sending Login Request...")
    req = user_login_request(card, ID, PW)
    if not req:
        print("[-] Login Failed at Step 1 (User Side)")
        sys.exit(1)
    time.sleep(0.5)
    
    # Step 2: Gateway Processing (verifies User, selects Sensor)
    delay_print("  [Step 2] GWN -> Sensor: Verifying User and Selecting Sensor...")
    gw_out = gateway_login_processing(gwn, req)
    if not gw_out:
        print("[-] Login Failed at Step 2 (GWN Side)")
        sys.exit(1)
    time.sleep(0.5)
    print(f"    Selected Sensor: {gw_out['target_SID']}")
    
    # Step 3: Sensor Processing (verifies GWN)
    delay_print("  [Step 3] Sensor -> GWN: Verifying Gateway signature...")
    sensor_out = sensor_login_processing(sensor_rec, gw_out)
    if not sensor_out:
        print("[-] Login Failed at Step 3 (Sensor Side)")
        sys.exit(1)
    time.sleep(0.5)
    
    # Step 4: Gateway Response (verifies Sensor)
    delay_print("  [Step 4] GWN -> User: Verifying Sensor verification code...")
    gw_resp = gateway_response_processing(gwn, gw_out['gw_state'], sensor_out)
    if not gw_resp:
        print("[-] Login Failed at Step 4 (GWN -> User)")
        sys.exit(1)
    time.sleep(0.5)
    
    # Step 5: User Verification (verifies GWN/Sensor, derives SK)
    delay_print("  [Step 5] User: Finalizing mutual authentication and key derivation...")
    session_key = user_final_verification(req, card, gw_resp)
    if not session_key:
        print("[-] Login Failed at Step 5 (User Final Check)")
        sys.exit(1)
    
    time.sleep(0.5)
    print(f"[+] LOGIN SUCCESSFUL!")
    print(f"    Session Key established: {session_key.hex()}")
    
    # ========================================================
    print_header("5. PASSWORD CHANGE")
    PW_NEW = "MyNewSecretPassword"
    delay_print(f"  [*] User initiating password change...")
    print(f"      Old PW: '{PW}' -> New PW: '{PW_NEW}'")
    
    time.sleep(1)
    success = user_password_change(card, ID, PW, PW_NEW)
    if success:
        print("[+] Password Change Successful locally on Smart Card.")
    else:
        print("[-] Password Change Failed.")
        sys.exit(1)
    
    delay_print("  [.] Verifying Old Password no longer works...")
    time.sleep(0.5)
    req_fail = user_login_request(card, ID, PW)
    if req_fail is None:
        print("[+] Good: Old password rejected.")
    else:
        print("[-] Bad: Old password still accepted!")
        sys.exit(1)

    # ========================================================
    print_header("6. LOGIN WITH NEW PASSWORD")
    delay_print(f"  [*] Logging in with NEW password...")
    time.sleep(1)
    
    req_new = user_login_request(card, ID, PW_NEW)
    if not req_new:
        print("[-] New Password Login Failed at Step 1")
        sys.exit(1)
        
    delay_print("  [.] Processing re-authentication flow...")
    gw_out_new = gateway_login_processing(gwn, req_new)
    sensor_out_new = sensor_login_processing(sensor_rec, gw_out_new)
    gw_resp_new = gateway_response_processing(gwn, gw_out_new['gw_state'], sensor_out_new)
    sk_new = user_final_verification(req_new, card, gw_resp_new)
    
    time.sleep(0.5)
    if sk_new:
        print(f"[+] LOGIN SUCCESSFUL with new password!")
        print(f"    Session Key: {sk_new.hex()}")
    else:
        print("[-] Failed to login with new password.")
        sys.exit(1)

    # ========================================================
    print_header("7. DYNAMIC NODE ADDITION")
    SID_2 = "Sensor2"
    delay_print(f"  [*] Dynamically adding new node: {SID_2}")
    time.sleep(1)
    
    rec_2 = gateway_node_addition(gwn, SID_2)
    print(f"[+] Node {SID_2} Added to GWN Database.")
    print(f"    Stored Pj: {rec_2.Pj.hex()[:16]}...")
    
    print("\n" + "="*60)
    print(" ALL TESTS PASSED. COMPLETE PROTOCOL DEMONSTRATION SUCCESSFUL.")
    print("="*60)

if __name__ == "__main__":
    main()
