from common.test_utils import setup_test_gwn
from auth_registration.registration import user_registration_phase
from auth_password_change.password_change import user_password_change
from auth_login.login import user_login_request

if __name__ == "__main__":
    print("=== Password Change Demo ===")
    
    # ---------------------------------------------------
    # 1. Setup
    # ---------------------------------------------------
    # We need a GWN and a Registered User
    gwn = setup_test_gwn()
    
    ID = "Bob"
    OldPW = "MySecret123"
    card = user_registration_phase(gwn, ID, OldPW)
    print(f"User '{ID}' registered with password '{OldPW}'.")
    
    # ---------------------------------------------------
    # 2. Change Password
    # ---------------------------------------------------
    NewPW = "ChangedToThis456!"
    print(f"\nAttempting to change password to '{NewPW}'...")
    
    success = user_password_change(card, ID, OldPW, NewPW)
    
    if success:
        print("Password change reported SUCCESS by SmartCard.")
    else:
        print("Password change FAILED.")
        exit(1)

    # ---------------------------------------------------
    # 3. Verify
    # ---------------------------------------------------
    print("\nVerifying by attempting Login with NEW password...")
    req_new = user_login_request(card, ID, NewPW)
    if req_new:
        print("Login Request generated successfully with NEW password.")
    else:
        print("Failed to generate Login Request with NEW password.")
        
    print("\nVerifying by attempting Login with OLD password...")
    req_old = user_login_request(card, ID, OldPW)
    if req_old:
        print("WARNING: Login Request generated with OLD password (should have failed).")
    else:
        print("Correctly rejected Login Request with OLD password.")
