import unittest
from common.models import GatewayNode
from auth_registration.registration import user_registration_phase
from auth_password_change.password_change import user_password_change
from auth_login.login import user_login_request

class TestPasswordChange(unittest.TestCase):
    def setUp(self):
        self.gwn = GatewayNode(e=65537, n=12345, dx=67890, n0=256) # Dummy keys
        self.ID = "Bob"
        self.PW = "Secret1"
        self.card = user_registration_phase(self.gwn, self.ID, self.PW)
    
    def test_successful_password_change(self):
        PW_new = "Secret2"
        # 1. Change Password
        success = user_password_change(self.card, self.ID, self.PW, PW_new)
        self.assertTrue(success, "Password change should succeed")
        
        # 2. Verify Old Password Fails Login (Local Authenticator)
        # Note: In reality, smart card values changed. We check if new values work for new PW.
        
        # Check if Login with NEW password works (Step 1 of Login)
        req_new = user_login_request(self.card, self.ID, PW_new)
        self.assertIsNotNone(req_new, "Login with NEW password should succeed locally")
        
        # Check if Login with OLD password fails
        req_old = user_login_request(self.card, self.ID, self.PW)
        self.assertIsNone(req_old, "Login with OLD password should fail locally")

    def test_wrong_old_password(self):
        PW_new = "Secret2"
        success = user_password_change(self.card, self.ID, "WrongPW", PW_new)
        self.assertFalse(success, "Password change should fail with wrong old password")
        
        # Ensure card not changed
        req_old = user_login_request(self.card, self.ID, self.PW)
        self.assertIsNotNone(req_old, "Original password should still work")

if __name__ == '__main__':
    unittest.main()
