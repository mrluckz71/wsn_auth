import unittest
from common.models import GatewayNode, SensorRecord
from common.crypto_utils import h_int, H
from auth_registration.registration import user_registration_phase, gateway_register_user
from auth_login.login import (
    user_login_request, 
    gateway_login_processing, 
    sensor_login_processing, 
    gateway_response_processing, 
    user_final_verification
)

from common.test_utils import setup_test_gwn
from auth_registration.registration import user_registration_phase, gateway_register_user
from auth_login.login import (
    user_login_request, 
    gateway_login_processing, 
    sensor_login_processing, 
    gateway_response_processing, 
    user_final_verification
)

class TestLoginPhase(unittest.TestCase):
    def setUp(self):
        # 1. Setup System
        self.gwn = setup_test_gwn()
        
        # Access parameters for tests if needed
        self.e = self.gwn.e
        self.n = self.gwn.n
        self.dx = self.gwn.dx
        self.n0 = self.gwn.n0
        
        # 2. Register User
        self.ID = "Alice"
        self.PW = "Password123"
        self.card = user_registration_phase(self.gwn, self.ID, self.PW)
        
        # 3. Register Sensor
        self.SID = "Sensor1"
        self.Pj_key = H(self.SID, self.gwn.dx)
        self.sensor_rec = SensorRecord(SID=self.SID, Pj=self.Pj_key)
        self.gwn.sensor_db[self.SID] = self.sensor_rec

    def test_successful_login(self):
        # Step 1: User Request
        req = user_login_request(self.card, self.ID, self.PW)
        self.assertIsNotNone(req)
        
        # Step 2: Gateway Processing
        gw_out = gateway_login_processing(self.gwn, req)
        self.assertIsNotNone(gw_out)
        self.assertEqual(gw_out["target_SID"], self.SID)
        
        # Step 3: Sensor Processing
        sensor_out = sensor_login_processing(self.sensor_rec, gw_out)
        self.assertIsNotNone(sensor_out)
        
        # Step 4: Gateway Response Processing
        gw_resp = gateway_response_processing(self.gwn, gw_out["gw_state"], sensor_out)
        self.assertIsNotNone(gw_resp)
        
        # Step 5: User Final Verification
        sk_user = user_final_verification(req, self.card, gw_resp)
        self.assertIsNotNone(sk_user)
        
        # Verify Session Keys Match
        sk_sensor = sensor_out["SKj"]
        self.assertEqual(sk_user, sk_sensor)
        print(f"Session Key Established: {sk_user.hex()}")

    def test_wrong_password(self):
        req = user_login_request(self.card, self.ID, "WrongPW")
        self.assertIsNone(req)

if __name__ == '__main__':
    unittest.main()
