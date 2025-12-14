import unittest
from common.models import GatewayNode, SensorRecord
from common.crypto_utils import H
from auth_registration.registration import user_registration_phase
from auth_login.login import (
    user_login_request, 
    gateway_login_processing, 
    sensor_login_processing, 
    gateway_response_processing, 
    user_final_verification
)

class TestLoginPhaseExtended(unittest.TestCase):
    def setUp(self):
        # 1. Setup System
        self.e = 65537
        # n > 2^128
        p = (1 << 127) - 1
        q = (1 << 61) - 1
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.dx = pow(self.e, -1, phi)
        
        self.n0 = 256
        self.gwn = GatewayNode(e=self.e, n=self.n, dx=self.dx, n0=self.n0)
        
        # 2. Register User
        self.ID = "Alice"
        self.PW = "Password123"
        self.card = user_registration_phase(self.gwn, self.ID, self.PW)
        
        # 3. Register Sensor
        self.SID = "Sensor1"
        self.Pj_key = H(self.SID, self.gwn.dx)
        self.sensor_rec = SensorRecord(SID=self.SID, Pj=self.Pj_key)
        self.gwn.sensor_db[self.SID] = self.sensor_rec

    def test_gateway_processing_tampered_M1(self):
        req = user_login_request(self.card, self.ID, self.PW)
        
        # Tamper M1 (bytes)
        # Flip the first byte
        original_m1 = req["M1"]
        tampered_byte = (original_m1[0] + 1) % 256
        req["M1"] = bytes([tampered_byte]) + original_m1[1:]
        
        gw_out = gateway_login_processing(self.gwn, req)
        self.assertIsNone(gw_out, "GWN should reject tampered M1")

    def test_gateway_processing_unknown_user(self):
        req = user_login_request(self.card, self.ID, self.PW)
        
        # Tamper D0 to decrypt to unknown ID? 
        # Hard to tamper encrypted D0 to valid unknown ID without key.
        # But we can verify that if we *could* produce such a request it fails.
        # Alternatively, assume someone sends random D0.
        
        req["D0"] = b'\x00' * len(req["D0"]) # garbage
        
        gw_out = gateway_login_processing(self.gwn, req)
        self.assertIsNone(gw_out, "GWN should reject garbage D0")

    def test_sensor_processing_tampered_D3(self):
        req = user_login_request(self.card, self.ID, self.PW)
        gw_out = gateway_login_processing(self.gwn, req)
        
        # Tamper D3
        gw_out["D3"] = b'\x00' * len(gw_out["D3"])
        
        sensor_out = sensor_login_processing(self.sensor_rec, gw_out)
        self.assertIsNone(sensor_out, "Sensor should reject tampered D3")
    
    def test_sensor_processing_mismatched_M2(self):
        req = user_login_request(self.card, self.ID, self.PW)
        gw_out = gateway_login_processing(self.gwn, req)
        
        # Tamper M2 (bytes)
        original_m2 = gw_out["M2"]
        tampered_byte = (original_m2[0] + 1) % 256
        gw_out["M2"] = bytes([tampered_byte]) + original_m2[1:]
        
        sensor_out = sensor_login_processing(self.sensor_rec, gw_out)
        self.assertIsNone(sensor_out, "Sensor should reject mismatched M2")

    def test_user_verification_mismatched_M4(self):
        req = user_login_request(self.card, self.ID, self.PW)
        gw_out = gateway_login_processing(self.gwn, req)
        sensor_out = sensor_login_processing(self.sensor_rec, gw_out)
        gw_resp = gateway_response_processing(self.gwn, gw_out["gw_state"], sensor_out)
        
        # Tamper M4 (bytes)
        original_m4 = gw_resp["M4"]
        tampered_byte = (original_m4[0] + 1) % 256
        gw_resp["M4"] = bytes([tampered_byte]) + original_m4[1:]
        
        sk = user_final_verification(req, self.card, gw_resp)
        self.assertIsNone(sk, "User should reject mismatched M4")

if __name__ == '__main__':
    unittest.main()
