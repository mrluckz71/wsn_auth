import unittest
from common.models import GatewayNode, SmartCard
from auth_registration.registration import user_registration_phase, gateway_register_user, is_id_available

class TestRegistration(unittest.TestCase):
    def setUp(self):
        self.gwn = GatewayNode(e=65537, n=12345, dx=67890, n0=256)
        
    def test_user_registration(self):
        ID = "Alice"
        PW = "Password123"
        
        # 1. Register
        card = user_registration_phase(self.gwn, ID, PW)
        
        # 2. Verify Card
        self.assertIsInstance(card, SmartCard)
        self.assertEqual(card.ID, ID)
        self.assertEqual(card.n0, 256)
        self.assertIsNotNone(card.b)
        
        # 3. Verify GWN Storage
        self.assertIn(ID, self.gwn.user_db)
        rec = self.gwn.user_db[ID]
        self.assertEqual(rec.IDi, ID)
        
    def test_duplicate_registration(self):
        ID = "Bob"
        PW = "Pass"
        user_registration_phase(self.gwn, ID, PW)
        
        # Try registering again
        with self.assertRaises(ValueError):
            user_registration_phase(self.gwn, ID, "NewPass")

if __name__ == '__main__':
    unittest.main()
