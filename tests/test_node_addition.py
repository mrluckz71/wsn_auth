import unittest
from common.models import GatewayNode, SensorRecord
from common.crypto_utils import H
from auth_node_addition.node_addition import gateway_node_addition

class TestNodeAddition(unittest.TestCase):
    def setUp(self):
        self.gwn = GatewayNode(e=65537, n=12345, dx=67890, n0=256)
    
    def test_node_addition(self):
        SID = "SensorNEW"
        
        # 1. Add Node
        rec = gateway_node_addition(self.gwn, SID)
        
        # 2. Verify Record
        self.assertIsInstance(rec, SensorRecord)
        self.assertEqual(rec.SID, SID)
        
        # 3. Verify Stored in DB
        self.assertIn(SID, self.gwn.sensor_db)
        self.assertEqual(self.gwn.sensor_db[SID], rec)
        
        # 4. Verify Pj correctness
        expected_Pj = H(SID, self.gwn.dx)
        self.assertEqual(rec.Pj, expected_Pj)

if __name__ == '__main__':
    unittest.main()
