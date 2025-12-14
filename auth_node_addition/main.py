from common.crypto_utils import H
from common.test_utils import setup_test_gwn
from auth_node_addition.node_addition import gateway_node_addition

if __name__ == "__main__":
    print("=== Node Addition Demo ===")
    
    # ---------------------------------------------------
    # 1. Setup GWN
    # ---------------------------------------------------
    gwn = setup_test_gwn()
    print("GWN initialized.")
    print(f"Current Sensors: {list(gwn.sensor_db.keys())}")
    
    # ---------------------------------------------------
    # 2. Add Node
    # ---------------------------------------------------
    NewSID = "Sensor_X"
    print(f"\nAdding new sensor '{NewSID}'...")
    
    rec = gateway_node_addition(gwn, NewSID)
    
    print("Node added successfully.")
    print(f"Returned Record: {rec}")
    
    print(f"\nGWN Sensor Database: {list(gwn.sensor_db.keys())}")
    
    # Verify Pj check
    expected_Pj = H(NewSID, gwn.dx)
    if rec.Pj == expected_Pj:
        print("Shared secret Pj verified correctly.")
    else:
        print("Shared secret Pj MISMATCH.")
