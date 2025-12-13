from typing import Tuple
from common.crypto_utils import h_int, H
from common.models import GatewayNode, SensorRecord

# -----------------------------
# Dynamic Node Addition Phase
# -----------------------------

def gateway_node_addition(gwn: GatewayNode, SIDj: str) -> SensorRecord:
    """
    Implements Section 6.5 Dynamic Node Addition Phase.
    
    Step 1. Sj sends node addition request (abstracted here as function call).
    Step 2. GWN selects unique identity (SIDj provided), computes Pj.
    Step 3. Returns SensorRecord to simulated sensor (keeping Pj).
    """
    
    # Check if SIDj exists?
    if SIDj in gwn.sensor_db:
        # In a real system, might reject or rotate key. 
        # Here we just overwrite/update mechanism implies logic.
        pass

    # Compute Pj = h(SIDj || dx)
    # Pj should be bytes for encryption/decryption use later.
    # Our models usually treat keys as bytes in crypto_utils.
    # But SensorRecord.Pj is typed as bytes in common/models.py?
    # Let's check common/models.py
    # Yes: Pj: bytes
    
    Pj = H(SIDj, gwn.dx)
    
    # Create record
    rec = SensorRecord(SID=SIDj, Pj=Pj)
    
    # Store in GWN DB
    gwn.sensor_db[SIDj] = rec
    
    # Return to sensor
    return rec
