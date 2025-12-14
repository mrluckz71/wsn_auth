from common.models import GatewayNode

def setup_test_gwn() -> GatewayNode:
    """
    Creates and returns a GatewayNode with standard dummy RSA keys and parameters
    for testing and demonstration purposes.
    
    In a real system, these keys would be generated securely and loaded from authentic sources.
    Here we use small fixed or calculated values to ensure deterministic and fast execution.
    """
    # Standard RSA public exponent
    e = 65537
    
    # Use larger primes for n to ensure n > 2^128
    # P = 2^127 - 1 (Mersenne prime M127)
    # Q = 2^61 - 1 (Mersenne prime M61)
    p = (1 << 127) - 1
    q = (1 << 61) - 1
    n = p * q
    
    # Calculate private exponent d
    # phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    dx = pow(e, -1, phi)
    
    # Fuzzy verifier parameter
    n0 = 256
    
    return GatewayNode(e=e, n=n, dx=dx, n0=n0)
