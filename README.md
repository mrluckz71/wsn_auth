# WSN User Authentication Protocol Project

This project implements an efficient user authentication protocol for Wireless Sensor Networks (WSNs) using public key cryptography (RSA).

## Quick Start

After downloading the project, navigate to the `wsn_auth_project` directory and run:

```bash
# Run the complete demo
python demo.py

# Or try individual phases
python -m auth_registration.main
python -m auth_login.main
python -m auth_password_change.main
python -m auth_node_addition.main

# Verify correctness with tests
python -m unittest discover tests
```

No installation needed; just Python 3.6+!

## Project Structure

- **`common/`**: Shared utilities and data models.
    - `crypto_utils.py`: Hashing, XOR, and symmetric encryption functions.
    - `models.py`: Data classes for `SmartCard`, `GatewayNode`, `UserRecord`, `SensorRecord`.
- **`auth_registration/`**: User Registration Phase implementation.
- **`auth_login/`**: Login and Authentication Phase (Steps 1-5).
- **`auth_password_change/`**: Password Change Phase.
- **`auth_node_addition/`**: Dynamic Node Addition Phase.
- **`tests/`**: Unit tests for all modules.
- **`demo.py`**: End-to-end demonstration script.

## Functionality

The protocol covers four main phases:

1. **Registration** - User creates a password and receives a smart card with encrypted authentication values. The Gateway Node stores the user's secrets securely.

2. **Login & Authentication** - A 5-step mutual authentication protocol where the user, Gateway Node, and Sensor establish a shared session key. All three parties verify each other's authenticity.

3. **Password Change** - Users can change passwords locally on their smart card without contacting the Gateway Node. Works entirely offline.

4. **Node Addition** - New sensor nodes register with the Gateway Node and receive cryptographic keys, enabling them to immediately participate in authentication.

## Basic Usage Example

```python
from common.test_utils import setup_test_gwn
from auth_registration.registration import user_registration_phase
from auth_login.login import user_login_request
from auth_node_addition.node_addition import gateway_node_addition

# Initialize Gateway Node
gwn = setup_test_gwn()

# Register a user
card = user_registration_phase(gwn, "alice", "mypassword")
print(f"User registered! Smart card ID: {card.ID}")

# Add a sensor
sensor = gateway_node_addition(gwn, "Sensor1")
print(f"Sensor registered: {sensor.SID}")

# User initiates login
request = user_login_request(card, "alice", "mypassword")
if request:
    print("Login request created successfully")
else:
    print("Wrong password!")
```

## Prerequisites

- Python 3.6+
- No external dependencies (uses standard library `hashlib`, `os`, `secrets`).

## How to Run the Demos

You can run a specific demo for each phase of the protocol:

### 1. Registration Phase
```bash
python -m auth_registration.main
```

### 2. Login & Authentication Phase
```bash
python -m auth_login.main
```

### 3. Password Change Phase
```bash
python -m auth_password_change.main
```

### 4. Node Addition Phase
```bash
python -m auth_node_addition.main
```

### Full System Demo
To see the full end-to-end lifecycle in one script:
```bash
python demo.py
```

## How to Run Tests

To verify the correctness of the implementation:

```bash
python -m unittest discover tests
```

Expected Output:
```
.................
----------------------------------------------------------------------
Ran 17 tests in 0.006s

OK
```
