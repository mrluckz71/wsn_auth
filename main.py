"""
Entry point for the WSN auth demo.

Run:
    python main.py
"""

from wsn_auth import (
    setup_system,
    register_sensor,
    register_user,
    login_and_authenticate,
)


def run_demo():
    print("=== WSN Auth Demo ===")

    # 1) Setup system
    sys_state = setup_system()
    print("[*] System initialized (GWN RSA keys, n0).")

    # 2) Register a sensor
    sensor_id = "S1"
    register_sensor(sys_state, sensor_id)
    print(f"[*] Sensor registered with SID = {sensor_id}")

    # 3) Register a user
    user_id = "alice"
    password = "password123"
    card = register_user(sys_state, user_id, password)
    print(f"[*] User registered with ID = {user_id}")

    # 4) Run login & authentication
    print("[*] Running login & authentication...")
    ok, sk = login_and_authenticate(sys_state, card, password, sensor_id)

    if ok:
        print("[+] Authentication succeeded.")
        print("    Session key (hex):", sk.hex())
    else:
        print("[-] Authentication failed.")


if __name__ == "__main__":
    run_demo()
