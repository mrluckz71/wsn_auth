"""
Simple tests for the WSN auth protocol.

You can run with:
    pytest
or:
    python -m tests.test_protocol
"""

import unittest

from wsn_auth import (
    setup_system,
    register_sensor,
    register_user,
    login_and_authenticate,
)


class TestWSNProtocol(unittest.TestCase):
    def setUp(self):
        self.sys_state = setup_system()
        self.sensor_id = "S1"
        register_sensor(self.sys_state, self.sensor_id)

        self.user_id = "alice"
        self.password = "password123"
        self.card = register_user(self.sys_state, self.user_id, self.password)

    def test_successful_authentication(self):
        ok, sk = login_and_authenticate(
            self.sys_state,
            self.card,
            self.password,
            self.sensor_id,
        )
        self.assertTrue(ok, "Authentication should succeed")
        self.assertIsInstance(sk, bytes)
        self.assertGreater(len(sk), 0, "Session key should not be empty")

    def test_wrong_password(self):
        ok, sk = login_and_authenticate(
            self.sys_state,
            self.card,
            "wrong-password",
            self.sensor_id,
        )
        self.assertFalse(ok, "Authentication should fail with wrong password")
        self.assertEqual(sk, b"")


if __name__ == "__main__":
    unittest.main()
