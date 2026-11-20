import os
import unittest
from pathlib import Path
from uuid import uuid4

os.environ["DATABASE_PATH"] = str(Path(__file__).parent / "safecircle-test.db")
os.environ["SECRET_KEY"] = "test-secret-key-with-more-than-32-characters"

from fastapi.testclient import TestClient
from backend.main import app

class ApiTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def register(self, email="one@example.com"):
        if email == "one@example.com":
            email = f"one-{uuid4().hex}@example.com"
        response = self.client.post("/api/auth/register", json={"name": "Taylor Example", "email": email, "password": "a-very-long-test-password"})
        self.assertEqual(response.status_code, 201, response.text)
        self.client.headers.update({"Authorization": "Bearer " + response.json()["access_token"]})

    def test_auth_contacts_and_private_incidents(self):
        self.register()
        contact = self.client.post("/api/contacts", json={"name": "Alex", "phone": "+1 555 123 4567"})
        self.assertEqual(contact.status_code, 201)
        self.assertEqual(len(self.client.get("/api/contacts").json()), 1)
        incident = self.client.post("/api/incidents", json={"kind": "sos", "message": "Manual SOS", "location": {"latitude": 50, "longitude": 20}})
        self.assertEqual(incident.status_code, 201)
        self.assertNotIn("location", incident.json())
        self.assertEqual(len(self.client.get("/api/incidents").json()), 1)

    def test_user_data_isolation(self):
        self.register(f"one-{uuid4().hex}@example.com")
        self.client.post("/api/contacts", json={"name": "Alex", "email": "alex@example.com"})
        self.client.headers.pop("Authorization")
        second = self.client.post("/api/auth/register", json={"name": "Jordan", "email": f"two-{uuid4().hex}@example.com", "password": "another-very-long-password"})
        self.client.headers.update({"Authorization": "Bearer " + second.json()["access_token"]})
        self.assertEqual(self.client.get("/api/contacts").json(), [])

    def test_validation_and_admin_are_restricted(self):
        self.register()
        self.assertEqual(self.client.post("/api/contacts", json={"name": "No method"}).status_code, 422)
        self.assertEqual(self.client.get("/api/admin/overview").status_code, 403)

    def test_duplicate_account_and_bad_login(self):
        email = f"one-{uuid4().hex}@example.com"
        self.register(email)
        self.assertEqual(self.client.post("/api/auth/register", json={"name": "X", "email": email, "password": "another-password-long"}).status_code, 409)
        self.assertEqual(self.client.post("/api/auth/login", json={"email": email, "password": "incorrect"}).status_code, 401)

if __name__ == "__main__":
    unittest.main()
