import unittest
import json
import time
from app import app, asset_store, JWT_SECRET
import jwt
import os

class TestAssetValidator(unittest.TestCase):
    def setUp(self):
        asset_store.clear()
        self.app = app.test_client()
        
        self.address = "0xOwner"
        payload = {
            "sub": self.address,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": "test-jti-" + os.urandom(4).hex()
        }
        self.token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_register_and_verify(self):
        """Test asset registration and public verification"""
        res = self.app.post('/api/assets/register', 
                           headers=self.headers,
                           json={"type": "Laptop", "description": "MacBook Pro"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        asset_id = data["asset_id"]
        
        res = self.app.get(f'/api/verify-asset/{asset_id}')
        self.assertEqual(res.status_code, 200)
        v_data = json.loads(res.data)
        
        self.assertEqual(v_data["status"], "CLEAN")
        self.assertEqual(v_data["type"], "Laptop")
        self.assertFalse(v_data["is_stolen"])
        self.assertNotIn("owner", v_data)

    def test_report_stolen(self):
        """Test reporting an asset as stolen"""
        res = self.app.post('/api/assets/register', 
                           headers=self.headers,
                           json={"type": "Bike", "description": "Red Trek"})
        asset_id = json.loads(res.data)["asset_id"]
        
        res = self.app.post('/api/assets/report',
                           headers=self.headers,
                           json={"asset_id": asset_id, "status": "STOLEN"})
        self.assertEqual(res.status_code, 200)
        
        res = self.app.get(f'/api/verify-asset/{asset_id}')
        v_data = json.loads(res.data)
        self.assertEqual(v_data["status"], "STOLEN")
        self.assertTrue(v_data["is_stolen"])

if __name__ == '__main__':
    unittest.main()
