import unittest
import json
import time
from app import app, token_blocklist, login_history_store, JWT_SECRET
import jwt
from unittest.mock import patch, MagicMock

class TestSecurityFeatures(unittest.TestCase):
    def setUp(self):
        token_blocklist.clear()
        login_history_store.clear()
        self.app = app.test_client()

    def test_logout_revocation(self):
        """Test that logout invalidates the token"""
        # 1. Create a valid token manually (simulating login)
        address = "0x123"
        payload = {
            "sub": address,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": "unique-id-1"
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Access protected route (should succeed)
        res = self.app.get('/protected', headers=headers)
        self.assertEqual(res.status_code, 200)

        # 3. Logout
        res = self.app.post('/logout', headers=headers)
        self.assertEqual(res.status_code, 200)

        # 4. Access protected route again (should fail)
        res = self.app.get('/protected', headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn(b"revoked", res.data)

    def test_login_history(self):
        """Test that login history is recorded and returned"""
        address = "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE" # Valid address
        
        # We need to mock the full login flow or just inspect the side effects if we mock the verify logic
        # Ideally we test the /verify endpoint but that requires signature. 
        # For simplicity, we can test the side effect on the store if we were calling the function, 
        # OR we can mock the signature verification to pass.
        
        # Let's mock the internal contract call and signature verification to test /verify
        with patch('app.contract') as mock_contract:
            with patch('app.w3.eth.account.recover_message') as mock_recover:
                # Setup
                mock_contract.functions.isUserActive.return_value.call.return_value = True
                mock_recover.return_value = address # Recovered matches address
                
                # Mock nonce cache
                with patch('app.nonce_cache') as mock_cache:
                    mock_cache.get.return_value = "some-nonce"
                    
                    # 1. First Login
                    res = self.app.post('/verify', 
                                      json={"address": address, "signature": "sig"},
                                      environ_base={'REMOTE_ADDR': '1.1.1.1'})
                    
                    data = json.loads(res.data)
                    self.assertEqual(res.status_code, 200)
                    self.assertIn('history', data)
                    self.assertEqual(len(data['history']), 1)
                    self.assertEqual(data['history'][0]['ip'], '1.1.1.1')
                    
                    # 2. Second Login from different IP
                    res = self.app.post('/verify', 
                                      json={"address": address, "signature": "sig"},
                                      environ_base={'REMOTE_ADDR': '2.2.2.2'})
                    
                    data = json.loads(res.data)
                    self.assertEqual(len(data['history']), 2)
                    self.assertEqual(data['history'][0]['ip'], '2.2.2.2')
                    self.assertEqual(data['history'][1]['ip'], '1.1.1.1')

if __name__ == '__main__':
    unittest.main()
