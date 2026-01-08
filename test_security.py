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
        address = "0x123"
        payload = {
            "sub": address,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": "unique-id-1"
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        headers = {"Authorization": f"Bearer {token}"}

        res = self.app.get('/protected', headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.app.post('/logout', headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.app.get('/protected', headers=headers)
        self.assertEqual(res.status_code, 401)
        self.assertIn(b"revoked", res.data)

    def test_login_history(self):
        address = "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE" 
        
        with patch('app.contract') as mock_contract:
            with patch('app.w3.eth.account.recover_message') as mock_recover:
                mock_contract.functions.isUserActive.return_value.call.return_value = True
                mock_recover.return_value = address 
                
                with patch('app.nonce_cache') as mock_cache:
                    mock_cache.get.return_value = "some-nonce"
                    
                    res = self.app.post('/verify', 
                                      json={"address": address, "signature": "sig"},
                                      environ_base={'REMOTE_ADDR': '1.1.1.1'})
                    
                    data = json.loads(res.data)
                    self.assertEqual(res.status_code, 200)
                    self.assertIn('history', data)
                    self.assertEqual(len(data['history']), 1)
                    self.assertEqual(data['history'][0]['ip'], '1.1.1.1')
                    
                    res = self.app.post('/verify', 
                                      json={"address": address, "signature": "sig"},
                                      environ_base={'REMOTE_ADDR': '2.2.2.2'})
                    
                    data = json.loads(res.data)
                    self.assertEqual(len(data['history']), 2)
                    self.assertEqual(data['history'][0]['ip'], '2.2.2.2')
                    self.assertEqual(data['history'][1]['ip'], '1.1.1.1')

if __name__ == '__main__':
    unittest.main()
