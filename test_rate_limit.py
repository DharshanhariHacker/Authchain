import time
import unittest
from unittest.mock import MagicMock, patch
from app import app, rate_limit, request_history, RATE_LIMIT_WINDOW, CLEANUP_INTERVAL, MAX_REQUESTS

class TestRateLimit(unittest.TestCase):
    def setUp(self):
        request_history.clear()
        pass

    def test_rate_limit_enforcement(self):
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '1.2.3.4'}):
            @rate_limit
            def dummy():
                return "ok"

            for _ in range(MAX_REQUESTS):
                dummy()
            
            response = dummy()
            if isinstance(response, tuple):
                self.assertEqual(response[1], 429)
            else:
                self.fail("Should have returned 429")

    def test_cleanup_logic(self):
        import app as app_module
        
        request_history['1.2.3.4'] = [time.time() - RATE_LIMIT_WINDOW - 10]
        request_history['5.6.7.8'] = [time.time()]
        
        app_module.LAST_CLEANUP = time.time() - CLEANUP_INTERVAL - 1
        
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '9.9.9.9'}):
            @rate_limit
            def dummy():
                return "ok"
            
            dummy()
            
            self.assertNotIn('1.2.3.4', request_history)
            self.assertIn('5.6.7.8', request_history)
            self.assertIn('9.9.9.9', request_history)

if __name__ == '__main__':
    unittest.main()
