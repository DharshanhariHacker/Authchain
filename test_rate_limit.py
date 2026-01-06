import time
import unittest
from unittest.mock import MagicMock, patch
from app import app, rate_limit, request_history, RATE_LIMIT_WINDOW, CLEANUP_INTERVAL, MAX_REQUESTS

class TestRateLimit(unittest.TestCase):
    def setUp(self):
        # Reset history before each test
        request_history.clear()
        # Reset LAST_CLEANUP in app (we need to access the global variable in app)
        # Since we imported it, we might need to patch it or just rely on the Logic.
        # Ideally we should modify app.py to make it testable or just test the side effects.
        pass

    def test_rate_limit_enforcement(self):
        """Test that rate limit blocks requests after MAX_REQUESTS"""
        # Set IP via environ_base
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '1.2.3.4'}):
            # decorated function
            @rate_limit
            def dummy():
                return "ok"

            # Hit 10 times
            for _ in range(MAX_REQUESTS):
                dummy()
            
            # 11th time should fail
            response = dummy()
            # response is (json, 429) tuple or just "ok"
            if isinstance(response, tuple):
                self.assertEqual(response[1], 429)
            else:
                self.fail("Should have returned 429")

    def test_cleanup_logic(self):
        """Test that stale entries are cleaned up"""
        # We need to simulate time passing and multiple IPs
        import app as app_module
        
        # Inject some stale data
        request_history['1.2.3.4'] = [time.time() - RATE_LIMIT_WINDOW - 10]
        request_history['5.6.7.8'] = [time.time()] # Fresh
        
        # Force cleanup interval to be passed
        app_module.LAST_CLEANUP = time.time() - CLEANUP_INTERVAL - 1
        
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '9.9.9.9'}):
            @rate_limit
            def dummy():
                return "ok"
            
            dummy() # This triggers cleanup
            
            # '1.2.3.4' should be gone
            self.assertNotIn('1.2.3.4', request_history)
            # '5.6.7.8' should remain
            self.assertIn('5.6.7.8', request_history)
            # '9.9.9.9' should be added
            self.assertIn('9.9.9.9', request_history)

if __name__ == '__main__':
    unittest.main()
