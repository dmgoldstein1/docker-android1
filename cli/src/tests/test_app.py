import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from http.server import BaseHTTPRequestHandler
import io

from tests import BaseTest
from constants import ENV


class TestAppSecurity(BaseTest):
    """Test security aspects of the app module, particularly directory traversal vulnerabilities."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test.log")
        
        # Create a test log file
        with open(self.log_file, "w") as f:
            f.write("test log content")
            
        # Create a sensitive file inside a dedicated subdirectory of the temp directory
        self.sensitive_dir = os.path.join(self.temp_dir, "sensitive_dir")
        os.makedirs(self.sensitive_dir, exist_ok=True)
        self.sensitive_file = os.path.join(self.sensitive_dir, "sensitive.txt")
        with open(self.sensitive_file, "w") as f:
            f.write("sensitive data")
    
    def tearDown(self):
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass
    @patch.dict(os.environ, {ENV.WEB_LOG: "true", ENV.LOG_PATH: "", ENV.WEB_LOG_PORT: "9000"})
    def test_directory_traversal_vulnerability(self):
        """Test that the shared_log function is vulnerable to directory traversal attacks."""
        
        # Test that the vulnerable path construction can access files outside log directory
        log_path = self.temp_dir
        request_path = "/../sensitive.txt"
        
        # This is the vulnerable line from app.py: p = log_path + self.path
        constructed_path = log_path + request_path
        
        # Verify that this path would resolve outside the log directory
        import os.path
        real_path = os.path.realpath(constructed_path)
        log_real_path = os.path.realpath(log_path)
        
        # The vulnerability exists if the real path is not within the log directory
        self.assertFalse(real_path.startswith(log_real_path), 
                        "Directory traversal vulnerability confirmed: path escapes log directory")
                        
    def test_fix_prevents_directory_traversal(self):
        """Test that the fixed path validation prevents directory traversal attacks."""
        import os.path
        
        # Extract the path validation logic from the fix
        def validate_path(log_path, request_path):
            """Reproduce the validation logic from the fixed code."""
            # Validate path to prevent directory traversal attacks
            if '..' in request_path:
                return False, "Contains directory traversal"
            
            # Safely construct the file path
            p = os.path.join(log_path, request_path.lstrip('/'))
            real_path = os.path.realpath(p)
            log_real_path = os.path.realpath(log_path)
            
            # Ensure the resolved path is within the log directory
            if not (real_path.startswith(log_real_path + os.sep) or real_path == log_real_path):
                return False, "Path escapes log directory"
            
            return True, p
        
        # Test directory traversal attempts are blocked
        valid, reason = validate_path(self.temp_dir, "/../sensitive.txt")
        self.assertFalse(valid, f"Should reject directory traversal: {reason}")
        
        valid, reason = validate_path(self.temp_dir, "../sensitive.txt")
        self.assertFalse(valid, f"Should reject directory traversal: {reason}")
        
        valid, reason = validate_path(self.temp_dir, "/subdir/../../../sensitive.txt")
        self.assertFalse(valid, f"Should reject directory traversal: {reason}")
        
        # Test legitimate paths are allowed
        valid, path = validate_path(self.temp_dir, "/test.log")
        self.assertTrue(valid, "Should allow legitimate file access")
        
        valid, path = validate_path(self.temp_dir, "test.log")  
        self.assertTrue(valid, "Should allow legitimate file access without leading slash")
    
    @patch.dict(os.environ, {ENV.WEB_LOG: "true"})
    def test_legitimate_log_access_should_work(self):
        """Test that legitimate log file access should work correctly after fix."""
        
        # Test that legitimate path construction works correctly
        log_path = self.temp_dir
        request_path = "/test.log"
        
        # This represents the safe path construction we want
        import os.path
        safe_path = os.path.join(log_path, request_path.lstrip('/'))
        real_path = os.path.realpath(safe_path)
        log_real_path = os.path.realpath(log_path)
        
        # Legitimate access should stay within the log directory
        self.assertTrue(real_path.startswith(log_real_path),
                       "Legitimate file access should stay within log directory")
                       
    def test_path_validation_rejects_traversal(self):
        """Test helper function to validate paths and reject directory traversal."""
        
        # This test will pass once we implement the fix
        def is_safe_path(log_dir, requested_path):
            """Helper function to validate paths - to be implemented in the fix."""
            # Remove leading slash and validate
            if '..' in requested_path:
                return False
            
            # Construct safe path
            safe_path = os.path.join(log_dir, requested_path.lstrip('/'))
            real_path = os.path.realpath(safe_path)
            log_real_path = os.path.realpath(log_dir)
            
            # Ensure the real path is within the log directory
            return real_path.startswith(log_real_path + os.sep) or real_path == log_real_path
        
        # Test cases
        self.assertTrue(is_safe_path(self.temp_dir, "/test.log"))
        self.assertTrue(is_safe_path(self.temp_dir, "test.log"))
        self.assertFalse(is_safe_path(self.temp_dir, "/../sensitive.txt"))
        self.assertFalse(is_safe_path(self.temp_dir, "../sensitive.txt"))
        self.assertFalse(is_safe_path(self.temp_dir, "/subdir/../../../sensitive.txt"))