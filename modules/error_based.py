#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
import logging

class ErrorBasedInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        """
        Initialize the ErrorBasedInjector.
        
        Args:
            request_engine: RequestEngine instance for making HTTP requests
            payload_manager: PayloadManager instance for managing SQL payloads
        """
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        
        # Common SQL error messages to look for
        self.error_indicators = [
            "SQL syntax",
            "mysql_fetch_array",
            "ORA-",
            "PostgreSQL",
            "SQLite3::",
            "Warning: mysql_",
            "Microsoft SQL Server",
            "ODBC SQL Server Driver",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "Warning: pg_",
            "PostgreSQL.*ERROR",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: column",
            "ERROR: relation",
            "ERROR: duplicate key value violates unique constraint",
            "ERROR: null value in column",
            "ERROR: current transaction is aborted",
            "ERROR: permission denied for",
            "ERROR: role",
            "ERROR: function",
            "ERROR: schema",
            "ERROR: database",
            "ERROR: relation",
            "ERROR: syntax error at end of input",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: unterminated quoted identifier at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: unterminated quoted identifier at or near",
            "ERROR: unterminated /* comment at or near",
            "ERROR: unterminated -- comment at or near",
        ]
    
    def test_parameter(self, param_name: str, param_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Test a parameter for error-based SQL injection vulnerabilities.
        
        Args:
            param_name: Name of the parameter to test
            param_value: Original value of the parameter
            
        Returns:
            Tuple containing (is_vulnerable, payload, error_message)
        """
        logging.info(f"Testing parameter '{param_name}' for error-based SQL injection")
        
        for payload in self.payload_manager.get_payloads("error_based"):
            test_value = param_value + payload
            try:
                if self.request_engine.method == "GET":
                    params = {param_name: test_value}
                    response, _ = self.request_engine.send_request(params=params)
                else:
                    data = {param_name: test_value}
                    response, _ = self.request_engine.send_request(data=data)
                
                # Check for error messages in the response
                for indicator in self.error_indicators:
                    if indicator.lower() in response.text.lower():
                        logging.info(f"Found potential SQL injection with payload: {payload}")
                        return True, payload, indicator
                
            except Exception as e:
                logging.error(f"Error testing payload '{payload}': {str(e)}")
                continue
        
        return False, None, None
    
    def test_all_parameters(self) -> Dict[str, Tuple[bool, Optional[str], Optional[str]]]:
        """
        Test all parameters in the request for error-based SQL injection vulnerabilities.
        
        Returns:
            Dictionary mapping parameter names to (is_vulnerable, payload, error_message)
        """
        results = {}
        
        # Test URL parameters for GET requests
        if self.request_engine.method == "GET":
            params = self.request_engine.get_url_parameters()
            for param_name, param_value in params.items():
                results[param_name] = self.test_parameter(param_name, param_value)
        
        # Test POST data for POST requests
        elif self.request_engine.method == "POST":
            for param_name, param_value in self.request_engine.data.items():
                results[param_name] = self.test_parameter(param_name, str(param_value))
        
        return results 
