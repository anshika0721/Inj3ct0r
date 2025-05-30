#!/usr/bin/env python3

import logging
import time
from typing import Dict, List, Optional
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class BlindBasedInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        """Initialize the blind-based SQL injector."""
        self.request_engine = request_engine
        self.payload_manager = payload_manager
    
    def test_all_parameters(self) -> List[Dict]:
        """Test all parameters for blind SQL injection vulnerabilities."""
        results = []
        params = self.request_engine.get_parameters()
        
        for param_name in params:
            # Test MySQL blind injection
            mysql_results = self._test_mysql_blind(param_name)
            results.extend(mysql_results)
            
            # Test PostgreSQL blind injection
            postgres_results = self._test_postgres_blind(param_name)
            results.extend(postgres_results)
            
            # Test MSSQL blind injection
            mssql_results = self._test_mssql_blind(param_name)
            results.extend(mssql_results)
        
        return results
    
    def _test_mysql_blind(self, param_name: str) -> List[Dict]:
        """Test for MySQL blind SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("blind", "mysql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, response_time = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for time-based injection
                if response_time > 5:  # If response time is significantly longer
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Time-based blind SQL injection detected in MySQL"
                    })
                    continue
                
                # Check for boolean-based injection
                if "true" in response.text.lower() or "1" in response.text:
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Boolean-based blind SQL injection detected in MySQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MySQL blind injection: {str(e)}")
                continue
        
        return results
    
    def _test_postgres_blind(self, param_name: str) -> List[Dict]:
        """Test for PostgreSQL blind SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("blind", "postgresql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, response_time = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for time-based injection
                if response_time > 5:  # If response time is significantly longer
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Time-based blind SQL injection detected in PostgreSQL"
                    })
                    continue
                
                # Check for boolean-based injection
                if "true" in response.text.lower() or "1" in response.text:
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Boolean-based blind SQL injection detected in PostgreSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing PostgreSQL blind injection: {str(e)}")
                continue
        
        return results
    
    def _test_mssql_blind(self, param_name: str) -> List[Dict]:
        """Test for MSSQL blind SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("blind", "mssql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, response_time = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for time-based injection
                if response_time > 5:  # If response time is significantly longer
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Time-based blind SQL injection detected in MSSQL"
                    })
                    continue
                
                # Check for boolean-based injection
                if "true" in response.text.lower() or "1" in response.text:
                    results.append({
                        "type": "blind",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Boolean-based blind SQL injection detected in MSSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MSSQL blind injection: {str(e)}")
                continue
        
        return results 
