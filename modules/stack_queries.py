#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class StackedQueriesInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        """Initialize the stacked queries injector."""
        self.request_engine = request_engine
        self.payload_manager = payload_manager
    
    def test_all_parameters(self) -> List[Dict]:
        """Test all parameters for stacked queries SQL injection vulnerabilities."""
        results = []
        params = self.request_engine.get_parameters()
        
        for param_name in params:
            # Test MySQL stacked queries
            mysql_results = self._test_mysql_stacked(param_name)
            results.extend(mysql_results)
            
            # Test PostgreSQL stacked queries
            postgres_results = self._test_postgres_stacked(param_name)
            results.extend(postgres_results)
            
            # Test MSSQL stacked queries
            mssql_results = self._test_mssql_stacked(param_name)
            results.extend(mssql_results)
        
        return results
    
    def _test_mysql_stacked(self, param_name: str) -> List[Dict]:
        """Test for MySQL stacked queries SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("stacked", "mysql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful stacked query execution
                if "You have an error in your SQL syntax" not in response.text:
                    results.append({
                        "type": "stacked",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Stacked queries SQL injection detected in MySQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MySQL stacked queries: {str(e)}")
                continue
        
        return results
    
    def _test_postgres_stacked(self, param_name: str) -> List[Dict]:
        """Test for PostgreSQL stacked queries SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("stacked", "postgresql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful stacked query execution
                if "ERROR: syntax error" not in response.text:
                    results.append({
                        "type": "stacked",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Stacked queries SQL injection detected in PostgreSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing PostgreSQL stacked queries: {str(e)}")
                continue
        
        return results
    
    def _test_mssql_stacked(self, param_name: str) -> List[Dict]:
        """Test for MSSQL stacked queries SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("stacked", "mssql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful stacked query execution
                if "Msg" not in response.text and "Incorrect syntax" not in response.text:
                    results.append({
                        "type": "stacked",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Stacked queries SQL injection detected in MSSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MSSQL stacked queries: {str(e)}")
                continue
        
        return results 
